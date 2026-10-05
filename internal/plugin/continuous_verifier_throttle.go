// Copyright The nri-supply-chain Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package plugin

import (
	"github.com/containerd/nri/pkg/api"
	"google.golang.org/protobuf/proto"
)

func (p *Plugin) buildThrottleUpdate(
	containerID string, original *api.LinuxResources,
) *api.ContainerUpdate {
	if original == nil {
		return nil
	}

	cpuPercent, memPercent := p.throttlePercents()
	resources := &api.LinuxResources{}

	if cpu := original.GetCpu(); cpu != nil {
		throttledCPU := &api.LinuxCPU{}

		if quota := cpu.GetQuota(); quota != nil {
			throttledQuota := max(
				quota.GetValue()*int64(cpuPercent)/percentDivisor,
				minCPUQuotaMicros,
			)

			throttledCPU.Quota = &api.OptionalInt64{Value: throttledQuota}
		}

		if shares := cpu.GetShares(); shares != nil {
			//nolint:gosec // cpuPercent is validated positive by throttlePercents()
			throttledShares := max(
				shares.GetValue()*uint64(cpuPercent)/percentDivisor,
				minCPUShares,
			)

			throttledCPU.Shares = &api.OptionalUInt64{Value: throttledShares}
		}

		resources.Cpu = throttledCPU
	}

	// A memory limit below the container's working set makes the kernel
	// OOM-kill it, so memory is only throttled when explicitly configured
	// below 100 percent.
	if mem := original.GetMemory(); mem != nil && memPercent < percentDivisor {
		throttledMem := &api.LinuxMemory{}

		if limit := mem.GetLimit(); limit != nil {
			throttledLimit := max(
				limit.GetValue()*int64(memPercent)/percentDivisor,
				minMemoryLimitBytes,
			)
			throttledMem.Limit = &api.OptionalInt64{Value: throttledLimit}
		}

		resources.Memory = throttledMem
	}

	return &api.ContainerUpdate{
		ContainerId:   containerID,
		Linux:         &api.LinuxContainerUpdate{Resources: resources},
		IgnoreFailure: false,
	}
}

// looksThrottled reports whether current holds exactly the limits a throttle
// update derived from original sets, and at least one of them differs from
// original. Limits changed for other reasons (for example an in-place resize)
// do not match and are left alone.
func (p *Plugin) looksThrottled(current, original *api.LinuxResources) bool {
	throttled := p.buildThrottleUpdate("", original).GetLinux().GetResources()
	if throttled == nil || current == nil {
		return false
	}

	limits := []limitMatch{
		compareLimit(
			optionalInt64(throttled.GetCpu().GetQuota()),
			optionalInt64(current.GetCpu().GetQuota()),
			optionalInt64(original.GetCpu().GetQuota()),
		),
		compareLimit(
			optionalUint64(throttled.GetCpu().GetShares()),
			optionalUint64(current.GetCpu().GetShares()),
			optionalUint64(original.GetCpu().GetShares()),
		),
		compareLimit(
			optionalInt64(throttled.GetMemory().GetLimit()),
			optionalInt64(current.GetMemory().GetLimit()),
			optionalInt64(original.GetMemory().GetLimit()),
		),
	}

	compared, changed := false, false

	for _, limit := range limits {
		if !limit.compared {
			continue
		}

		if !limit.matches {
			return false
		}

		compared = true
		changed = changed || limit.changed
	}

	return compared && changed
}

// limitMatch is the comparison of one throttleable limit.
type limitMatch struct {
	// compared is false when the throttle update does not set the limit.
	compared bool
	// matches is true when the current limit equals the throttled limit.
	matches bool
	// changed is true when the throttled limit differs from the original.
	changed bool
}

func compareLimit[T comparable](throttled, current, original *T) limitMatch {
	if throttled == nil {
		return limitMatch{compared: false, matches: false, changed: false}
	}

	return limitMatch{
		compared: true,
		matches:  current != nil && *current == *throttled,
		changed:  original == nil || *original != *throttled,
	}
}

func optionalInt64(value *api.OptionalInt64) *int64 {
	if value == nil {
		return nil
	}

	v := value.GetValue()

	return &v
}

func optionalUint64(value *api.OptionalUInt64) *uint64 {
	if value == nil {
		return nil
	}

	v := value.GetValue()

	return &v
}

func (p *Plugin) throttlePercents() (cpuPercent, memPercent int) {
	if cfg := p.remediation.cfg.Load(); cfg != nil {
		cpuPercent = cfg.Throttle.CPUQuotaPercent
		memPercent = cfg.Throttle.MemoryLimitPercent
	}

	if cpuPercent <= 0 {
		cpuPercent = defaultThrottleCPUPercent
	}

	if memPercent <= 0 {
		memPercent = defaultThrottleMemPercent
	}

	cpuPercent = min(cpuPercent, percentDivisor)
	memPercent = min(memPercent, percentDivisor)

	return cpuPercent, memPercent
}

func buildRollbackUpdate(
	containerID string, original *api.LinuxResources,
) *api.ContainerUpdate {
	restored := deepCopyLinuxResources(original)

	return &api.ContainerUpdate{
		ContainerId:   containerID,
		Linux:         &api.LinuxContainerUpdate{Resources: restored},
		IgnoreFailure: false,
	}
}

func deepCopyLinuxResources(src *api.LinuxResources) *api.LinuxResources {
	if src == nil {
		return nil
	}

	cloned, ok := proto.Clone(src).(*api.LinuxResources)
	if !ok {
		return nil
	}

	return cloned
}

const (
	defaultThrottleCPUPercent = 10
	defaultThrottleMemPercent = 100
	percentDivisor            = 100
	minCPUQuotaMicros         = 1000
	minCPUShares              = 2
	minMemoryLimitBytes       = 4 << 20 // 4 MiB
)
