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

// Package plugin implements the NRI hooks for supply chain attestation verification.
package plugin

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

// ErrMissingAnnotations indicates that required CRI-O image annotations are absent.
var ErrMissingAnnotations = errors.New("missing image annotations")

const (
	// AnnotationImage is the CRI-O annotation for the user-specified image reference.
	AnnotationImage = "io.kubernetes.cri-o.Image"
	// AnnotationImageRef is the CRI-O annotation for the resolved image digest.
	AnnotationImageRef = "io.kubernetes.cri-o.ImageRef"
)

// Plugin implements the NRI CreateContainer and Configure hooks
// for supply chain attestation verification.
type Plugin struct {
	verifier   *verifier.Verifier
	configPath string
}

// New creates a new Plugin with the given verifier and config file path.
func New(v *verifier.Verifier, configPath string) *Plugin {
	return &Plugin{
		verifier:   v,
		configPath: configPath,
	}
}

// Configure is called when the plugin connects to the NRI runtime.
func (p *Plugin) Configure(
	_ context.Context, cfg, runtime, version string,
) (stub.EventMask, error) {
	slog.Info("Connected to runtime", "runtime", runtime, "version", version)

	if p.configPath == "" && cfg != "" {
		parsed, err := config.LoadFromString(cfg)
		if err != nil {
			return 0, fmt.Errorf("parsing NRI config: %w", err)
		}

		err = parsed.ValidateRuntime()
		if err != nil {
			return 0, fmt.Errorf("validating NRI config: %w", err)
		}

		err = p.verifier.Reload(parsed)
		if err != nil {
			return 0, fmt.Errorf("applying NRI config: %w", err)
		}
	}

	return 0, nil
}

// CreateContainer is called for each new container before it is created.
// It verifies supply chain attestations and rejects the container on failure.
func (p *Plugin) CreateContainer(
	ctx context.Context, pod *api.PodSandbox, ctr *api.Container,
) (*api.ContainerAdjustment, []*api.ContainerUpdate, error) {
	annotations := ctr.GetAnnotations()
	imageRef := annotations[AnnotationImage]
	digest := annotations[AnnotationImageRef]
	namespace := pod.GetNamespace()

	if imageRef == "" || digest == "" {
		if p.verifier.Enforcing() {
			slog.ErrorContext(ctx, "Missing image annotations in enforce mode",
				"pod", namespace+"/"+pod.GetName(),
				"container", ctr.GetName(),
			)

			return nil, nil, fmt.Errorf(
				"%w for container %s", ErrMissingAnnotations, ctr.GetName(),
			)
		}

		slog.WarnContext(ctx, "Missing image annotations, skipping verification",
			"pod", namespace+"/"+pod.GetName(),
			"container", ctr.GetName(),
		)

		return nil, nil, nil
	}

	result, err := p.verifier.Verify(ctx, imageRef, digest, namespace)
	if err != nil {
		slog.ErrorContext(ctx, "Container rejected",
			"pod", namespace+"/"+pod.GetName(),
			"container", ctr.GetName(),
			"image", imageRef,
			"error", err,
		)

		return nil, nil, fmt.Errorf("supply chain verification: %w", err)
	}

	slog.InfoContext(ctx, "Container verified",
		"pod", namespace+"/"+pod.GetName(),
		"container", ctr.GetName(),
		"image", imageRef,
		"allowed", result.Allowed,
	)

	return nil, nil, nil
}
