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

// Package imageref normalizes the different spellings of a container image
// registry and repository, so that references naming the same image compare
// equal wherever images are matched.
package imageref

import "strings"

const (
	// DockerHubRegistry is the canonical spelling of the Docker Hub registry.
	DockerHubRegistry = "docker.io"

	// dockerHubOfficialNamespace is the namespace of Docker Hub official
	// images, implied when a Docker Hub repository has a single segment.
	dockerHubOfficialNamespace = "library"
)

// IsDockerHub reports whether registry is one of the hosts that serve Docker
// Hub: docker.io, index.docker.io, registry-1.docker.io and
// registry.hub.docker.com (case-insensitive).
func IsDockerHub(registry string) bool {
	switch strings.ToLower(registry) {
	case DockerHubRegistry, "index.docker.io", "registry-1.docker.io", "registry.hub.docker.com":
		return true
	default:
		return false
	}
}

// NormalizeRegistry returns the lowercase registry host, with every Docker Hub
// alias spelled as docker.io.
func NormalizeRegistry(registry string) string {
	if IsDockerHub(registry) {
		return DockerHubRegistry
	}

	return strings.ToLower(registry)
}

// NormalizeRepositoryPath returns the repository path (without registry) of
// an image on registry. Single-segment Docker Hub repositories get the
// implied official image namespace ("nginx" becomes "library/nginx").
func NormalizeRepositoryPath(registry, path string) string {
	if IsDockerHub(registry) && path != "" && !strings.Contains(path, "/") {
		return dockerHubOfficialNamespace + "/" + path
	}

	return path
}

// NormalizeRepository normalizes a fully qualified repository name
// ("<registry>/<path>"): the registry is normalized with NormalizeRegistry and
// the path with NormalizeRepositoryPath. A name without a path is returned
// unchanged.
func NormalizeRepository(repository string) string {
	registry, path, found := strings.Cut(repository, "/")
	if !found {
		return repository
	}

	return NormalizeRegistry(registry) + "/" + NormalizeRepositoryPath(registry, path)
}
