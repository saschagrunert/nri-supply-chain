GO ?= go

GOLANGCI_LINT_VERSION = 2.13.1
ZEITGEIST_VERSION = 0.8.0
SHFMT_VERSION = v3.13.1
SHELLCHECK_VERSION = v0.11.0
KUBERNIX_VERSION = 0.3.5
MDTOC_VERSION = v1.4.0
COSIGN_VERSION = 3.1.3
CRANE_VERSION = 0.21.9
GOVULNCHECK_VERSION = v1.7.0
PRETTIER_VERSION = 3.9.6
DASHBOARD_LINTER_VERSION = 0.3.0
HELM_VERSION = 3.21.4
KUBECONFORM_VERSION = 0.8.0
GORELEASER_VERSION = 2.18.1

# SHA-256 checksums for downloaded tools, named <TOOL>_SHA256_<os>_<arch>.
# Downloads fail when no checksum is pinned for the current platform.
GOLANGCI_LINT_SHA256_linux_amd64 = b17bfbc9d4aaa48be7f4f1ce3240bc3d8200c870c072bacf15c26219e2cfb9cc
GOLANGCI_LINT_SHA256_linux_arm64 = 908317c23db18448f924e853b3d8a659fd919614cd438f224810a4053daa2607
GOLANGCI_LINT_SHA256_darwin_amd64 = 2c373363953e4e0bee2a03b7fe864a5eb6a3822927cb077d9ca33f2ae3cb2da2
GOLANGCI_LINT_SHA256_darwin_arm64 = 0c9818baf6fb8ad26c6d2ef51b68d5a1e260ef07727036b1431647cc44637c7c

ZEITGEIST_SHA256_linux_amd64 = b004b91e0ad881732f2ba0e63def2e3c35950323e221b50c50cbad75b3f5c2b1
ZEITGEIST_SHA256_linux_arm64 = 52e3b1af8ce2fc304b21cfa380a37bc1c4c6a48015063fdbeab6516123804e55
ZEITGEIST_SHA256_darwin_amd64 = b0d8ebad065e47d7cce174395f39ab3e702ac97ea1f2a3814304aec60de9c888
ZEITGEIST_SHA256_darwin_arm64 = 340a1cf35d8354c4bb1a6eb251c9ee2bbab13978e9c39b148badf955bae7e087

SHFMT_SHA256_linux_amd64 = fb096c5d1ac6beabbdbaa2874d025badb03ee07929f0c9ff67563ce8c75398b1
SHFMT_SHA256_linux_arm64 = 32d92acaa5cd8abb29fc49dac123dc412442d5713967819d8af2c29f1b3857c7
SHFMT_SHA256_darwin_amd64 = 6feedafc72915794163114f512348e2437d080d0047ef8b8fa2ec63b575f12af
SHFMT_SHA256_darwin_arm64 = 9680526be4a66ea1ffe988ed08af58e1400fe1e4f4aef5bd88b20bb9b3da33f8

SHELLCHECK_SHA256_linux_amd64 = 8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198
SHELLCHECK_SHA256_linux_arm64 = 12b331c1d2db6b9eb13cfca64306b1b157a86eb69db83023e261eaa7e7c14588
SHELLCHECK_SHA256_darwin_amd64 = 3c89db4edcab7cf1c27bff178882e0f6f27f7afdf54e859fa041fca10febe4c6
SHELLCHECK_SHA256_darwin_arm64 = 56affdd8de5527894dca6dc3d7e0a99a873b0f004d7aabc30ae407d3f48b0a79

# kubernix only ships Linux binaries.
KUBERNIX_SHA256_linux_amd64 = 63844f7a513a42b01d7d39a6f42888c7640295d68aeae82b7ccf4a9d7984196c
KUBERNIX_SHA256_linux_arm64 = ac043a9bcdac1ffb93623b30d92a594e59dc0ef9bdf0d222eab3efa17be8f892

COSIGN_SHA256_linux_amd64 = 4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71
COSIGN_SHA256_linux_arm64 = c5d324e091826b0d7a78eb16fef316450b4eb9aaec045611c08ba06f5e73220a
COSIGN_SHA256_darwin_amd64 = 2347488e5d5b25336644024dfeca5601b190e91197a71a917bda44744aff106c
COSIGN_SHA256_darwin_arm64 = 5cf948c2f4dfe59687bdd0b8523709067383e03982cc543475c8a7dc70e92a76

CRANE_SHA256_linux_amd64 = 5c16d8ddb971cb1d5e6ed8b1e743da8224414eeba2c2762d8f1a61b2f095699e
CRANE_SHA256_linux_arm64 = 1f4c647b7bb260ab5435661df5b526cf59950ebf95201790db7183ac189cbcbd
CRANE_SHA256_darwin_amd64 = f31075b3375f79b406a600e090d5c4778b3c6598a01c817dc7898c05c7c00a56
CRANE_SHA256_darwin_arm64 = 11cc3640e53473eb0d8c501068573e52a259f4d82177e6dd11b7bacb8955459e

DASHBOARD_LINTER_SHA256_linux_amd64 = 9a0eecb84ff22005dbd21c39ffd91534b407b511c45c21879df62ad0de33d79f
DASHBOARD_LINTER_SHA256_linux_arm64 = cca3c44ab921a4303dc3850b0cea56e0192112a185ebadceb173d7c7a5d3731b
DASHBOARD_LINTER_SHA256_darwin_amd64 = 9ca2cd292b5aaaaa6827c417b26440033e35516e4896238c34c7cc97cbcb45cf
DASHBOARD_LINTER_SHA256_darwin_arm64 = 910c20366491565faa241166676b54a53648ed2b30d8403017056bb18aeae75d

HELM_SHA256_linux_amd64 = 61f88ab166748cb19604d7884cb100ae9ccb13804ddeb98e08af167eacbb6a14
HELM_SHA256_linux_arm64 = b54c04b4e0b2540bbdc08c17a121dab70e9a2ed0de5705528fec68a5fd3b85a7
HELM_SHA256_darwin_amd64 = 9173d05edf9592c6be1d0412ffafd935448dfc7a63c2bc732b8c67e55503e8a8
HELM_SHA256_darwin_arm64 = 6e0bf5eb6daafc2b1ec34bb5ba04ef103f3afc16192fb19805c2924d7ea1033f

KUBECONFORM_SHA256_linux_amd64 = 9bc2bffbf71f261128533edaf912153948b7ff238f9a531ae6d34466ec287883
KUBECONFORM_SHA256_linux_arm64 = 1f53fc8e81258197a35e8603054162a5af1de8c5af13746c71ab680d9534ed87
KUBECONFORM_SHA256_darwin_amd64 = 71dbc87ac9f24099a62b93570e65aa06312ba6ac8aea63b7f86e9d999edf5a92
KUBECONFORM_SHA256_darwin_arm64 = f84f4dfbebf4a6b0b230385fa065a39ea35e02608c2b50d025dcf64775a69d67

GORELEASER_SHA256_linux_amd64 = 0c6122af0ad8fd65638889bf7d3757148b2f80eeff9f079682f0655df66ec8e8
GORELEASER_SHA256_linux_arm64 = 93dba7614308e167158bd26978e8275971fd4b9147e7f3c687a64f5939d42d27
GORELEASER_SHA256_darwin_amd64 = 623e9ba517ace49c3d6b57bcfe8f5fe33ca45313ee93261c1854464cca94d861
GORELEASER_SHA256_darwin_arm64 = 8e912c5cc78896d791b7530e672d4a4ef9c00ebff7375de410fae1b459825ea3

# verify_checksum verifies a downloaded file against the SHA-256 checksum
# pinned for the current OS and architecture. It fails closed and removes the
# file when no checksum is pinned or when the checksum does not match. It uses
# sha256sum on Linux and falls back to "shasum -a 256" on macOS.
# Usage: $(call verify_checksum,file,TOOL)
define verify_checksum
	expected="$($(2)_SHA256_$(OS)_$(ARCH))"; \
	if [ -z "$$expected" ]; then \
		echo "ERROR: no pinned SHA-256 checksum for $(2) on $(OS)/$(ARCH)" >&2; \
		rm -f "$(1)"; \
		exit 1; \
	fi; \
	if command -v sha256sum >/dev/null 2>&1; then \
		actual="$$(sha256sum "$(1)" | cut -d ' ' -f 1)"; \
	else \
		actual="$$(shasum -a 256 "$(1)" | cut -d ' ' -f 1)"; \
	fi; \
	if [ "$$actual" != "$$expected" ]; then \
		echo "ERROR: SHA-256 mismatch for $(1): expected $$expected, got $$actual" >&2; \
		rm -f "$(1)"; \
		exit 1; \
	fi
endef

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || sed -n 's/^var version = "\(.*\)"/\1/p' cmd/nri-supply-chain/main.go)
SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct 2>/dev/null || echo 0)
BUILD_DIR := build
GOLANGCI_LINT := $(BUILD_DIR)/golangci-lint
ZEITGEIST := $(BUILD_DIR)/zeitgeist
SHFMT := $(BUILD_DIR)/shfmt
SHELLCHECK := $(BUILD_DIR)/shellcheck
KUBERNIX := $(BUILD_DIR)/kubernix
MDTOC := $(BUILD_DIR)/mdtoc
COSIGN := $(BUILD_DIR)/cosign
CRANE := $(BUILD_DIR)/crane
GOVULNCHECK := $(BUILD_DIR)/govulncheck
DASHBOARD_LINTER := $(BUILD_DIR)/dashboard-linter
HELM := $(BUILD_DIR)/helm
KUBECONFORM := $(BUILD_DIR)/kubeconform
GORELEASER := $(BUILD_DIR)/goreleaser

ARCH ?= $(shell uname -m | \
	sed 's/x86_64/amd64/' | \
	sed 's/aarch64/arm64/')

OS ?= $(shell uname -s | tr '[:upper:]' '[:lower:]')

# Architecture and OS spellings used by upstream release assets.
UNAME_ARCH = $(if $(filter arm64,$(ARCH)),aarch64,x86_64)
SHELLCHECK_ARCH ?= $(UNAME_ARCH)
CRANE_OS ?= $(if $(filter darwin,$(OS)),Darwin,Linux)
CRANE_ARCH ?= $(if $(filter arm64,$(ARCH)),arm64,x86_64)

COLOR := \033[36m
NOCOLOR := \033[0m

.PHONY: all
all: build ## Build the project

.PHONY: help
help: ## Display this help
	@awk \
		-v "col=$(COLOR)" -v "nocol=$(NOCOLOR)" \
		' \
			BEGIN { \
				FS = ":.*##" ; \
				printf "\nUsage:\n  make %s<target>%s\n\n", col, nocol; \
			} \
			/^[a-zA-Z0-9_-]+:.*?##/ { \
				printf "  %s%-25s%s %s\n", col, $$1, nocol, $$2 \
			} \
			/^##@/ { \
				printf "\n%s%s%s\n", col, substr($$0, 5), nocol \
			} \
		' $(MAKEFILE_LIST)

##@ Build

.PHONY: build
build: ## Build the nri-supply-chain binary (static)
	@mkdir -p $(BUILD_DIR)
	SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) CGO_ENABLED=0 $(GO) build -mod=vendor -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o $(BUILD_DIR)/nri-supply-chain ./cmd/nri-supply-chain/

PREFIX ?= /usr/local

.PHONY: install
install: build ## Install the binary to $(PREFIX)/bin
	install -D -m 0755 $(BUILD_DIR)/nri-supply-chain $(PREFIX)/bin/nri-supply-chain

.PHONY: docker-build
docker-build: ## Build the container image locally
	docker build -t nri-supply-chain:$(VERSION) --build-arg VERSION=$(VERSION) .

##@ Development

.PHONY: test
test: ## Run tests with race detection and coverage report
	@mkdir -p $(BUILD_DIR)
	$(GO) test -v -race -count=1 -coverprofile=$(BUILD_DIR)/coverage.out -covermode=atomic -coverpkg=./... ./...
	$(GO) tool cover -html=$(BUILD_DIR)/coverage.out -o $(BUILD_DIR)/coverage.html

FUZZTIME ?= 30s

.PHONY: fuzz
fuzz: ## Run all fuzz tests (use FUZZTIME to adjust, default 30s)
	@for pkg in $$($(GO) list ./...); do \
		for target in $$($(GO) test -list 'Fuzz.*' $$pkg 2>/dev/null | grep '^Fuzz'); do \
			echo "fuzzing $$pkg $$target"; \
			$(GO) test -fuzz=$$target -fuzztime=$(FUZZTIME) $$pkg || exit 1; \
		done; \
	done

.PHONY: bench
bench: ## Run benchmark tests
	$(GO) test -bench=. -benchmem -count=1 -run=^$$ ./...

##@ Release

.PHONY: snapshot
snapshot: $(GORELEASER) ## Run goreleaser snapshot build
	$(GORELEASER) release --snapshot --skip=sign --clean

.PHONY: integration
integration: build ## Run bats integration tests
	bats --jobs $(shell nproc 2>/dev/null || sysctl -n hw.ncpu) test/integration/

.PHONY: e2e
e2e: build $(KUBERNIX) $(COSIGN) $(CRANE) $(HELM) ## Run bats e2e tests (requires root and Nix)
	bats test/e2e/

##@ Verification

.PHONY: verify-all
verify-all: lint verify-shfmt verify-shellcheck verify-mdtoc verify-jsonschema verify-helm verify-manifests verify-tidy verify-vendor verify-no-test-deps verify-dependencies govulncheck verify-prettier verify-typos verify-dashboard ## Run all verification targets

.PHONY: lint
lint: $(GOLANGCI_LINT) ## Run golangci-lint
	$(GOLANGCI_LINT) run

$(GOLANGCI_LINT):
	@mkdir -p $(BUILD_DIR)
	curl -sSfL -o $(BUILD_DIR)/golangci-lint.tar.gz \
		https://github.com/golangci/golangci-lint/releases/download/v$(GOLANGCI_LINT_VERSION)/golangci-lint-$(GOLANGCI_LINT_VERSION)-$(OS)-$(ARCH).tar.gz
	$(call verify_checksum,$(BUILD_DIR)/golangci-lint.tar.gz,GOLANGCI_LINT)
	tar xfz $(BUILD_DIR)/golangci-lint.tar.gz -C $(BUILD_DIR) --strip-components=1 \
		golangci-lint-$(GOLANGCI_LINT_VERSION)-$(OS)-$(ARCH)/golangci-lint
	rm $(BUILD_DIR)/golangci-lint.tar.gz

SHELL_FILES = $(eval SHELL_FILES := $(shell find . -not -path './build/*' -not -path './dist/*' -not -path './vendor/*' -not -path './.claude/*' \( -name '*.sh' -o -name '*.bash' -o -name '*.bats' \) | sort))$(SHELL_FILES)

.PHONY: verify-shfmt
verify-shfmt: $(SHFMT) ## Verify shell script formatting
	$(SHFMT) -d $(SHELL_FILES)

.PHONY: verify-shellcheck
verify-shellcheck: $(SHELLCHECK) ## Run shellcheck on shell scripts
	$(SHELLCHECK) $(SHELL_FILES)

.PHONY: verify-mdtoc
verify-mdtoc: $(MDTOC) ## Verify table of contents in docs
	@fail=0; for f in README.md docs/*.md; do $(MDTOC) --inplace --dryrun "$$f" || fail=1; done; exit $$fail

.PHONY: verify-jsonschema
verify-jsonschema: build ## Verify JSON Schemas in docs match CLI output
	@command -v jq >/dev/null 2>&1 || { echo "ERROR: jq is required for verify-jsonschema"; exit 1; }
	@generated=$$($(BUILD_DIR)/nri-supply-chain json-schema policy | jq -S .); \
	[ -n "$$generated" ] || { echo "ERROR: empty policy schema output"; exit 1; }; \
	embedded=$$(sed -n '/<!-- jsonschema-start -->/,/<!-- jsonschema-end -->/p' docs/policy.md \
		| sed -n '/^```json$$/,/^```$$/p' | sed '1d;$$d' | jq -S .); \
	[ -n "$$embedded" ] || { echo "ERROR: no schema found in docs/policy.md"; exit 1; }; \
	if [ "$$generated" != "$$embedded" ]; then \
		echo "ERROR: JSON Schema in docs/policy.md is out of date."; \
		echo "Run 'nri-supply-chain json-schema policy' and update the schema section."; \
		exit 1; \
	fi
	@generated=$$($(BUILD_DIR)/nri-supply-chain json-schema result | jq -S .); \
	[ -n "$$generated" ] || { echo "ERROR: empty result schema output"; exit 1; }; \
	embedded=$$(sed -n '/<!-- verify-jsonschema-start -->/,/<!-- verify-jsonschema-end -->/p' docs/config.md \
		| sed -n '/^```json$$/,/^```$$/p' | sed '1d;$$d' | jq -S .); \
	[ -n "$$embedded" ] || { echo "ERROR: no schema found in docs/config.md"; exit 1; }; \
	if [ "$$generated" != "$$embedded" ]; then \
		echo "ERROR: JSON Schema in docs/config.md is out of date."; \
		echo "Run 'nri-supply-chain json-schema result' and update the schema section."; \
		exit 1; \
	fi

.PHONY: verify-helm
verify-helm: $(HELM) ## Lint and render the Helm chart
	$(HELM) lint --strict deploy/helm/nri-supply-chain
	$(HELM) template nri-supply-chain deploy/helm/nri-supply-chain --namespace nri-supply-chain > /dev/null

.PHONY: verify-manifests
verify-manifests: build $(HELM) $(KUBECONFORM) ## Validate raw and Helm manifests, their embedded config, and drift
	BINARY=$(BUILD_DIR)/nri-supply-chain HELM=$(HELM) KUBECONFORM=$(KUBECONFORM) \
		hack/verify-manifests.sh

.PHONY: verify-tidy
verify-tidy: ## Verify go.mod is tidy
	$(GO) mod tidy
	git diff --exit-code go.mod go.sum

.PHONY: vendor
vendor: ## Update vendor directory
	$(GO) mod vendor

.PHONY: verify-vendor
verify-vendor: ## Verify vendor directory is in sync
	$(GO) mod vendor
	git diff --exit-code vendor/

# Test-only packages that must never be linked into the plugin binary.
TEST_ONLY_PACKAGES = github.com/sigstore/sigstore-go/pkg/testing/ca

.PHONY: verify-no-test-deps
verify-no-test-deps: ## Verify test-only packages are not linked into the binary
	@deps=$$($(GO) list -mod=vendor -deps ./cmd/...) || exit 1; \
	fail=0; for pkg in $(TEST_ONLY_PACKAGES); do \
		if printf '%s\n' "$$deps" | grep -qx "$$pkg"; then \
			echo "ERROR: test-only package $$pkg is linked into ./cmd/..."; fail=1; \
		fi; \
	done; exit $$fail

.PHONY: verify-dependencies
verify-dependencies: $(ZEITGEIST) ## Verify external dependencies
	$(ZEITGEIST) validate --local-only --base-path . --config dependencies.yaml

.PHONY: verify-typos
verify-typos: ## Check for typos in source files
	typos

.PHONY: verify-prettier
verify-prettier: ## Verify file formatting with prettier
	npx prettier@$(PRETTIER_VERSION) --check .

.PHONY: verify-dashboard
verify-dashboard: $(DASHBOARD_LINTER) ## Lint Grafana dashboard JSON
	$(DASHBOARD_LINTER) lint deploy/grafana/dashboard.json
	diff deploy/grafana/dashboard.json deploy/helm/nri-supply-chain/files/dashboard.json

$(ZEITGEIST):
	@mkdir -p $(BUILD_DIR)
	curl -sSfL -o $(ZEITGEIST) \
		https://github.com/kubernetes-sigs/zeitgeist/releases/download/v$(ZEITGEIST_VERSION)/zeitgeist-$(ARCH)-$(OS)
	$(call verify_checksum,$(ZEITGEIST),ZEITGEIST)
	chmod +x $(ZEITGEIST)

$(SHFMT):
	@mkdir -p $(BUILD_DIR)
	curl -sSfL -o $(SHFMT) \
		https://github.com/mvdan/sh/releases/download/$(SHFMT_VERSION)/shfmt_$(SHFMT_VERSION)_$(OS)_$(ARCH)
	$(call verify_checksum,$(SHFMT),SHFMT)
	chmod +x $(SHFMT)

$(SHELLCHECK):
	@mkdir -p $(BUILD_DIR)
	curl -sSfL -o $(BUILD_DIR)/shellcheck.tar.xz \
		https://github.com/koalaman/shellcheck/releases/download/$(SHELLCHECK_VERSION)/shellcheck-$(SHELLCHECK_VERSION).$(OS).$(SHELLCHECK_ARCH).tar.xz
	$(call verify_checksum,$(BUILD_DIR)/shellcheck.tar.xz,SHELLCHECK)
	tar xfJ $(BUILD_DIR)/shellcheck.tar.xz -C $(BUILD_DIR) --strip-components=1 shellcheck-$(SHELLCHECK_VERSION)/shellcheck
	rm $(BUILD_DIR)/shellcheck.tar.xz

$(MDTOC):
	@mkdir -p $(BUILD_DIR)
	GOBIN=$(abspath $(BUILD_DIR)) $(GO) install sigs.k8s.io/mdtoc@$(MDTOC_VERSION)

$(KUBERNIX):
	@mkdir -p $(BUILD_DIR)
	curl -sSfL -o $(KUBERNIX) \
		https://github.com/saschagrunert/kubernix/releases/download/v$(KUBERNIX_VERSION)/kubernix-$(UNAME_ARCH)
	$(call verify_checksum,$(KUBERNIX),KUBERNIX)
	chmod +x $(KUBERNIX)

$(COSIGN):
	@mkdir -p $(BUILD_DIR)
	curl -sSfL -o $(COSIGN) \
		https://github.com/sigstore/cosign/releases/download/v$(COSIGN_VERSION)/cosign-$(OS)-$(ARCH)
	$(call verify_checksum,$(COSIGN),COSIGN)
	chmod +x $(COSIGN)

$(CRANE):
	@mkdir -p $(BUILD_DIR)
	curl -sSfL -o $(BUILD_DIR)/crane.tar.gz \
		https://github.com/google/go-containerregistry/releases/download/v$(CRANE_VERSION)/go-containerregistry_$(CRANE_OS)_$(CRANE_ARCH).tar.gz
	$(call verify_checksum,$(BUILD_DIR)/crane.tar.gz,CRANE)
	tar xfz $(BUILD_DIR)/crane.tar.gz -C $(BUILD_DIR) crane
	rm $(BUILD_DIR)/crane.tar.gz

$(DASHBOARD_LINTER):
	@mkdir -p $(BUILD_DIR)
	curl -sSfL -o $(BUILD_DIR)/dashboard-linter.tar.gz \
		https://github.com/grafana/dashboard-linter/releases/download/v$(DASHBOARD_LINTER_VERSION)/dashboard-linter_$(DASHBOARD_LINTER_VERSION)_$(OS)_$(ARCH).tar.gz
	$(call verify_checksum,$(BUILD_DIR)/dashboard-linter.tar.gz,DASHBOARD_LINTER)
	tar xfz $(BUILD_DIR)/dashboard-linter.tar.gz -C $(BUILD_DIR) dashboard-linter
	rm $(BUILD_DIR)/dashboard-linter.tar.gz

$(HELM):
	@mkdir -p $(BUILD_DIR)
	curl -sSfL -o $(BUILD_DIR)/helm.tar.gz \
		https://get.helm.sh/helm-v$(HELM_VERSION)-$(OS)-$(ARCH).tar.gz
	$(call verify_checksum,$(BUILD_DIR)/helm.tar.gz,HELM)
	tar xfz $(BUILD_DIR)/helm.tar.gz -C $(BUILD_DIR) --strip-components=1 $(OS)-$(ARCH)/helm
	rm $(BUILD_DIR)/helm.tar.gz

$(KUBECONFORM):
	@mkdir -p $(BUILD_DIR)
	curl -sSfL -o $(BUILD_DIR)/kubeconform.tar.gz \
		https://github.com/yannh/kubeconform/releases/download/v$(KUBECONFORM_VERSION)/kubeconform-$(OS)-$(ARCH).tar.gz
	$(call verify_checksum,$(BUILD_DIR)/kubeconform.tar.gz,KUBECONFORM)
	tar xfz $(BUILD_DIR)/kubeconform.tar.gz -C $(BUILD_DIR) kubeconform
	rm $(BUILD_DIR)/kubeconform.tar.gz

$(GORELEASER):
	@mkdir -p $(BUILD_DIR)
	curl -sSfL -o $(BUILD_DIR)/goreleaser.tar.gz \
		https://github.com/goreleaser/goreleaser/releases/download/v$(GORELEASER_VERSION)/goreleaser_$(CRANE_OS)_$(CRANE_ARCH).tar.gz
	$(call verify_checksum,$(BUILD_DIR)/goreleaser.tar.gz,GORELEASER)
	tar xfz $(BUILD_DIR)/goreleaser.tar.gz -C $(BUILD_DIR) goreleaser
	rm $(BUILD_DIR)/goreleaser.tar.gz

$(GOVULNCHECK):
	@mkdir -p $(BUILD_DIR)
	GOBIN=$(abspath $(BUILD_DIR)) $(GO) install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

.PHONY: govulncheck
govulncheck: $(GOVULNCHECK) ## Run govulncheck
	$(GOVULNCHECK) ./cmd/...

##@ Maintenance

.PHONY: tidy
tidy: ## Run go mod tidy
	$(GO) mod tidy

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf $(BUILD_DIR)
