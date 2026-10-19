GO ?= go

GOLANGCI_LINT_VERSION = 2.15.0
ZEITGEIST_VERSION = 0.8.0
SHFMT_VERSION = v3.14.1
SHELLCHECK_VERSION = v0.11.0
KUBERNIX_VERSION = 0.4.3
MDTOC_VERSION = v1.4.0
COSIGN_VERSION = 3.1.3
CRANE_VERSION = 0.22.1
GOVULNCHECK_VERSION = v1.9.0
PRETTIER_VERSION = 3.9.10
MARKDOWNLINT_VERSION = 0.23.3
DASHBOARD_LINTER_VERSION = 0.3.0
HELM_VERSION = 4.3.1
KUBECONFORM_VERSION = 0.8.0
GORELEASER_VERSION = 2.18.3

# SHA-256 checksums for downloaded tools, named <TOOL>_SHA256_<os>_<arch>.
# Downloads fail when no checksum is pinned for the current platform.
GOLANGCI_LINT_SHA256_linux_amd64 = 9b7fe6a6bf6334b98decf8d86b11415ea7889afdabdd1959fdce23af2a9ebcea
GOLANGCI_LINT_SHA256_linux_arm64 = b4d8f17068b35ee6060cc2f69a16fb48740d706fbba81661c318649c114a6998
GOLANGCI_LINT_SHA256_darwin_amd64 = 767b899a28285e88ded2823d5dcc4bc5ef681173eb2d80f029a7b17ee4ece3b8
GOLANGCI_LINT_SHA256_darwin_arm64 = d1e409481a8ca846c4bc97e781eb5cb1bd5c23353a0b3977a1cbda1b1b6447d5

ZEITGEIST_SHA256_linux_amd64 = b004b91e0ad881732f2ba0e63def2e3c35950323e221b50c50cbad75b3f5c2b1
ZEITGEIST_SHA256_linux_arm64 = 52e3b1af8ce2fc304b21cfa380a37bc1c4c6a48015063fdbeab6516123804e55
ZEITGEIST_SHA256_darwin_amd64 = b0d8ebad065e47d7cce174395f39ab3e702ac97ea1f2a3814304aec60de9c888
ZEITGEIST_SHA256_darwin_arm64 = 340a1cf35d8354c4bb1a6eb251c9ee2bbab13978e9c39b148badf955bae7e087

SHFMT_SHA256_linux_amd64 = 76e77641faa025814b77f153b29796b8e6fa2fca03e0c76a691608b86c7ea7bf
SHFMT_SHA256_linux_arm64 = 5f2db09dae91fca848f7adbdd014632e921a383863a2ad7e0450ad3aba0c6489
SHFMT_SHA256_darwin_amd64 = d33eee0da0f92835b3562e9767a05cee7e4eaeef47daa03bfd09da17b4b590a6
SHFMT_SHA256_darwin_arm64 = b7c872db63553ccffc7253aba3ed7d4885a27d83f1ba567b1138c6315a5847e5

SHELLCHECK_SHA256_linux_amd64 = 8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198
SHELLCHECK_SHA256_linux_arm64 = 12b331c1d2db6b9eb13cfca64306b1b157a86eb69db83023e261eaa7e7c14588
SHELLCHECK_SHA256_darwin_amd64 = 3c89db4edcab7cf1c27bff178882e0f6f27f7afdf54e859fa041fca10febe4c6
SHELLCHECK_SHA256_darwin_arm64 = 56affdd8de5527894dca6dc3d7e0a99a873b0f004d7aabc30ae407d3f48b0a79

# kubernix only ships Linux binaries.
KUBERNIX_SHA256_linux_amd64 = f52d8e90282468a11ba585cca36b6110104c5573395dacdd101953d055e5677f
KUBERNIX_SHA256_linux_arm64 = fa03f7cfbf21e7ba210603eb6aa459830ab9b55b5d5bb3558a5db632dec7cccb

COSIGN_SHA256_linux_amd64 = 4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71
COSIGN_SHA256_linux_arm64 = c5d324e091826b0d7a78eb16fef316450b4eb9aaec045611c08ba06f5e73220a
COSIGN_SHA256_darwin_amd64 = 2347488e5d5b25336644024dfeca5601b190e91197a71a917bda44744aff106c
COSIGN_SHA256_darwin_arm64 = 5cf948c2f4dfe59687bdd0b8523709067383e03982cc543475c8a7dc70e92a76

CRANE_SHA256_linux_amd64 = 0ab7a1d6932a213aed964ce97666c3077fe691c8606413674a8b3e0b9ec4cda0
CRANE_SHA256_linux_arm64 = 898c0cff975f898a33e8c4580bdafb0e7c02c7faa33374e946762f97c4ab7110
CRANE_SHA256_darwin_amd64 = 6fedd06a648c11335f0e8b9547e4783002c30e9336047fec292942cd518bb799
CRANE_SHA256_darwin_arm64 = 2231fc8df8806d20d680ff1225db44e095a55dd6ac1ae8eced4faf4b278b78fb

DASHBOARD_LINTER_SHA256_linux_amd64 = 9a0eecb84ff22005dbd21c39ffd91534b407b511c45c21879df62ad0de33d79f
DASHBOARD_LINTER_SHA256_linux_arm64 = cca3c44ab921a4303dc3850b0cea56e0192112a185ebadceb173d7c7a5d3731b
DASHBOARD_LINTER_SHA256_darwin_amd64 = 9ca2cd292b5aaaaa6827c417b26440033e35516e4896238c34c7cc97cbcb45cf
DASHBOARD_LINTER_SHA256_darwin_arm64 = 910c20366491565faa241166676b54a53648ed2b30d8403017056bb18aeae75d

HELM_SHA256_linux_amd64 = 0403a88ae20913d11b10a2467b50087721fea7581736da6b9d3992f5357fe54b
HELM_SHA256_linux_arm64 = 8cf8f66ecbc252ac8f7f06cca68aba88508ddfde3a6a34feb1678ad1694b4f88
HELM_SHA256_darwin_amd64 = 34bec4eba761ba5c16d1965ee6b8f5b0abe5993974a802274e2a4f0418893d89
HELM_SHA256_darwin_arm64 = 6b4e61c8cd27d99e5a801e63ff25dd5c70b36875c2cd659d3e9ce6b76fc23198

KUBECONFORM_SHA256_linux_amd64 = 9bc2bffbf71f261128533edaf912153948b7ff238f9a531ae6d34466ec287883
KUBECONFORM_SHA256_linux_arm64 = 1f53fc8e81258197a35e8603054162a5af1de8c5af13746c71ab680d9534ed87
KUBECONFORM_SHA256_darwin_amd64 = 71dbc87ac9f24099a62b93570e65aa06312ba6ac8aea63b7f86e9d999edf5a92
KUBECONFORM_SHA256_darwin_arm64 = f84f4dfbebf4a6b0b230385fa065a39ea35e02608c2b50d025dcf64775a69d67

GORELEASER_SHA256_linux_amd64 = b8dee4728bca1aba0d71a832a17cd0a3799f75372878e7ffa36aef2343bce0bc
GORELEASER_SHA256_linux_arm64 = fa7011a7f8de3b504326b8552cf21c708ed3089519b01d372da32ef4e8d298d7
GORELEASER_SHA256_darwin_amd64 = dbc39347d9ca25a2da9bcc03633f39130bb3a67c9f2a0da86ba15b8b00bf86ce
GORELEASER_SHA256_darwin_arm64 = 821c58ab8c31d57bb331cab9f1a703eb3673bff4fce0db9cc3c4a038af14f76f

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

VERSION ?= $(shell (git describe --tags --always --dirty 2>/dev/null || sed -n 's/^var version = "\(.*\)"/\1/p' cmd/nri-supply-chain/main.go) | sed 's/^v//')
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

# Each downloaded tool depends on a stamp named after its version, so changing
# a *_VERSION downloads the tool again instead of reusing the binary in build/.
# Creating a stamp removes the other stamps of the same tool, which also covers
# switching back to a version that was used before.
STAMP_DIR := $(BUILD_DIR)/.stamps
stamp = $(STAMP_DIR)/$(1)@$(2)

$(STAMP_DIR)/%:
	@mkdir -p $(STAMP_DIR)
	@rm -f $(STAMP_DIR)/$(firstword $(subst @, ,$*))@*
	@touch $@

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
	CGO_ENABLED=0 $(GO) build -mod=vendor -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o $(BUILD_DIR)/nri-supply-chain ./cmd/nri-supply-chain/

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

##@ Test

.PHONY: integration
integration: build ## Run bats integration tests
	bats --jobs $(shell nproc 2>/dev/null || sysctl -n hw.ncpu) test/integration/

.PHONY: e2e
e2e: build $(KUBERNIX) $(COSIGN) $(CRANE) $(HELM) ## Run bats e2e tests (requires root and Nix)
	bats test/e2e/

##@ Release

.PHONY: snapshot
snapshot: $(GORELEASER) ## Run goreleaser snapshot build
	$(GORELEASER) release --snapshot --skip=sign --clean

##@ Verification

.PHONY: verify-all
verify-all: lint verify-shfmt verify-shellcheck verify-mdtoc verify-jsonschema verify-helm verify-manifests verify-tidy verify-mod verify-vendor verify-no-test-deps verify-dependencies govulncheck verify-prettier verify-markdownlint verify-typos verify-dashboard ## Run all verification targets

.PHONY: lint
lint: $(GOLANGCI_LINT) ## Run golangci-lint
	$(GOLANGCI_LINT) run

$(GOLANGCI_LINT): $(call stamp,golangci-lint,$(GOLANGCI_LINT_VERSION))
	@mkdir -p $(BUILD_DIR)
	curl -sSfL -o $(BUILD_DIR)/golangci-lint.tar.gz \
		https://github.com/golangci/golangci-lint/releases/download/v$(GOLANGCI_LINT_VERSION)/golangci-lint-$(GOLANGCI_LINT_VERSION)-$(OS)-$(ARCH).tar.gz
	$(call verify_checksum,$(BUILD_DIR)/golangci-lint.tar.gz,GOLANGCI_LINT)
	tar xmfz $(BUILD_DIR)/golangci-lint.tar.gz -C $(BUILD_DIR) --strip-components=1 \
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

.PHONY: verify-mod
verify-mod: ## Verify module dependencies match go.sum
	$(GO) mod verify

.PHONY: vendor
vendor: ## Update vendor directory
	$(GO) mod vendor

.PHONY: verify-vendor
verify-vendor: ## Verify vendor directory is in sync
	$(GO) mod vendor
	git diff --exit-code vendor/
	@untracked=$$(git ls-files --others vendor/); \
	if [ -n "$$untracked" ]; then \
		echo "ERROR: go mod vendor created files that are not committed:"; \
		echo "$$untracked"; \
		exit 1; \
	fi

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

.PHONY: verify-markdownlint
verify-markdownlint: ## Lint Markdown files with markdownlint-cli2
	npx markdownlint-cli2@$(MARKDOWNLINT_VERSION) "**/*.md" "#vendor" "#build" "#dist" "#node_modules" "#.claude"

.PHONY: verify-dashboard
verify-dashboard: $(DASHBOARD_LINTER) ## Lint Grafana dashboard JSON
	$(DASHBOARD_LINTER) lint deploy/grafana/dashboard.json
	diff deploy/grafana/dashboard.json deploy/helm/nri-supply-chain/files/dashboard.json

$(ZEITGEIST): $(call stamp,zeitgeist,$(ZEITGEIST_VERSION))
	@mkdir -p $(BUILD_DIR)
	curl -sSfL -o $(ZEITGEIST) \
		https://github.com/kubernetes-sigs/zeitgeist/releases/download/v$(ZEITGEIST_VERSION)/zeitgeist-$(ARCH)-$(OS)
	$(call verify_checksum,$(ZEITGEIST),ZEITGEIST)
	chmod +x $(ZEITGEIST)

$(SHFMT): $(call stamp,shfmt,$(SHFMT_VERSION))
	@mkdir -p $(BUILD_DIR)
	curl -sSfL -o $(SHFMT) \
		https://github.com/mvdan/sh/releases/download/$(SHFMT_VERSION)/shfmt_$(SHFMT_VERSION)_$(OS)_$(ARCH)
	$(call verify_checksum,$(SHFMT),SHFMT)
	chmod +x $(SHFMT)

$(SHELLCHECK): $(call stamp,shellcheck,$(SHELLCHECK_VERSION))
	@mkdir -p $(BUILD_DIR)
	curl -sSfL -o $(BUILD_DIR)/shellcheck.tar.xz \
		https://github.com/koalaman/shellcheck/releases/download/$(SHELLCHECK_VERSION)/shellcheck-$(SHELLCHECK_VERSION).$(OS).$(SHELLCHECK_ARCH).tar.xz
	$(call verify_checksum,$(BUILD_DIR)/shellcheck.tar.xz,SHELLCHECK)
	tar xmfJ $(BUILD_DIR)/shellcheck.tar.xz -C $(BUILD_DIR) --strip-components=1 shellcheck-$(SHELLCHECK_VERSION)/shellcheck
	rm $(BUILD_DIR)/shellcheck.tar.xz

$(MDTOC): $(call stamp,mdtoc,$(MDTOC_VERSION))
	@mkdir -p $(BUILD_DIR)
	GOBIN=$(abspath $(BUILD_DIR)) $(GO) install sigs.k8s.io/mdtoc@$(MDTOC_VERSION)
	touch $@

$(KUBERNIX): $(call stamp,kubernix,$(KUBERNIX_VERSION))
	@mkdir -p $(BUILD_DIR)
	curl -sSfL -o $(KUBERNIX) \
		https://github.com/saschagrunert/kubernix/releases/download/v$(KUBERNIX_VERSION)/kubernix-$(UNAME_ARCH)
	$(call verify_checksum,$(KUBERNIX),KUBERNIX)
	chmod +x $(KUBERNIX)

$(COSIGN): $(call stamp,cosign,$(COSIGN_VERSION))
	@mkdir -p $(BUILD_DIR)
	curl -sSfL -o $(COSIGN) \
		https://github.com/sigstore/cosign/releases/download/v$(COSIGN_VERSION)/cosign-$(OS)-$(ARCH)
	$(call verify_checksum,$(COSIGN),COSIGN)
	chmod +x $(COSIGN)

$(CRANE): $(call stamp,crane,$(CRANE_VERSION))
	@mkdir -p $(BUILD_DIR)
	curl -sSfL -o $(BUILD_DIR)/crane.tar.gz \
		https://github.com/google/go-containerregistry/releases/download/v$(CRANE_VERSION)/go-containerregistry_$(CRANE_OS)_$(CRANE_ARCH).tar.gz
	$(call verify_checksum,$(BUILD_DIR)/crane.tar.gz,CRANE)
	tar xmfz $(BUILD_DIR)/crane.tar.gz -C $(BUILD_DIR) crane
	rm $(BUILD_DIR)/crane.tar.gz

$(DASHBOARD_LINTER): $(call stamp,dashboard-linter,$(DASHBOARD_LINTER_VERSION))
	@mkdir -p $(BUILD_DIR)
	curl -sSfL -o $(BUILD_DIR)/dashboard-linter.tar.gz \
		https://github.com/grafana/dashboard-linter/releases/download/v$(DASHBOARD_LINTER_VERSION)/dashboard-linter_$(DASHBOARD_LINTER_VERSION)_$(OS)_$(ARCH).tar.gz
	$(call verify_checksum,$(BUILD_DIR)/dashboard-linter.tar.gz,DASHBOARD_LINTER)
	tar xmfz $(BUILD_DIR)/dashboard-linter.tar.gz -C $(BUILD_DIR) dashboard-linter
	rm $(BUILD_DIR)/dashboard-linter.tar.gz

$(HELM): $(call stamp,helm,$(HELM_VERSION))
	@mkdir -p $(BUILD_DIR)
	curl -sSfL -o $(BUILD_DIR)/helm.tar.gz \
		https://get.helm.sh/helm-v$(HELM_VERSION)-$(OS)-$(ARCH).tar.gz
	$(call verify_checksum,$(BUILD_DIR)/helm.tar.gz,HELM)
	tar xmfz $(BUILD_DIR)/helm.tar.gz -C $(BUILD_DIR) --strip-components=1 $(OS)-$(ARCH)/helm
	rm $(BUILD_DIR)/helm.tar.gz

$(KUBECONFORM): $(call stamp,kubeconform,$(KUBECONFORM_VERSION))
	@mkdir -p $(BUILD_DIR)
	curl -sSfL -o $(BUILD_DIR)/kubeconform.tar.gz \
		https://github.com/yannh/kubeconform/releases/download/v$(KUBECONFORM_VERSION)/kubeconform-$(OS)-$(ARCH).tar.gz
	$(call verify_checksum,$(BUILD_DIR)/kubeconform.tar.gz,KUBECONFORM)
	tar xmfz $(BUILD_DIR)/kubeconform.tar.gz -C $(BUILD_DIR) kubeconform
	rm $(BUILD_DIR)/kubeconform.tar.gz

$(GORELEASER): $(call stamp,goreleaser,$(GORELEASER_VERSION))
	@mkdir -p $(BUILD_DIR)
	curl -sSfL -o $(BUILD_DIR)/goreleaser.tar.gz \
		https://github.com/goreleaser/goreleaser/releases/download/v$(GORELEASER_VERSION)/goreleaser_$(CRANE_OS)_$(CRANE_ARCH).tar.gz
	$(call verify_checksum,$(BUILD_DIR)/goreleaser.tar.gz,GORELEASER)
	tar xmfz $(BUILD_DIR)/goreleaser.tar.gz -C $(BUILD_DIR) goreleaser
	rm $(BUILD_DIR)/goreleaser.tar.gz

$(GOVULNCHECK): $(call stamp,govulncheck,$(GOVULNCHECK_VERSION))
	@mkdir -p $(BUILD_DIR)
	GOBIN=$(abspath $(BUILD_DIR)) $(GO) install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	touch $@

.PHONY: govulncheck
govulncheck: $(GOVULNCHECK) ## Run govulncheck
	$(GOVULNCHECK) ./cmd/...

##@ Maintenance

.PHONY: tidy
tidy: ## Run go mod tidy
	$(GO) mod tidy

.PHONY: clean
clean: ## Remove build and release artifacts
	rm -rf $(BUILD_DIR) dist
