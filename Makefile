GO ?= go

GOLANGCI_LINT_VERSION = 2.12.2
ZEITGEIST_VERSION = 0.7.0
SHFMT_VERSION = v3.13.1
SHELLCHECK_VERSION = v0.11.0
KUBERNIX_VERSION = 0.3.4
MDTOC_VERSION = v1.4.0
COSIGN_VERSION = 3.1.2
CRANE_VERSION = 0.21.7
GOVULNCHECK_VERSION = v1.6.0

# SHA-256 checksums for downloaded CI tools (linux/amd64).
# Verification is skipped on other platforms.
KUBERNIX_SHA256 = 93a6d0a9b9fa09e51e7187a186a289deb7761392b953db1f49d130b700891ade
COSIGN_SHA256 = f7622ed3cf22e55e1ae6377c080979ff77a22da9981c11df222a2e444991e7cf
CRANE_SHA256 = 1a57bc98207fa1c0d04bf760699099e26f8383499bfd55b99c1b919a928a7230
ZEITGEIST_SHA256 = 68525c8d56635f898e2dff94f37332412ff42d16bb6d78f2b07d974b291c0725
SHFMT_SHA256 = fb096c5d1ac6beabbdbaa2874d025badb03ee07929f0c9ff67563ce8c75398b1
SHELLCHECK_SHA256 = 8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198

# verify_checksum verifies a file's SHA-256 checksum on linux/amd64.
# Usage: $(call verify_checksum,file,expected_hash)
define verify_checksum
	if [ "$$(uname -s)" = "Linux" ] && [ "$$(uname -m)" = "x86_64" ]; then \
		echo "$(2)  $(1)" | sha256sum -c -; \
	fi
endef

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || sed -n 's/^var version = "\(.*\)"/\1/p' cmd/nri-supply-chain/main.go)
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

ARCH ?= $(shell uname -m | \
	sed 's/x86_64/amd64/' | \
	sed 's/aarch64/arm64/')

OS ?= $(shell uname -s | tr '[:upper:]' '[:lower:]')

SHELLCHECK_ARCH ?= $(shell uname -m)
CRANE_OS ?= $(shell uname -s)
CRANE_ARCH ?= $(shell uname -m | sed 's/aarch64/arm64/')

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
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o $(BUILD_DIR)/nri-supply-chain ./cmd/nri-supply-chain/

PREFIX ?= /usr/local

.PHONY: install
install: build ## Install the binary to $(PREFIX)/bin
	install -m 0755 $(BUILD_DIR)/nri-supply-chain $(PREFIX)/bin/nri-supply-chain

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
snapshot: ## Run goreleaser snapshot build
	goreleaser release --snapshot --skip=sign --clean

.PHONY: integration
integration: build ## Run bats integration tests
	bats --jobs $(shell nproc 2>/dev/null || sysctl -n hw.ncpu) test/integration/

.PHONY: e2e
e2e: build $(KUBERNIX) $(COSIGN) $(CRANE) ## Run bats e2e tests (requires root and Nix)
	bats test/e2e/

##@ Verification

.PHONY: verify-all
verify-all: lint verify-shfmt verify-shellcheck verify-mdtoc verify-jsonschema verify-tidy verify-dependencies govulncheck ## Run all verification targets

.PHONY: lint
lint: $(GOLANGCI_LINT) ## Run golangci-lint
	$(GOLANGCI_LINT) run

$(GOLANGCI_LINT):
	@mkdir -p $(BUILD_DIR)
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/v$(GOLANGCI_LINT_VERSION)/install.sh | sh -s -- -b $(BUILD_DIR) v$(GOLANGCI_LINT_VERSION)

SHELL_FILES := $(shell find . -name '*.sh' -o -name '*.bash' -o -name '*.bats' | sort)

.PHONY: verify-shfmt
verify-shfmt: $(SHFMT) ## Verify shell script formatting
	$(SHFMT) -d $(SHELL_FILES)

.PHONY: verify-shellcheck
verify-shellcheck: $(SHELLCHECK) ## Run shellcheck on shell scripts
	$(SHELLCHECK) $(SHELL_FILES)

.PHONY: verify-mdtoc
verify-mdtoc: $(MDTOC) ## Verify table of contents in docs
	for f in README.md docs/*.md; do $(MDTOC) --inplace --dryrun "$$f"; done

.PHONY: verify-jsonschema
verify-jsonschema: build ## Verify JSON Schemas in docs match CLI output
	@generated=$$($(BUILD_DIR)/nri-supply-chain --json-schema policy | jq -S .); \
	[ -n "$$generated" ] || { echo "ERROR: empty policy schema output"; exit 1; }; \
	embedded=$$(sed -n '/<!-- jsonschema-start -->/,/<!-- jsonschema-end -->/p' docs/policy.md \
		| sed -n '/^```json$$/,/^```$$/p' | sed '1d;$$d' | jq -S .); \
	[ -n "$$embedded" ] || { echo "ERROR: no schema found in docs/policy.md"; exit 1; }; \
	if [ "$$generated" != "$$embedded" ]; then \
		echo "ERROR: JSON Schema in docs/policy.md is out of date."; \
		echo "Run 'nri-supply-chain --json-schema policy' and update the schema section."; \
		exit 1; \
	fi
	@generated=$$($(BUILD_DIR)/nri-supply-chain --json-schema result | jq -S .); \
	[ -n "$$generated" ] || { echo "ERROR: empty result schema output"; exit 1; }; \
	embedded=$$(sed -n '/<!-- verify-jsonschema-start -->/,/<!-- verify-jsonschema-end -->/p' docs/config.md \
		| sed -n '/^```json$$/,/^```$$/p' | sed '1d;$$d' | jq -S .); \
	[ -n "$$embedded" ] || { echo "ERROR: no schema found in docs/config.md"; exit 1; }; \
	if [ "$$generated" != "$$embedded" ]; then \
		echo "ERROR: JSON Schema in docs/config.md is out of date."; \
		echo "Run 'nri-supply-chain --json-schema result' and update the schema section."; \
		exit 1; \
	fi

.PHONY: verify-tidy
verify-tidy: ## Verify go.mod is tidy
	$(GO) mod tidy
	git diff --exit-code go.mod go.sum

.PHONY: verify-dependencies
verify-dependencies: $(ZEITGEIST) ## Verify external dependencies
	$(ZEITGEIST) validate --local-only --base-path . --config dependencies.yaml

$(ZEITGEIST):
	@mkdir -p $(BUILD_DIR)
	curl -sSfL -o $(ZEITGEIST) \
		https://github.com/kubernetes-sigs/zeitgeist/releases/download/v$(ZEITGEIST_VERSION)/zeitgeist-$(ARCH)-$(OS)
	$(call verify_checksum,$(ZEITGEIST),$(ZEITGEIST_SHA256))
	chmod +x $(ZEITGEIST)

$(SHFMT):
	@mkdir -p $(BUILD_DIR)
	curl -sSfL -o $(SHFMT) \
		https://github.com/mvdan/sh/releases/download/$(SHFMT_VERSION)/shfmt_$(SHFMT_VERSION)_$(OS)_$(ARCH)
	$(call verify_checksum,$(SHFMT),$(SHFMT_SHA256))
	chmod +x $(SHFMT)

$(SHELLCHECK):
	@mkdir -p $(BUILD_DIR)
	curl -sSfL -o $(BUILD_DIR)/shellcheck.tar.xz \
		https://github.com/koalaman/shellcheck/releases/download/$(SHELLCHECK_VERSION)/shellcheck-$(SHELLCHECK_VERSION).$(OS).$(SHELLCHECK_ARCH).tar.xz
	$(call verify_checksum,$(BUILD_DIR)/shellcheck.tar.xz,$(SHELLCHECK_SHA256))
	tar xfJ $(BUILD_DIR)/shellcheck.tar.xz -C $(BUILD_DIR) --strip-components=1 shellcheck-$(SHELLCHECK_VERSION)/shellcheck
	rm $(BUILD_DIR)/shellcheck.tar.xz

$(MDTOC):
	@mkdir -p $(BUILD_DIR)
	GOBIN=$(abspath $(BUILD_DIR)) $(GO) install sigs.k8s.io/mdtoc@$(MDTOC_VERSION)

$(KUBERNIX):
	@mkdir -p $(BUILD_DIR)
	curl -sSfL -o $(KUBERNIX) \
		https://github.com/saschagrunert/kubernix/releases/download/v$(KUBERNIX_VERSION)/kubernix-$(shell uname -m)
	$(call verify_checksum,$(KUBERNIX),$(KUBERNIX_SHA256))
	chmod +x $(KUBERNIX)

$(COSIGN):
	@mkdir -p $(BUILD_DIR)
	curl -sSfL -o $(COSIGN) \
		https://github.com/sigstore/cosign/releases/download/v$(COSIGN_VERSION)/cosign-$(OS)-$(ARCH)
	$(call verify_checksum,$(COSIGN),$(COSIGN_SHA256))
	chmod +x $(COSIGN)

$(CRANE):
	@mkdir -p $(BUILD_DIR)
	curl -sSfL -o $(BUILD_DIR)/crane.tar.gz \
		https://github.com/google/go-containerregistry/releases/download/v$(CRANE_VERSION)/go-containerregistry_$(CRANE_OS)_$(CRANE_ARCH).tar.gz
	$(call verify_checksum,$(BUILD_DIR)/crane.tar.gz,$(CRANE_SHA256))
	tar xfz $(BUILD_DIR)/crane.tar.gz -C $(BUILD_DIR) crane
	rm $(BUILD_DIR)/crane.tar.gz

$(GOVULNCHECK):
	@mkdir -p $(BUILD_DIR)
	GOBIN=$(abspath $(BUILD_DIR)) $(GO) install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

.PHONY: govulncheck
govulncheck: $(GOVULNCHECK) ## Run govulncheck
	$(GOVULNCHECK) ./...

##@ Maintenance

.PHONY: tidy
tidy: ## Run go mod tidy
	$(GO) mod tidy

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf $(BUILD_DIR)
