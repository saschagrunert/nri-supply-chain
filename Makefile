GO ?= go

GOLANGCI_LINT_VERSION = 2.12.2
ZEITGEIST_VERSION = 0.7.0
SHFMT_VERSION = v3.13.1
SHELLCHECK_VERSION = v0.11.0

BUILD_DIR := build
GOLANGCI_LINT := $(BUILD_DIR)/golangci-lint
ZEITGEIST := $(BUILD_DIR)/zeitgeist
SHFMT := $(BUILD_DIR)/shfmt
SHELLCHECK := $(BUILD_DIR)/shellcheck

ARCH ?= $(shell uname -m | \
	sed 's/x86_64/amd64/' | \
	sed 's/aarch64/arm64/')

OS ?= $(shell uname -s | tr '[:upper:]' '[:lower:]')

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
	CGO_ENABLED=0 $(GO) build -trimpath -o $(BUILD_DIR)/nri-supply-chain ./cmd/nri-supply-chain/

##@ Development

.PHONY: test
test: ## Run tests with race detection and coverage report
	@mkdir -p $(BUILD_DIR)
	$(GO) test -v -race -count=1 -coverprofile=$(BUILD_DIR)/coverage.out -covermode=atomic -coverpkg=./... ./...
	$(GO) tool cover -html=$(BUILD_DIR)/coverage.out -o $(BUILD_DIR)/coverage.html

##@ Release

.PHONY: snapshot
snapshot: ## Run goreleaser snapshot build
	goreleaser release --snapshot --skip=sign --clean

.PHONY: integration
integration: build ## Run bats integration tests
	bats --jobs $(shell nproc 2>/dev/null || sysctl -n hw.ncpu) test/

##@ Verification

.PHONY: lint
lint: $(GOLANGCI_LINT) ## Run golangci-lint
	$(GOLANGCI_LINT) run

$(GOLANGCI_LINT):
	@mkdir -p $(BUILD_DIR)
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sh -s -- -b $(BUILD_DIR) v$(GOLANGCI_LINT_VERSION)

.PHONY: verify-shfmt
verify-shfmt: $(SHFMT) ## Verify shell script formatting
	$(SHFMT) -d test/*.bash test/*.bats

.PHONY: verify-shellcheck
verify-shellcheck: $(SHELLCHECK) ## Run shellcheck on shell scripts
	$(SHELLCHECK) test/*.bash test/*.bats

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
	chmod +x $(ZEITGEIST)

$(SHFMT):
	@mkdir -p $(BUILD_DIR)
	curl -sSfL -o $(SHFMT) \
		https://github.com/mvdan/sh/releases/download/$(SHFMT_VERSION)/shfmt_$(SHFMT_VERSION)_linux_amd64
	chmod +x $(SHFMT)

$(SHELLCHECK):
	@mkdir -p $(BUILD_DIR)
	curl -sSfL \
		https://github.com/koalaman/shellcheck/releases/download/$(SHELLCHECK_VERSION)/shellcheck-$(SHELLCHECK_VERSION).linux.x86_64.tar.xz \
		| tar xfJ - -C $(BUILD_DIR) --strip-components=1 shellcheck-$(SHELLCHECK_VERSION)/shellcheck

.PHONY: govulncheck
govulncheck: ## Run govulncheck
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

##@ Maintenance

.PHONY: tidy
tidy: ## Run go mod tidy
	$(GO) mod tidy

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf $(BUILD_DIR)
