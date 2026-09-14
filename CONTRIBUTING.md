# Contributing Guidelines

Welcome to nri-supply-chain! We are excited about the prospect of you joining
our community. This project abides by the [code of conduct](CODE_OF_CONDUCT.md).

## Getting Started

1. Fork the repository
2. Create a feature branch from `main`
3. Make your changes
4. Run `make lint test integration` to verify
5. Submit a pull request

## Development

```console
make help        # Show all available targets
make build       # Build the binary
make test        # Run unit tests
make lint        # Run linters
make integration # Run integration tests
```

## Pull Requests

- Keep changes focused and atomic
- Include tests for new functionality
- Ensure all CI checks pass
- Sign off your commits (`git commit -s`)

## Verification

Run all checks before submitting:

```shell
make verify-all
```

This runs lint, shfmt, shellcheck, mdtoc, jsonschema, helm, manifests, tidy,
vendor, dependencies, govulncheck, prettier, typos, and dashboard checks.
`make verify-manifests` schema-validates the raw manifests and the rendered
Helm chart, validates their embedded config and policies with the plugin
binary, and fails when the two drift apart.

## Testing

```shell
make test         # Unit tests with race detection and coverage
make fuzz         # Fuzz tests (FUZZTIME adjustable, default 30s)
make integration  # Bats integration tests
make e2e          # End-to-end tests (requires Nix, kubernix, root)
make bench        # Benchmark tests
```

## Dependencies

External tool versions are tracked in `dependencies.yaml` and verified by
`make verify-dependencies`. When bumping a tool version, update every file
listed in its `refPaths` entry. Downloaded tools are pinned by SHA-256 checksum
in the `Makefile` (`<TOOL>_SHA256_<os>_<arch>`) and the download fails when no
checksum is pinned for the current platform, so update the checksums together
with the version.

To bump the project version, run `hack/bump-version.sh X.Y.Z`.
