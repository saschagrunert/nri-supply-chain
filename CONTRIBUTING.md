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

This runs lint, shfmt, shellcheck, mdtoc, jsonschema, tidy,
dependencies, govulncheck, prettier, and typos.

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
listed in its `refPaths` entry.
