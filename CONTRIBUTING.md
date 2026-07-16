# Contributing Guidelines

Welcome to nri-supply-chain! We are excited about the prospect of you joining
our community. This project abides by the [code of conduct](code-of-conduct.md).

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
