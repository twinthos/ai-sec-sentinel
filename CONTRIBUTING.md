# Contributing to Twinthos Sentinel

## How to contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Make your changes
4. Run tests: `python -m unittest tests.test_sentinel_core tests.test_comprehensive -v`
5. Commit with a clear message
6. Push to your fork
7. Open a pull request

## Code standards

- Python 3.10+ compatible
- All new features must have tests
- No secrets in code or config files
- Use `privacy.redact_text()` for any user-facing output
- Follow existing code style (PEP 8)

## Security

- Report vulnerabilities via SECURITY.md process
- Do not open public issues for security vulnerabilities
- All PRs are reviewed for security implications

## Testing

- Run full test suite before submitting PR
- Add tests for new features
- Do not skip failing tests
- Do not modify test expectations to make tests pass

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
