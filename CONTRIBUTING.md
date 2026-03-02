# Contributing to SocialBlobs

Thank you for your interest in contributing to SocialBlobs!

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/<your-username>/SocialBlobs.git`
3. Install dependencies: `pip install -r requirements.txt`
4. Run tests: `pytest -v`

## Development Setup

```bash
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows
pip install -r requirements.txt
```

## Running Tests

```bash
# Run all tests
pytest -v

# Run specific test file
pytest test_blob_encoder.py -v

# Run the original integration test
python test.py
```

## Code Style

- Python code follows PEP 8
- Vyper contracts follow Vyper style guidelines
- Keep functions focused and well-documented
- Add tests for new functionality

## Pull Request Process

1. Create a feature branch from `main`
2. Make your changes with clear commit messages
3. Ensure all tests pass (`pytest -v`)
4. Update documentation if needed
5. Submit a pull request with a clear description

## Reporting Issues

- Use GitHub Issues for bug reports and feature requests
- Include steps to reproduce for bugs
- Reference relevant ERC sections when applicable

## ERC References

- [ERC-8179 (BSS)](https://github.com/ethereum/ERCs/pull/1577) — Blob Space Segments
- [ERC-8180 (BAM)](https://github.com/ethereum/ERCs/pull/1578) — Blob Authenticated Messaging

## License

By contributing, you agree that your contributions will be licensed under CC0 1.0 Universal.
