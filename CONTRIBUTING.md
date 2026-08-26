# Contributing

Thank you for your interest in contributing to mcp-guard! This document outlines the process for contributing to this project.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for all contributors.

## How to Contribute

### Reporting Bugs

Before opening a bug report, please check [existing issues](https://github.com/ShovalBenjer/mcp-guard/issues) to avoid duplicates. When filing a bug report, include:

- mcp-guard version (`mcp-guard --version` or `pip show mcp-guard`)
- Python version
- Target server name and version
- Full command used
- Expected vs actual output

### Suggesting Features

Feature requests are welcome. Please describe:

- The problem you're solving
- Your proposed solution
- Any alternatives you've considered

### Development Setup

```bash
git clone https://github.com/ShovalBenjer/mcp-guard.git
cd mcp-guard
pip install -e ".[dev]"
```

### Running Tests

```bash
pytest tests/
```

### Linting

```bash
ruff check src/ tests/
ruff format src/ tests/
mypy src/
```

### Submitting a Pull Request

1. Fork the repository and create a feature branch from `main`.
2. Make your changes, following the existing code style.
3. Add tests for any new functionality.
4. Ensure all tests pass and linting is clean.
5. Open a pull request with a clear description of the change.

## Adding Leaderboard Entries

To add a new server to the leaderboard:

1. Run mcp-guard against your server:
   ```bash
   mcp-guard fuzz -- npx @your-org/your-mcp-server
   ```
2. Capture the full output.
3. Open a PR updating `LEADERBOARD.md` with your results formatted as a new table row.

## Code Style

- Follow PEP 8 with a 100-character line length.
- Use type hints for all function signatures.
- Use `dataclass` for data structures.
- No external runtime dependencies — stdlib only.
