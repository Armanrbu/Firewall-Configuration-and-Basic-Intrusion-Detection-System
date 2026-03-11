# Contributing to NetGuard IDS

Thank you for your interest in contributing! Please read this guide before submitting a PR.

## Development Setup

```bash
git clone https://github.com/Armanrbu/Firewall-Configuration-and-Basic-Intrusion-Detection-System.git
cd Firewall-Configuration-and-Basic-Intrusion-Detection-System

# Create venv
python -m venv .venv && source .venv/bin/activate    # Linux/macOS
python -m venv .venv && .venv\Scripts\activate       # Windows

# Install all dev deps
pip install -e ".[gui,api,cli,ml,dev]"
```

## Running Tests

```bash
# All tests
pytest tests/

# With coverage report
pytest tests/ --cov=api --cov=cli --cov=core --cov=utils --cov-report=term-missing

# Specific file
pytest tests/test_cli.py -v
```

## Code Style

We use **ruff** for linting + formatting:

```bash
ruff check .          # lint
ruff format .         # auto-format
ruff check --fix .    # auto-fix lint issues
```

And **mypy** for type checking:

```bash
mypy core/ api/ cli/ utils/ --ignore-missing-imports
```

## Writing Detection Rules

Rules live in `rules/`. See `rules/builtin.yaml` for examples.
Use `python -m cli rules validate path/to/rule.yaml` to validate before committing.

## Pull Request Guidelines

1. Branch off `develop` (not `main`)
2. Write tests for new code (aim for ≥75% coverage on new modules)
3. Run `pytest` and `ruff` locally before opening a PR
4. Add an entry to `CHANGELOG.md` under `[Unreleased]`
5. Fill in the PR template

## Reporting Bugs

See [SECURITY.md](SECURITY.md) for security issues.
For ordinary bugs, open a GitHub issue using the Bug Report template.
