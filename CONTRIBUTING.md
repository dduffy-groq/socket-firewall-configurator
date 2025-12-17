# Contributing to Socket Firewall Configurator

Thank you for your interest in contributing! This document provides guidelines for development and contribution.

## Development Setup

### Prerequisites

- Python 3.10 or higher
- pip
- Git

### Local Setup

1. Clone the repository:

```bash
git clone https://github.com/your-org/socket-firewall-configurator.git
cd socket-firewall-configurator
```

2. Create a virtual environment:

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:

```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

4. Install pre-commit hooks:

```bash
pre-commit install
```

## Development Workflow

### Running Tests

```bash
pytest tests/ -v
```

With coverage:

```bash
pytest tests/ -v --cov=app --cov-report=html
```

### Linting

```bash
# Run all linters
flake8 app/
black --check app/
isort --check-only app/
mypy app/
```

### Formatting

```bash
black app/
isort app/
```

## Code Style

- Follow PEP 8 guidelines
- Use type hints for all function parameters and return values
- Write docstrings for all public functions and classes
- Keep functions focused and under 50 lines when possible

## Pull Request Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run tests and linting
5. Commit with clear messages
6. Push and create a pull request

### Commit Message Format

```
type: short description

Longer description if needed.

Fixes #123
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

## Adding New Socket Patterns

To add detection for new socket patterns:

1. Edit `app/socket-firewall-configurator/scanner.py`
2. Add patterns to the appropriate language in `SOCKET_PATTERNS`
3. Add tests in `tests/test_scanner.py`
4. Update documentation

Example:

```python
SOCKET_PATTERNS = {
    "python": {
        # Existing patterns...
        "new_framework": r"NewFramework\.listen\(",
    },
}
```

## Adding New Templates

1. Create a new file in `templates/rules/`
2. Follow the existing template format
3. Add documentation to README.md

## Questions?

Open an issue for questions or discussion.

