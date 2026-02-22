# Contributing to Commerce Abuse Defense

## Requirements

- Python 3.10+
- Git

## Setup

```bash
git clone https://github.com/mason5052/commerce-abuse-defense.git
cd commerce-abuse-defense
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -e ".[dev]"
```

## Development Workflow

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make changes and add tests
4. Run linting: `ruff check src/ tests/`
5. Run tests: `pytest tests/`
6. Commit with a descriptive message
7. Push and open a Pull Request

## Code Style

- Follow PEP 8 (enforced via ruff)
- Line length: 100 characters
- Type hints on all public functions
- Pydantic models for data structures

## Adding a New Detection Rule

1. Create a new file in `src/cad/detectors/`
2. Inherit from `BaseDetector`
3. Implement the `detect()` method
4. Add unit tests in `tests/test_detectors.py`
5. Register the detector in `src/cad/detectors/__init__.py`

## Adding a New Collector

1. Create a new file in `src/cad/collectors/`
2. Inherit from `BaseCollector`
3. Implement the `collect()` method
4. Add configuration docs in `docs/`
