# Contributing to Universal Template System

Thank you for your interest in contributing to the Universal Template System! This document provides guidelines and instructions for contributing.

## Getting Started

### Prerequisites

- Python 3.10 or 3.11
- Git
- Basic understanding of the template system structure

### Setting Up Development Environment

1. **Clone the repository**:
   ```bash
   git clone https://github.com/FishRaposo/_templates.git
   cd _templates
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   ```

3. **Install pre-commit hooks** (optional but recommended):
   ```bash
   pip install pre-commit
   pre-commit install
   ```

## Running Validations and Tests

### Template Validation

Before submitting any changes, run the full template validation suite:

```bash
python scripts/validate-templates.py --full
```

This validates:
- File structure and organization
- Blueprint metadata schemas
- Template consistency
- Cross-references and links

### Running Tests

Run the pytest suite to ensure all tests pass:

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_render_template_smoke.py -v

# Run with coverage
pytest tests/ --cov=template_schema --cov=scripts
```

### Code Quality Checks

If you have pre-commit installed, run all checks:

```bash
pre-commit run --all-files
```

Or run individual tools:

```bash
# Format code with black
black scripts/ tests/ template_schema/

# Lint with ruff
ruff check scripts/ tests/ template_schema/ --fix

# Type checking with mypy
mypy template_schema/
```

## Making Changes

### Adding New Templates

When adding new templates:

1. Follow the existing template structure in `stacks/`, `tasks/`, or `blueprints/`
2. Ensure templates include proper header comments
3. Use consistent placeholder syntax: `{{VARIABLE}}` or `[[.Field]]`
4. Run validation: `python scripts/validate-templates.py --full`

### Modifying Schema Models

If you need to update the template metadata schema:

1. Edit `template_schema/schema.py`
2. Regenerate JSON schema: `python template_schema/schema.py`
3. Update tests if needed
4. Run full validation and tests

### Adding or Modifying Tests

- Place new tests in the `tests/` directory
- Follow pytest conventions (test files start with `test_`)
- Use descriptive test names
- Add docstrings explaining what each test validates

## Continuous Integration

All pull requests automatically run:

1. **Template validation** - Ensures all templates are valid
2. **Pytest suite** - Runs all integration and unit tests
3. **Matrix testing** - Tests on Python 3.10 and 3.11

The CI must pass before a PR can be merged.

## Pull Request Guidelines

1. **Branch naming**: Use descriptive names like `feature/add-rust-stack` or `fix/blueprint-validation`
2. **Commit messages**: Write clear, concise commit messages
3. **Test coverage**: Add tests for new features
4. **Documentation**: Update relevant documentation
5. **Validation**: Ensure all validations and tests pass locally before pushing

## Pull Request Checklist

Before submitting a PR, ensure:

- [ ] All template validation passes: `python scripts/validate-templates.py --full`
- [ ] All tests pass: `pytest tests/ -v`
- [ ] Code is formatted: `black scripts/ tests/ template_schema/`
- [ ] No linting errors: `ruff check scripts/ tests/ template_schema/`
- [ ] New features include tests
- [ ] Documentation is updated if needed
- [ ] Commit messages are clear and descriptive

## Code Style

- **Python**: Follow PEP 8, enforced by black and ruff
- **Line length**: 100 characters (black default)
- **Imports**: Organize imports logically (standard library, third-party, local)
- **Type hints**: Use type hints for new code when practical
- **Docstrings**: Add docstrings for modules, classes, and functions

## Template Structure Guidelines

### Stack Templates
- Located in `stacks/{stack_name}/`
- Include base templates, tests, and documentation
- Follow language-specific conventions

### Task Templates
- Located in `tasks/{task_name}/`
- Include universal and stack-specific implementations
- Document dependencies and requirements

### Blueprint Templates
- Located in `blueprints/{blueprint_name}/`
- Include `BLUEPRINT.md` and `blueprint.meta.yaml`
- Define clear constraints and overlays

## Getting Help

- **Documentation**: Check `README.md`, `QUICKSTART.md`, and `AGENTS.md`
- **Issues**: Search existing issues or open a new one
- **Questions**: Use GitHub Discussions for questions

## License

By contributing, you agree that your contributions will be licensed under the same license as the project.

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help maintain a welcoming community

---

Thank you for contributing to the Universal Template System! 🚀
