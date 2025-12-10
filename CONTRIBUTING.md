# Contributing to Trustpoint

Thank you for your interest in contributing to Trustpoint! We welcome contributions from the community and appreciate your efforts to improve the project.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for all contributors.

## Reporting Issues

Please use [GitHub Issues](https://github.com/Trustpoint-Project/trustpoint/issues) to report bugs or request enhancements.

When reporting a bug, please include:
- A clear description of the issue
- Steps to reproduce the problem
- Expected vs. actual behavior
- Your environment (OS, Python version, deployment method)
- Relevant log output or error messages

## Reporting Security Vulnerabilities

**Do not report security vulnerabilities through public GitHub issues.**

Please refer to our [Security Policy](SECURITY.md) for instructions on how to report security vulnerabilities privately.

## Making Changes

1. **Fork the repository** and create a feature branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** following the project's coding standards (see below).

3. **Add or update automated tests** for any major new functionality.

4. **Ensure all tests pass** before submitting a pull request:
   ```bash
   uv run pytest tests/
   uv run mypy .
   uv run ruff check .
   ```

5. **Update documentation** if you're adding new features or changing existing behavior.

6. **Commit your changes** with clear, descriptive commit messages.

7. **Push to your fork** and submit a pull request to the `main` branch.

## Development Guidelines

Please follow the guidelines which include:

### Code Style
- Follow PEP 8 and Django's coding style guide
- Add type annotations to all functions and methods
- Include descriptive docstrings in reStructuredText (reST) style
- Use Django's built-in features wherever possible

### Testing
- Write tests for new functionality in `tests/`
- Test file naming: `test_<module>.py`
- Test function naming: Start with `test_`
- Run the full test suite before submitting

### Linting and Type Checking
Before submitting your pull request, ensure your code passes:
- **Ruff linting**: `uv run ruff check .`
- **MyPy type checking**: `uv run mypy .`

## Testing Policy

**Major new functionality must include appropriate automated tests.**

This ensures long-term reliability and maintainability of the project. Tests should cover:
- Normal operation (happy path)
- Edge cases
- Error conditions
- Any security-relevant code paths

We use:
- **pytest** for unit and integration tests
- **behave** for behavior-driven development tests (features)

## Pull Request Process

1. Ensure your PR description clearly describes the problem and solution
2. Reference any related issues using `#issue-number`
3. Make sure all CI/CD checks pass (pytest, mypy, ruff, behave tests)
4. Request review from maintainers
5. Address any review feedback promptly

## Contributor License Agreement

Before your contribution can be merged, you must:

1. **Read and agree** to the Contributor License Agreement found in [`AUTHORS.md`](AUTHORS.md)
2. **Add your name** to the authors list in `AUTHORS.md` following the specified format

By adding your name to the authors list, you certify your agreement with the CLA terms.

## Recognition

All contributors will be acknowledged in the project's `AUTHORS.md` file.

---

We appreciate your contributions and look forward to collaborating with you!
