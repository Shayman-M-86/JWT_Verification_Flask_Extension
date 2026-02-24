# Contributing to JWT Verification Extension

Thank you for your interest in contributing! This document provides guidelines and information for contributors.

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Getting Started](#getting-started)
3. [Development Setup](#development-setup)
4. [Code Style](#code-style)
5. [Testing](#testing)
6. [Documentation](#documentation)
7. [Pull Request Process](#pull-request-process)
8. [Reporting Bugs](#reporting-bugs)
9. [Suggesting Features](#suggesting-features)
10. [Security Issues](#security-issues)

---

## Code of Conduct

### Our Pledge

We are committed to providing a welcoming and inclusive environment for all contributors.

### Expected Behavior

- Be respectful and constructive
- Welcome newcomers and help them learn
- Accept constructive criticism gracefully
- Focus on what's best for the community

### Unacceptable Behavior

- Harassment, discrimination, or offensive comments
- Personal attacks or trolling
- Publishing others' private information
- Other unethical or unprofessional conduct

---

## Getting Started

### Prerequisites

- Python 3.14 or higher
- Git
- Basic understanding of JWT and Flask
- Familiarity with Auth0 (helpful but not required)

### First Contributions

Good first issues for new contributors:

1. **Documentation improvements**
   - Fix typos or unclear explanations
   - Add missing examples
   - Improve error messages

2. **Testing**
   - Add test cases for edge cases
   - Improve test coverage
   - Add integration tests

3. **Examples**
   - Add examples for new use cases
   - Improve existing examples
   - Add integration examples

### Finding Work

- Check the issue tracker for:
  - Issues tagged `good first issue`
  - Issues tagged `help wanted`
  - Issues tagged `documentation`
- Look for TODO comments in code
- Review CHANGELOG.md [Unreleased] section

---

## Development Setup

### 1. Fork and Clone

```bash
# Fork the repository on GitHub, then:
git clone https://github.com/YOUR_USERNAME/auth0_Flask.git # Update actual GitHub URL
cd auth0_Flask
```

### 2. Create Virtual Environment

```bash
# Using uv (recommended)
uv venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Or using standard Python
python -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies

```bash
# Install in development mode
uv pip install -e ".[dev]"

# Or with standard pip
pip install -e ".[dev]"
```

### 4. Install Development Tools

```bash
# Install pre-commit hooks
pre-commit install

# Install testing tools
pip install pytest pytest-cov mypy black ruff
```

### 5. Verify Setup

```bash
# Run tests
pytest

# Run type checking
mypy src/extension/jwt_verification

# Run linting
ruff check src/extension/jwt_verification
```

### 6. Create Feature Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/bug-description
```

---

## Code Style

### Python Style Guide

We follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) with some modifications.

### Formatting

**Use Black for code formatting:**

```bash
black src/extension/jwt_verification
```

**Configuration (.black.toml):**

```toml
line-length = 88
target-version = ['py311']
```

### Linting

**Use Ruff for linting:**

```bash
ruff check src/extension/jwt_verification
```

**Auto-fix issues:**

```bash
ruff check --fix src/extension/jwt_verification
```

### Type Hints

**All code must include type hints:**

✅ Good:

```python
def verify(self, token: str) -> Claims:
    """Verify JWT and return claims."""
    ...
```

❌ Bad:

```python
def verify(self, token):
    """Verify JWT and return claims."""
    ...
```

**Run type checking:**

```bash
mypy src/extension/jwt_verification
```

### Docstrings

**Use Google-style docstrings:**

```python
def authorize(
    self,
    claims: Claims,
    *,
    permissions: FrozenSet[str],
    roles: FrozenSet[str],
    require_all_permissions: bool,
) -> None:
    """
    Enforce authorization rules.

    Args:
        claims: Verified JWT claims
        permissions: Required permissions
        roles: Required roles
        require_all_permissions: If True, user must have all permissions

    Raises:
        Forbidden: If authorization fails

    Example:
        >>> authorizer.authorize(
        ...     claims,
        ...     permissions=frozenset(["read:posts"]),
        ...     roles=frozenset(["user"]),
        ...     require_all_permissions=True,
        ... )
    """
    ...
```

### Naming Conventions

- **Classes:** `PascalCase` (e.g., `AuthExtension`)
- **Functions/Methods:** `snake_case` (e.g., `verify_token`)
- **Constants:** `UPPER_SNAKE_CASE` (e.g., `DEFAULT_TTL`)
- **Private members:** Leading underscore (e.g., `_internal_method`)
- **Type variables:** `PascalCase` with `T` prefix (e.g., `TKey`)

### Import Organization

**Order:**

1. Standard library
2. Third-party libraries
3. Local application/library

**Use absolute imports:**

```python
from jwt_verification import AuthExtension
from jwt_verification.errors import InvalidToken
```

**Format with isort:**

```bash
isort src/extension/jwt_verification
```

---

## Testing

### Writing Tests

**Test file structure:**

```text
tests/
├── JWT_verification/
│   ├── test_auth0_provider.py
│   ├── test_cache_stores.py
│   ├── test_extractor.py
│   ├── test_flask_extension.py
│   ├── test_jwt_verifier.py
│   ├── test_rbac.py
│   └── test_refresh_gate.py
```

**Test naming:**

```python
def test_verifier_accepts_valid_token():
    """Test that verifier accepts tokens with valid signature."""
    ...

def test_verifier_rejects_expired_token():
    """Test that verifier rejects expired tokens."""
    ...

def test_authorizer_requires_all_permissions_when_configured():
    """Test that authorizer enforces all permissions requirement."""
    ...
```

### Test Requirements

**Every PR must:**

- Include tests for new features
- Maintain or improve code coverage
- Pass all existing tests
- Include both positive and negative test cases

**Test categories:**

1. **Unit tests** - Test individual components in isolation
2. **Integration tests** - Test component interactions
3. **Security tests** - Test attack scenarios and mitigations

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src/extension/jwt_verification --cov-report=html

# Run specific test file
pytest tests/JWT_verification/test_jwt_verifier.py

# Run specific test
pytest tests/JWT_verification/test_jwt_verifier.py::test_verifier_accepts_valid_token

# Run with verbose output
pytest -v

# Run and stop on first failure
pytest -x
```

### Test Fixtures

**Use pytest fixtures for common setup:**

```python
import pytest
from jwt_verification import JWTVerifier, JWTVerifyOptions

@pytest.fixture
def verifier_options():
    return JWTVerifyOptions(
        issuer="https://test.auth0.com/",
        audience="test-api",
    )

@pytest.fixture
def verifier(mock_key_provider, verifier_options):
    return JWTVerifier(
        key_provider=mock_key_provider,
        options=verifier_options,
    )

def test_something(verifier):
    # Use verifier fixture
    ...
```

### Coverage Requirements

- **Minimum coverage:** 90%
- **Target coverage:** 95%+
- **Critical paths:** 100% coverage required

**Check coverage:**

```bash
pytest --cov=src/extension/jwt_verification --cov-report=term-missing
```

---

## Documentation

### Documentation Requirements

**All contributions must include:**

1. **Code documentation** (docstrings)
2. **API documentation** (if adding public APIs)
3. **Usage examples** (for new features)
4. **README updates** (for significant changes)

### Updating Documentation

**When adding a new feature:**

1. Add docstrings to all public classes/methods
2. Add entry to API_REFERENCE.md
3. Add usage example to EXAMPLES.md
4. Update README.md if appropriate
5. Add entry to CHANGELOG.md under [Unreleased]

**When fixing a bug:**

1. Update docstrings if behavior changes
2. Add to CHANGELOG.md under [Unreleased] > Fixed
3. Update troubleshooting guide if relevant

### Documentation Style

**Be clear and concise:**

- Use simple language
- Provide examples
- Explain "why" not just "what"
- Include security considerations

**Code examples must:**

- Be complete and runnable
- Include imports
- Show expected output
- Handle errors appropriately

---

## Pull Request Process

### Before Submitting

**Checklist:**

- [ ] Code follows style guidelines
- [ ] All tests pass
- [ ] New tests added for new features
- [ ] Type hints added
- [ ] Docstrings added/updated
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] No merge conflicts with main branch
- [ ] Commits are logical and well-described

### PR Title Format

Use conventional commit format:

```text
type(scope): brief description

Examples:
feat(auth): add support for custom extractors
fix(cache): resolve race condition in InMemoryCache
docs(examples): add SQLAlchemy integration example
test(verifier): add tests for algorithm confusion
refactor(authorizer): simplify permission checking logic
```

**Types:**

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `test`: Adding/updating tests
- `refactor`: Code change that neither fixes a bug nor adds a feature
- `perf`: Performance improvement
- `chore`: Maintenance tasks

### PR Description Template

```markdown
## Description
Brief description of what this PR does.

## Motivation
Why is this change needed? What problem does it solve?

## Changes
- Detailed list of changes
- Be specific about what was modified

## Testing
- How was this tested?
- What test cases were added?

## Documentation
- What documentation was updated?
- Links to relevant docs

## Breaking Changes
- List any breaking changes
- Migration guide if needed

## Checklist
- [ ] Tests pass
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] Type hints added
- [ ] No security issues introduced
```

### Review Process

1. **Automated checks** run (tests, linting, type checking)
2. **Code review** by maintainers
3. **Feedback addressed** by contributor
4. **Approval** from at least one maintainer
5. **Merge** by maintainer

### After Merge

- Your contribution will be included in the next release
- You'll be credited in release notes
- CHANGELOG.md will be updated with the release

---

## Reporting Bugs

### Before Reporting

1. **Search existing issues** - Check if already reported
2. **Try latest version** - Bug may be fixed
3. **Verify it's a bug** - Check documentation
4. **Reproduce** - Can you consistently reproduce it?

### Bug Report Template

```markdown
**Bug Description**
Clear description of the bug.

**To Reproduce**
Steps to reproduce:
1. Configure extension with...
2. Call method...
3. See error

**Expected Behavior**
What you expected to happen.

**Actual Behavior**
What actually happened.

**Code Sample**
```python
# Minimal code to reproduce
```

#### Environment

- Python version:
- Flask version:
- Extension version:
- Auth0 tenant (if relevant):
- OS:

### Error Messages

```Text
Full error message and stack trace
```

**Additional Context**
Any other relevant information.

```text

### Security Bugs

**Do NOT report security issues publicly.**

See [Security Issues](#security-issues) section below.

---

## Suggesting Features

### Before Suggesting

1. **Check existing issues** - May already be planned
2. **Review CHANGELOG.md** - Check [Unreleased] section
3. **Consider scope** - Does it fit the project goals?
4. **Think about users** - Who benefits?

### Feature Request Template

```markdown
**Feature Description**
Clear description of the feature.

**Motivation**
Why is this feature needed?
What problem does it solve?
Who would use it?

**Proposed Solution**
How would you implement this?
What's the API?

**Alternatives Considered**
What other solutions did you consider?
Why is this approach better?

**Code Example**
```python
# How would users use this feature?
```

**Breaking Changes**
Would this break existing code?
How could we avoid that?

**Additional Context**
Any other relevant information.

```text

---

## Security Issues

**Security issues require special handling.**

### Reporting Security Issues

**DO:**
- Email security contact privately (see main README)
- Provide detailed reproduction steps
- Suggest fixes if you have them
- Allow reasonable time for fix (90 days)

**DON'T:**
- Open public GitHub issues
- Discuss in public forums
- Share exploit code publicly
- Pressure for immediate disclosure

### What We'll Do

1. **Acknowledge** receipt within 48 hours
2. **Investigate** and verify the issue
3. **Develop** a fix
4. **Release** patched version
5. **Disclose** publicly after fix is available
6. **Credit** you in security advisory (if desired)

### Security Review

All security-related PRs undergo additional review:
- Threat modeling
- Code review by security-focused maintainer
- Penetration testing for major changes
- Documentation of security implications

---

## Additional Guidelines

### Commit Messages

**Format:**

```text
type(scope): brief description

Longer explanation if needed.

- Bullet points for details
- Reference issues: Fixes #123

```text

**Examples:**
```

feat(auth): add support for EdDSA algorithm

Adds support for Ed25519 signature verification alongside
existing RSA support.

- Add EdDSA to allowed algorithms
- Update key provider to handle EdDSA keys
- Add tests for EdDSA verification

Fixes #456

docs(readme): fix typo in quick start guide

test(cache): add concurrency tests for Redis cache

```text

### Branch Naming

```

feature/add-eddsa-support
fix/cache-race-condition
docs/improve-security-guide
test/add-integration-tests
refactor/simplify-authorizer

```text

### Code Review Etiquette

**As a reviewer:**
- Be respectful and constructive
- Explain reasoning
- Distinguish between blocking and non-blocking feedback
- Approve when ready, even if minor suggestions remain

**As a contributor:**
- Accept feedback gracefully
- Ask questions if unclear
- Make requested changes promptly
- Be patient with review process

---

## Recognition

Contributors will be recognized in:
- Release notes
- CHANGELOG.md
- GitHub contributors page
- Special thanks in documentation (for major contributions)

---

## Questions?

- **Documentation:** Check docs in this directory
- **Usage questions:** Open a discussion on GitHub
- **Bugs:** Open an issue
- **Security:** Email security contact
- **Other:** Open a discussion

Thank you for contributing! 🎉

---

**Last Updated:** February 23, 2026
