# AI Assistant Context - Flask JWT Verification Extension

This document provides comprehensive context for AI assistants working with this codebase.

## Project Overview

**Name:** flask-jwt-verification  
**Version:** 1.0.0  
**Type:** Flask extension library (not an application)  
**Purpose:** Production-ready JWT authentication and authorization for Flask applications

### Key Principle
The extension is a **reusable library**. The Auth0 demo in `examples/auth0_demo/` is just an example use case - not the main product.

## Project Structure

```
flask-jwt-verification/
├── src/jwt_verification/           # Main package (the library)
│   ├── __init__.py                 # Public API exports
│   ├── flask_extension.py          # @auth.require() decorator
│   ├── verifier.py                 # JWT signature/claims verification
│   ├── authorization.py            # RBAC implementation
│   ├── errors.py                   # Exception hierarchy
│   ├── extractors.py               # Token extraction (Bearer, Cookie)
│   ├── protocols.py                # Protocol definitions (KeyProvider, etc.)
│   ├── cache_stores.py             # InMemoryCache, RedisCache
│   ├── refresh_gate.py             # DoS protection for JWKS refresh
│   └── key_providers/
│       ├── __init__.py
│       └── auth0.py                # Auth0 JWKS provider
│
├── examples/auth0_demo/            # Example application (NOT core product)
│   ├── app.py                      # Backend API example
│   ├── login_provider.py           # OAuth login flow example
│   ├── templates/                  # HTML templates
│   ├── static/                     # CSS and assets
│   ├── certs/                      # Self-signed SSL certificates
│   └── README.md                   # Demo setup guide
│
├── tests/JWT_verification/         # Test suite for extension
│   ├── conftest.py                 # Pytest fixtures
│   ├── test_auth0_provider.py      # Auth0JWKSProvider tests
│   ├── test_cache_stores.py        # Cache implementation tests
│   ├── test_extractor.py           # Token extractor tests
│   ├── test_flask_extension.py     # AuthExtension decorator tests
│   ├── test_jwt_verifier.py        # JWTVerifier tests
│   ├── test_rbac.py                # Authorization tests
│   └── test_refresh_gate.py        # Rate limiting tests
│
├── docs/                           # Documentation
│   ├── README.md                   # Complete guide (architecture, usage)
│   ├── SECURITY.md                 # Security analysis and best practices
│   ├── API_REFERENCE.md            # Complete API documentation
│   ├── EXAMPLES.md                 # Working code examples
│   ├── QUICKREF.md                 # Quick lookup reference
│   ├── INDEX.md                    # Documentation navigation
│   ├── CONTRIBUTING.md             # Contribution guidelines
│   ├── CHANGELOG.md                # Version history
│   ├── DOCS_SUMMARY.md             # Documentation summary
│   └── AI_PROMPT.md                # This file
│
├── pyproject.toml                  # Package configuration
└── README.md                       # Project overview (user-facing)
```

## Architecture

### Request Flow

```
1. HTTP Request with JWT
   ↓
2. @auth.require(roles=["admin"]) decorator (flask_extension.py)
   ↓
3. BearerExtractor extracts token from Authorization header (extractors.py)
   ↓
4. JWTVerifier.verify(token) (verifier.py)
   ├─ jwt.decode() reads unverified header to get 'kid'
   ├─ KeyProvider.get_key(kid) fetches verification key (key_providers/auth0.py)
   │  ├─ Check cache first (cache_stores.py)
   │  ├─ If miss: fetch JWKS from Auth0 (with rate limiting via refresh_gate.py)
   │  └─ Cache the key
   └─ jwt.decode() validates signature, issuer, audience, expiration
   ↓
5. RBACAuthorizer.authorize() checks roles/permissions (authorization.py)
   ↓
6. On success: verified claims stored in flask.g.jwt
   ↓
7. Route handler executes
```

### Core Components

#### 1. AuthExtension (flask_extension.py)
- Entry point for developers
- `@auth.require(roles=[], permissions=[])` decorator
- Integrates verifier and authorizer
- Stores verified JWT in `flask.g.jwt`

#### 2. JWTVerifier (verifier.py)
- Provider-agnostic JWT verification
- Uses PyJWT for cryptographic validation
- Validates: signature, issuer, audience, expiration, algorithms
- Configurable via `JWTVerifyOptions`

#### 3. Auth0JWKSProvider (key_providers/auth0.py)
- Fetches RSA public keys from Auth0 JWKS endpoint
- Multi-layer caching (InMemory or Redis)
- Negative caching (prevents repeated failed lookups)
- DoS protection via RefreshGate
- Thread-safe

#### 4. RBACAuthorizer (authorization.py)
- Role-based and permission-based access control
- Extracts roles/permissions from JWT claims
- Supports both array access and claim mapping
- Flexible claim structure support

#### 5. Cache Stores (cache_stores.py)
- **InMemoryCache**: For development/single-instance (uses threading.Lock)
- **RedisCache**: For production/multi-instance (uses Redis)
- TTL support, negative caching

#### 6. RefreshGate (refresh_gate.py)
- Rate-limits JWKS refresh operations
- Prevents DoS via malicious `kid` values
- Thread-safe with Lock

## Key Design Patterns

### Protocol-Based Extensibility
All major components use Python protocols (PEP 544):
- `KeyProvider` - Custom key sources
- `CacheStore` - Custom cache backends
- `Authorizer` - Custom authorization logic
- `TokenExtractor` - Custom token extraction

### Defense in Depth
Multiple security layers:
1. Signature verification (cryptographic)
2. Claims validation (issuer, audience, expiration)
3. Algorithm allowlist (prevent algorithm confusion)
4. Negative caching (DoS prevention)
5. JWKS refresh throttling (DoS prevention)
6. Thread safety (concurrency protection)

## Common Tasks

### Adding a New KeyProvider

1. Create file in `src/jwt_verification/key_providers/`
2. Implement `KeyProvider` protocol:
   ```python
   class MyProvider:
       def get_key(self, kid: str) -> str:
           """Return PEM-encoded public key for kid."""
           pass
   ```
3. Add to `key_providers/__init__.py` exports
4. Add tests in `tests/JWT_verification/test_my_provider.py`

### Adding a New CacheStore

1. Implement `CacheStore` protocol in `cache_stores.py`:
   ```python
   class MyCache:
       def get(self, key: str) -> bytes | None: ...
       def set(self, key: str, value: bytes, ttl_seconds: int) -> None: ...
   ```
2. Add tests in `test_cache_stores.py`

### Adding a New TokenExtractor

1. Implement `TokenExtractor` protocol in `extractors.py`:
   ```python
   class MyExtractor:
       def extract(self, request: Request) -> str | None:
           """Extract JWT from request."""
           pass
   ```
2. Add tests in `test_extractor.py`

## Import Paths

**Correct imports** (what users should use):
```python
from jwt_verification import (
    AuthExtension,
    JWTVerifier,
    JWTVerifyOptions,
    Auth0JWKSProvider,
    InMemoryCache,
    RedisCache,
    RBACAuthorizer,
    ClaimAccess,
    ClaimsMapping,
    BearerExtractor,
    CookieExtractor,
)
```

**Internal imports** (within the package):
```python
from jwt_verification.verifier import JWTVerifier
from jwt_verification.flask_extension import AuthExtension
from jwt_verification.key_providers.auth0 import Auth0JWKSProvider
```

## Dependencies

### Core
- **Python 3.14+** - Required for modern type hints
- **flask >=3.0.0** - Web framework
- **PyJWT[crypto] >=2.8.0** - JWT verification
- **requests >=2.31.0** - HTTP requests (for JWKS fetch)
- **cryptography >=41.0.0** - RSA signature verification

### Optional
- **redis >=5.0.0** - For production caching
- **auth0-python >=4.7.0** - For examples (OAuth flow)
- **authlib >=1.3.0** - For examples (OAuth flow)

### Development
- **pytest >=8.0.0** - Testing
- **pytest-cov >=4.1.0** - Coverage
- **ruff >=0.1.0** - Linting
- **mypy >=1.8.0** - Type checking

## Testing

### Run Tests
```bash
# All tests
pytest

# Extension tests only (excludes demo)
pytest tests/JWT_verification/

# Specific test file
pytest tests/JWT_verification/test_auth0_provider.py

# With coverage
pytest --cov=jwt_verification --cov-report=html
```

### Test Structure
- All tests use pytest
- Fixtures in `conftest.py`
- Mocking with `unittest.mock`
- Test both success and failure paths
- 100% coverage goal for critical paths

### Current Test Status
- **Extension tests**: 37/37 passing ✅
- **Integration tests**: Removed (were for demo app)

## Security Considerations

### What the Extension Protects Against
1. ✅ Invalid signatures (cryptographic verification)
2. ✅ Expired tokens (exp claim validation)
3. ✅ Wrong issuer (iss claim validation)
4. ✅ Wrong audience (aud claim validation)
5. ✅ Algorithm confusion attacks (explicit RS256 allowlist)
6. ✅ DoS via malicious kid (RefreshGate rate limiting)
7. ✅ DoS via repeated invalid kid (negative caching)

### What It Doesn't Protect Against
1. ❌ Token theft (use HTTPS, secure cookies)
2. ❌ Replay attacks (implement token revocation if needed)
3. ❌ Authorization logic bugs (app's responsibility)
4. ❌ Network attacks (use TLS, firewall)

### Best Practices
- Always use HTTPS in production
- Use Redis for caching in multi-instance deployments
- Set appropriate TTLs (3600s for keys, 60s for negative cache)
- Enable RBAC in Auth0 API settings
- Monitor failed verification attempts
- Test key rotation procedures

## Code Style

### Type Hints
- All public APIs fully typed
- Use Python 3.14+ syntax (e.g., `str | None` not `Optional[str]`)
- Protocols over ABCs for extensibility

### Error Handling
- Custom exceptions in `errors.py`
- Hierarchy: `InvalidToken` (base) → specific errors
- Always include helpful error messages

### Logging
- Use `logging.getLogger("jwt_verification")`
- Log at appropriate levels:
  - DEBUG: Cache hits/misses, verification steps
  - INFO: JWKS refresh, configuration
  - WARNING: Rate limiting triggered, cache errors
  - ERROR: Verification failures, critical errors

### Naming Conventions
- Classes: `PascalCase`
- Functions/methods: `snake_case`
- Constants: `UPPER_SNAKE_CASE`
- Private: `_leading_underscore`

## Common Pitfalls

### Import Errors
❌ **Wrong**: `from src.jwt_verification import AuthExtension`  
✅ **Correct**: `from jwt_verification import AuthExtension`

The package is installed as `jwt_verification`, not `src.jwt_verification`.

### Cache Configuration
❌ **Wrong**: Using InMemoryCache in production with multiple instances  
✅ **Correct**: Use RedisCache for multi-instance deployments

### Claims Mapping
Auth0 can put roles/permissions in different claim structures:
- Array: `{"permissions": ["read:posts", "write:posts"]}`
- Namespaced: `{"https://myapp.com/roles": ["admin"]}`

Use `ClaimsMapping` to configure the claim names.

### Token Extraction
Default is `BearerExtractor` (Authorization header).  
For cookies, explicitly set:
```python
auth = AuthExtension(verifier=verifier, extractor=CookieExtractor("access_token"))
```

## Documentation Guidelines

### When Adding Features
1. Update main [README.md](README.md) - add to relevant section
2. Update [API_REFERENCE.md](API_REFERENCE.md) - document new APIs
3. Add example to [EXAMPLES.md](EXAMPLES.md) - show usage
4. Update [QUICKREF.md](QUICKREF.md) - add quick reference
5. Add entry to [CHANGELOG.md](CHANGELOG.md) - note the change
6. Update this file (AI_PROMPT.md) if architecture changes

### Documentation Locations
- **For users**: Main `README.md` and `docs/`
- **For contributors**: `docs/CONTRIBUTING.md`
- **For security**: `docs/SECURITY.md`
- **For AI assistants**: `docs/AI_PROMPT.md` (this file)

## Troubleshooting

### "Module not found: jwt_verification"
**Cause**: Package not installed  
**Fix**: `pip install -e .` from project root

### "Key not found for kid: xyz123"
**Cause**: JWKS doesn't have that key ID  
**Fix**: 
- Check if token is from correct Auth0 tenant
- Verify issuer URL is correct
- Check Auth0 signing key rotation

### "Token has expired"
**Cause**: Token exp claim is in the past  
**Fix**: Get a new token from Auth0

### Tests failing with import errors
**Cause**: Test imports still using old path  
**Fix**: Ensure all test imports use `from jwt_verification import ...`

## Development Workflow

### Setup
```bash
git clone <repo>
cd flask-jwt-verification
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

### Before Committing
```bash
# Run tests
pytest

# Type check
mypy src/jwt_verification

# Lint
ruff check src/jwt_verification

# Format
ruff format src/jwt_verification
```

### Release Process
1. Update version in `pyproject.toml`
2. Update `CHANGELOG.md`
3. Run full test suite: `pytest`
4. Tag release: `git tag v1.x.x`
5. Build: `python -m build`
6. Publish: `twine upload dist/*`

## Environment Variables (for examples only)

The extension itself doesn't use environment variables. These are for the demo app in `examples/auth0_demo/`:

- `AUTH0_DOMAIN` - Your Auth0 tenant domain
- `AUTH0_CLIENT_ID` - OAuth application client ID
- `AUTH0_CLIENT_SECRET` - OAuth application secret
- `AUTH0_API_IDENTIFIER` - API identifier (audience)
- `SECRET_KEY` - Flask session secret
- `REDIS_URL` - Redis connection URL (optional)

## Quick Reference

### Minimal Setup
```python
from flask import Flask
from jwt_verification import AuthExtension, Auth0JWKSProvider, JWTVerifier, JWTVerifyOptions

app = Flask(__name__)
provider = Auth0JWKSProvider(issuer="https://tenant.auth0.com/")
verifier = JWTVerifier(
    key_provider=provider,
    options=JWTVerifyOptions(issuer="https://tenant.auth0.com/", audience="api-id")
)
auth = AuthExtension(verifier=verifier)

@app.route("/protected")
@auth.require()
def protected():
    return {"message": "Success"}
```

### With RBAC
```python
from jwt_verification import RBACAuthorizer, ClaimAccess, ClaimsMapping

authorizer = RBACAuthorizer(
    ClaimAccess(ClaimsMapping(roles_claim="roles", permissions_claim="permissions"))
)
auth = AuthExtension(verifier=verifier, authorizer=authorizer)

@app.route("/admin")
@auth.require(roles=["admin"])
def admin():
    return {"message": "Admin only"}
```

## Version Information

**Current Version:** 1.0.0  
**Python Requirement:** 3.14+  
**Flask Requirement:** 3.0+  
**Status:** Production Ready

## Contact & Support

- **Issues**: GitHub Issues
- **Documentation**: See `docs/` folder
- **Examples**: See `examples/auth0_demo/`

---

**Last Updated:** February 23, 2026  
**Maintained by:** Project Team  
**License:** MIT
