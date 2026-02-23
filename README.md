# Flask JWT Verification Extension

A production-ready Flask extension for JWT authentication and authorization with built-in Auth0 integration, RBAC, and intelligent caching.

[![Python 3.14+](https://img.shields.io/badge/python-3.14+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- **🔐 Secure JWT Verification** - Cryptographic signature validation with Auth0 JWKS
- **🛡️ Defense in Depth** - Multiple security layers protect against various attack vectors
- **👥 RBAC Support** - Role-based and permission-based access control
- **⚡ High Performance** - Multi-layer caching with Redis support
- **🚫 DoS Protection** - Rate-limiting for JWKS refresh operations and negative caching
- **🔌 Extensible** - Protocol-based design for easy customization
- **📝 Fully Typed** - Complete type hints for excellent IDE support
- **📚 Well Documented** - Comprehensive documentation and examples

## Quick Start

### Installation

```bash
pip install -e .
```

### Basic Usage

```python
from flask import Flask, g
from jwt_verification import (
    AuthExtension,
    Auth0JWKSProvider,
    JWTVerifier,
    JWTVerifyOptions,
)

app = Flask(__name__)

# Configure JWT verification
provider = Auth0JWKSProvider(issuer="https://your-tenant.auth0.com/")
verifier = JWTVerifier(
    key_provider=provider,
    options=JWTVerifyOptions(
        issuer="https://your-tenant.auth0.com/",
        audience="your-api-identifier",
    ),
)

# Create auth extension
auth = AuthExtension(verifier=verifier)

# Protect routes
@app.route("/api/protected")
@auth.require()
def protected():
    user_id = g.jwt["sub"]
    return {"message": f"Hello, {user_id}!"}

@app.route("/api/admin")
@auth.require(roles=["admin"])
def admin_only():
    return {"message": "Admin access granted"}

if __name__ == "__main__":
    app.run()
```

## Documentation

The extension includes comprehensive documentation:

- **[README](docs/README.md)** - Complete guide with architecture and usage
- **[Security Guide](docs/SECURITY.md)** - Security analysis and best practices
- **[API Reference](docs/API_REFERENCE.md)** - Complete API documentation
- **[Code Examples](docs/EXAMPLES.md)** - Working examples for common scenarios
- **[Quick Reference](docs/QUICKREF.md)** - Quick lookup reference
- **[Contributing](docs/CONTRIBUTING.md)** - Contribution guidelines
- **[AI Assistant Guide](docs/AI_PROMPT.md)** - Comprehensive context for AI assistants

### Documentation Index

Start here: **[Documentation Index](docs/INDEX.md)** - Navigation guide for all documentation

## Project Structure

```
flask-jwt-verification/
├── src/
│   └── jwt_verification/          # Main extension package
│       ├── __init__.py            # Public API exports
│       ├── flask_extension.py     # Flask integration
│       ├── verifier.py            # JWT verification
│       ├── authorization.py       # RBAC implementation
│       ├── errors.py              # Exception classes
│       ├── extractors.py          # Token extraction
│       ├── protocols.py           # Protocol definitions
│       ├── cache_stores.py        # Cache implementations
│       ├── refresh_gate.py        # Rate limiting
│       └── key_providers/         # Key provider implementations
│           ├── __init__.py
│           └── auth0.py           # Auth0 JWKS provider
├── docs/                          # Documentation
│   ├── README.md                  # Complete guide
│   ├── SECURITY.md                # Security analysis
│   ├── API_REFERENCE.md           # API documentation
│   ├── EXAMPLES.md                # Code examples
│   ├── QUICKREF.md                # Quick reference
│   ├── INDEX.md                   # Documentation index
│   ├── CONTRIBUTING.md            # Contribution guide
│   ├── CHANGELOG.md               # Version history
│   ├── DOCS_SUMMARY.md            # Documentation summary
│   └── AI_PROMPT.md               # AI assistant guide
├── examples/
│   └── auth0_demo/                # Complete Auth0 integration example
│       ├── app.py                 # Backend API setup
│       ├── login_provider.py      # OAuth login flow
│       ├── templates/             # HTML templates
│       ├── static/                # CSS and assets
│       ├── certs/                 # SSL certificates
│       ├── run.sh                 # Run script
│       └── README.md              # Demo setup guide
├── tests/
│   └── JWT_verification/          # Comprehensive test suite
├── pyproject.toml                 # Project configuration
└── README.md                      # This file
```

## Core Components

### AuthExtension
Flask decorator for protecting routes with JWT authentication and optional authorization.

### JWTVerifier
Provider-agnostic JWT signature and claims verification.

### Auth0JWKSProvider
Intelligent key provider with caching, negative caching, and DoS protection.

### RBACAuthorizer
Role-based and permission-based access control.

### Cache Stores
- **InMemoryCache** - For development and single-instance deployments
- **RedisCache** - For production multi-instance deployments

## Security Features

- ✅ **Signature Verification** - RSA signature validation with public keys
- ✅ **Claims Validation** - Issuer, audience, and expiration checks
- ✅ **Algorithm Confusion Prevention** - Explicit algorithm allowlist
- ✅ **Negative Caching** - Prevents repeated lookups for invalid keys
- ✅ **JWKS Refresh Throttling** - Rate-limits refresh operations
- ✅ **Thread Safety** - Safe for concurrent requests
- ✅ **Defense in Depth** - Multiple security layers

See [SECURITY.md](docs/SECURITY.md) for detailed security analysis.

## Examples

### With RBAC

```python
from jwt_verification import (
    RBACAuthorizer,
    ClaimAccess,
    ClaimsMapping,
)

# Configure claims mapping
mapping = ClaimsMapping(
    permissions_claim="permissions",
    roles_claim="roles",
)
authorizer = RBACAuthorizer(ClaimAccess(mapping))

# Create auth with authorization
auth = AuthExtension(verifier=verifier, authorizer=authorizer)

@app.route("/api/posts", methods=["POST"])
@auth.require(permissions=["write:posts"])
def create_post():
    return {"message": "Post created"}
```

### With Redis Cache (Production)

```python
import redis
from jwt_verification import RedisCache

redis_client = redis.Redis(
    host='localhost',
    port=6379,
    password=os.environ['REDIS_PASSWORD'],
    ssl=True,
    decode_responses=False,
)
cache = RedisCache(redis_client)

provider = Auth0JWKSProvider(
    issuer="https://your-tenant.auth0.com/",
    cache=cache,
    ttl_seconds=3600,
)
```

### Running the Demo

A complete Auth0 integration example is available:

```bash
# Setup environment
cp .env.example .env
# Edit .env with your Auth0 credentials

# Install dependencies
pip install -e ".[examples]"

# Run the demo
cd examples/auth0_demo
bash run.sh
```

See [examples/auth0_demo/README.md](examples/auth0_demo/README.md) for details.

## Testing

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run with coverage
pytest --cov=jwt_verification --cov-report=html

# Run linting
ruff check src/jwt_verification

# Run type checking
mypy src/jwt_verification
```

## Production Deployment

### Environment Configuration

```python
import os
from jwt_verification import (
    Auth0JWKSProvider,
    RedisCache,
    JWTVerifier,
    JWTVerifyOptions,
)

issuer = f"https://{os.environ['AUTH0_DOMAIN']}/"
audience = os.environ['AUTH0_API_IDENTIFIER']

redis_client = redis.from_url(os.environ['REDIS_URL'])
cache = RedisCache(redis_client)

provider = Auth0JWKSProvider(
    issuer=issuer,
    cache=cache,
    ttl_seconds=3600,
)

verifier = JWTVerifier(
    key_provider=provider,
    options=JWTVerifyOptions(issuer=issuer, audience=audience),
)
```

### Production Checklist

- [ ] Use Redis for caching (not InMemoryCache)
- [ ] Set appropriate TTLs (3600s for keys, 30-60s for negative cache)
- [ ] Enable Redis AUTH and/or TLS
- [ ] Use HTTPS exclusively
- [ ] Configure rate limiting at API gateway
- [ ] Set up monitoring and alerting
- [ ] Review Auth0 tenant security settings
- [ ] Test key rotation procedures

See [README.md - Deployment](docs/README.md#deployment) for complete guide.

## Requirements

- Python 3.14+
- Flask 3.0+
- PyJWT 2.8+ (with cryptography)

### Optional Dependencies

- Redis 5.0+ (for production caching)
- Auth0 account (for examples)

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](docs/CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
# Clone repository
git clone https://github.com/yourusername/flask-jwt-verification.git
cd flask-jwt-verification

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install in development mode
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install

# Run tests
pytest
```

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Security

For security issues, please see [SECURITY.md](docs/SECURITY.md) for reporting guidelines.

**Do not report security issues publicly via GitHub issues.**

## Changelog

See [CHANGELOG.md](docs/CHANGELOG.md) for version history.

## Support

- **Documentation:** [Documentation Index](docs/INDEX.md)
- **Issues:** [GitHub Issues](https://github.com/yourusername/flask-jwt-verification/issues)
- **Discussions:** [GitHub Discussions](https://github.com/yourusername/flask-jwt-verification/discussions)

## Acknowledgments

- Auth0 for excellent JWT documentation
- PyJWT library for JWT verification
- Flask framework for web application support

---

**Version:** 1.0.0  
**Status:** Production Ready  
**Python:** 3.14+  
**License:** MIT
