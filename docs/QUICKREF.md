# JWT Verification Extension - Quick Reference

## Installation

```bash
pip install -e .
```

## Basic Setup

```python
from jwt_verification import (
    AuthExtension,
    Auth0JWKSProvider,
    JWTVerifier,
    JWTVerifyOptions,
)

# Configure
provider = Auth0JWKSProvider(issuer="https://tenant.auth0.com/")
verifier = JWTVerifier(
    key_provider=provider,
    options=JWTVerifyOptions(
        issuer="https://tenant.auth0.com/",
        audience="your-api-id",
    ),
)
auth = AuthExtension(verifier=verifier)

# Use
@app.route("/protected")
@auth.require()
def protected():
    return {"user": g.jwt["sub"]}
```

## Common Decorators

```python
# Require authentication only
@auth.require()

# Require specific role
@auth.require(roles=["admin"])

# Require multiple roles (any)
@auth.require(roles=["admin", "moderator"])

# Require permission
@auth.require(permissions=["write:posts"])

# Require all permissions
@auth.require(
    permissions=["read:posts", "write:posts"],
    require_all_permissions=True
)

# Require any permission
@auth.require(
    permissions=["read:posts", "read:comments"],
    require_all_permissions=False
)

# Combined role and permissions
@auth.require(
    roles=["editor"],
    permissions=["write:posts"],
    require_all_permissions=True
)
```

## Accessing Claims

```python
from flask import g

@app.route("/profile")
@auth.require()
def profile():
    user_id = g.jwt["sub"]
    email = g.jwt.get("email")
    perms = g.jwt.get("permissions", [])
    return {"user_id": user_id, "email": email}
```

## Error Handling

```python
from jwt_verification import (
    MissingToken,
    ExpiredToken,
    InvalidToken,
    Forbidden,
)

@app.errorhandler(401)
def unauthorized(e):
    return {"error": "Unauthorized"}, 401

@app.errorhandler(403)
def forbidden(e):
    return {"error": "Forbidden"}, 403
```

## RBAC Setup

```python
from jwt_verification import (
    RBACAuthorizer,
    ClaimAccess,
    ClaimsMapping,
)

mapping = ClaimsMapping(
    permissions_claim="permissions",
    roles_claim="roles",
)
authorizer = RBACAuthorizer(ClaimAccess(mapping))
auth = AuthExtension(verifier=verifier, authorizer=authorizer)
```

## Production Cache (Redis)

```python
import redis
from jwt_verification import RedisCache

redis_client = redis.Redis(host='localhost', decode_responses=False)
cache = RedisCache(redis_client)

provider = Auth0JWKSProvider(
    issuer="https://tenant.auth0.com/",
    cache=cache,
    ttl_seconds=3600,
)
```

## Cookie Authentication

```python
from jwt_verification import CookieExtractor

auth = AuthExtension(
    verifier=verifier,
    extractor=CookieExtractor("access_token"),
)
```

## Environment Configuration

```python
import os

issuer = f"https://{os.environ['AUTH0_DOMAIN']}/"
audience = os.environ['AUTH0_API_IDENTIFIER']

provider = Auth0JWKSProvider(issuer=issuer)
verifier = JWTVerifier(
    key_provider=provider,
    options=JWTVerifyOptions(issuer=issuer, audience=audience),
)
```

## Common Patterns

### Optional Authentication
```python
def optional_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            token = auth._extractor.extract()
            g.jwt = auth._verifier.verify(token)
            g.authenticated = True
        except:
            g.authenticated = False
        return f(*args, **kwargs)
    return decorated

@app.route("/content")
@optional_auth
def content():
    if g.get("authenticated"):
        return {"msg": f"Hello {g.jwt['name']}"}
    return {"msg": "Hello guest"}
```

### Resource Ownership Check
```python
@app.route("/posts/<id>", methods=["PUT"])
@auth.require(permissions=["write:posts"])
def edit_post(id):
    post = get_post(id)
    if post.author_id != g.jwt["sub"]:
        if "admin" not in g.jwt.get("roles", []):
            abort(403)
    update_post(id, request.json)
    return {"msg": "Updated"}
```

## Testing

```python
import pytest

@pytest.fixture
def client(app):
    return app.test_client()

def test_protected_route(client):
    # No token
    assert client.get("/protected").status_code == 401
    
    # Valid token
    headers = {"Authorization": f"Bearer {token}"}
    resp = client.get("/protected", headers=headers)
    assert resp.status_code == 200
```

## Debugging

```bash
# Check token contents (without verification)
python -c "
import jwt
token = 'your.jwt.token'
print(jwt.decode(token, options={'verify_signature': False}))
"

# Test JWKS endpoint
curl https://your-tenant.auth0.com/.well-known/jwks.json
```

## Key Classes

| Class | Purpose |
|-------|---------|
| `AuthExtension` | Flask decorator for routes |
| `JWTVerifier` | Verify JWT signatures |
| `Auth0JWKSProvider` | Fetch keys from Auth0 |
| `RBACAuthorizer` | Role/permission checks |
| `InMemoryCache` | Dev cache |
| `RedisCache` | Prod cache |
| `BearerExtractor` | Extract from header |
| `CookieExtractor` | Extract from cookie |

## Key Errors

| Error | Status | Meaning |
|-------|--------|---------|
| `MissingToken` | 401 | No token in request |
| `InvalidToken` | 401 | Bad signature/claims |
| `ExpiredToken` | 401 | Token expired |
| `Forbidden` | 403 | Insufficient permissions |

## Configuration Options

### JWTVerifyOptions
```python
JWTVerifyOptions(
    issuer="https://tenant.auth0.com/",  # Required
    audience="your-api-id",               # Required
    algorithms=("RS256",),                 # Default: RS256
)
```

### Auth0JWKSProvider
```python
Auth0JWKSProvider(
    issuer="...",              # Required
    cache=cache,               # Default: InMemoryCache
    ttl_seconds=600,           # Default: 600 (10 min)
    missing_ttl_seconds=30,    # Default: 30
    min_interval=60.0,         # Default: 60 (1 min)
    alert_threshold=40,        # Default: 40
)
```

### ClaimsMapping
```python
ClaimsMapping(
    permissions_claim="permissions",  # Default
    roles_claim="roles",              # Default
    single_role_claim=None,           # Optional
)
```

## Security Checklist

- [ ] Use HTTPS only
- [ ] Set issuer and audience
- [ ] Use Redis in production
- [ ] Enable Redis AUTH
- [ ] Short token lifetimes (15-60 min)
- [ ] Never log tokens
- [ ] Rate limit at API gateway
- [ ] Monitor 401/403 errors
- [ ] Test key rotation

## Documentation Links

- **Full Documentation:** [README.md](./README.md)
- **Security Guide:** [SECURITY.md](./SECURITY.md)
- **Code Examples:** [EXAMPLES.md](./EXAMPLES.md)
- **API Reference:** [API_REFERENCE.md](./API_REFERENCE.md)
- **Documentation Index:** [INDEX.md](./INDEX.md)

## Support

- **Issues:** GitHub Issues
- **Security:** Email security contact (see README)
- **Questions:** GitHub Discussions

---

**Version:** 1.0.0  
**Last Updated:** February 23, 2026
