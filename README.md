# Flask JWT Authorization Extension

A production‑style Flask extension for JWT authentication and authorization with JWKS verification, RBAC support, and defensive caching.

Maintained by: Shayman McGee

---

## ✨ Features

- JWT signature and claims verification
- Auth0 JWKS integration with caching
- Role‑based and permission‑based authorization (RBAC)
- Flask decorator for route protection
- Bearer token and cookie extraction
- Redis or in‑memory caching
- Defensive protections against DoS and key‑rotation abuse
- Protocol‑based architecture for customization

---

## 🎯 Why This Exists

Most Flask JWT examples are minimal and tightly coupled to a specific provider.

This extension demonstrates a production‑style approach:

- Stateless verification using public keys
- Separation of authentication and authorization logic
- Extensible architecture using dependency injection
- Defensive caching and security controls

---

## 🚀 Quick Start

```python
from jwt_verification import (
    AuthExtension,
    Auth0JWKSProvider,
    JWTVerifier,
    JWTVerifyOptions,
)

provider = Auth0JWKSProvider(
    issuer="https://tenant.auth0.com/"
)

verifier = JWTVerifier(
    key_provider=provider,
    options=JWTVerifyOptions(
        issuer="https://tenant.auth0.com/",
        audience="your-api-id",
    ),
)

auth = AuthExtension(verifier=verifier)
```

Protect routes:

```python
@app.route("/protected")
@auth.require()
def protected():
    return {"user": g.jwt["sub"]}
```

---

## 🔐 Authorization Examples

Require role:

```python
@auth.require(roles=["admin"])
```

Require permissions:

```python
@auth.require(permissions=["write:posts"])
```

Require multiple permissions:

```python
@auth.require(
    permissions=["read:posts", "write:posts"],
    require_all_permissions=True
)
```

---

## ⚙️ Configuration

```python
issuer = f"https://{os.environ['AUTH0_DOMAIN']}/"
audience = os.environ["AUTH0_API_IDENTIFIER"]
```

---

## 🧠 Architecture Overview

Core components:

- AuthExtension — Flask decorator interface
- JWTVerifier — Token validation logic
- KeyProvider — JWKS key retrieval
- Authorizer — RBAC enforcement
- Extractor — Token extraction source
- CacheStore — Key caching layer

---

## 🧪 Accessing Claims

```python
from flask import g

user_id = g.jwt["sub"]
permissions = g.jwt.get("permissions", [])
```

---

## ❗ Error Handling

Exceptions map to HTTP responses automatically:

- MissingToken → 401
- InvalidToken → 401
- ExpiredToken → 401
- Forbidden → 403

---

## 🔐 Security Highlights

- Cryptographic signature verification
- Issuer and audience validation
- Algorithm allow‑listing
- JWKS caching with negative cache
- Refresh throttling to prevent abuse
- Thread‑safe operations

See SECURITY.md for details.

---

## 📚 Documentation

- [API_REFERENCE.md](API_REFERENCE.md) — Full API reference
- [SECURITY.md](SECURITY.md) — Security considerations
- [AI_PROMPT.md](AI_PROMPT.md) — Architecture explanation for AI tools

---

## 🗺️ Roadmap

- Async support
- Metrics hooks
- WebSocket auth
- Distributed refresh coordination

---

## 📄 License

MIT

