# JWT Verification Extension

A production-ready Flask extension for JWT authentication and authorization with Auth0 integration.

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Core Components](#core-components)
4. [Security Features](#security-features)
5. [Quick Start](#quick-start)
6. [Detailed Usage](#detailed-usage)
7. [API Reference](#api-reference)
8. [Testing](#testing)
9. [Deployment](#deployment)
10. [Troubleshooting](#troubleshooting)
11. [Advanced Topics](#advanced-topics)

---

## Overview

This JWT verification extension provides a secure, flexible, and production-ready solution for authenticating and authorizing Flask APIs using JSON Web Tokens (JWTs). It is designed with Auth0 in mind but supports any JWT provider that follows standard specifications.

### Key Features

- **Signature Verification**: Validates JWT signatures using JWKS (JSON Web Key Set)
- **Claims Validation**: Enforces issuer, audience, and expiration checks
- **Role-Based Access Control (RBAC)**: Flexible role and permission enforcement
- **Performance Optimization**: Multi-layer caching with TTL support
- **DoS Protection**: Rate-limiting for JWKS refresh operations
- **Negative Caching**: Prevents repeated lookups for invalid key IDs
- **Extensible Design**: Protocol-based architecture for easy customization
- **Type Safety**: Fully typed with Python type hints

### Architecture Philosophy

The extension follows several key design principles:

1. **Separation of Concerns**: Each component has a single, well-defined responsibility
2. **Protocol-Based Design**: Uses Python protocols (structural typing) for flexibility
3. **Defense in Depth**: Multiple security layers protect against various attack vectors
4. **Fail-Safe Defaults**: Secure by default, with explicit opt-in for relaxed security
5. **Observable**: Designed for monitoring and alerting in production environments

---

## Architecture

### High-Level Request Flow

```text
┌─────────────────────────────────────────────────────────────────┐
│ 1. HTTP Request                                                 │
│    Authorization: Bearer <JWT>                                  │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│ 2. AuthExtension.require() Decorator                            │
│    - Route protection                                           │
│    - Error handling & HTTP status mapping                       │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│ 3. Extractor (BearerExtractor / CookieExtractor)                │
│    - Extract raw JWT string from request                        │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│ 4. JWTVerifier                                                  │
│    - Parse unverified header to get kid                         │
│    - Request signing key from KeyProvider                       │
│    - Verify signature + claims                                  │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│ 5. KeyProvider (Auth0JWKSProvider)                              │
│    ┌────────────────────────────────────────┐                   │
│    │ Cache Lookup (fast path)               │                   │
│    └─────────┬──────────────────────────────┘                   │
│              │ Cache miss                                       │
│              ▼                                                  │
│    ┌────────────────────────────────────────┐                   │
│    │ JWKS Fetch (PyJWKClient)               │                   │
│    └─────────┬──────────────────────────────┘                   │
│              │ Still not found                                  │
│              ▼                                                  │
│    ┌────────────────────────────────────────┐                   │
│    │ RefreshGate (rate-limited)             │                   │
│    │ - Force JWKS refresh                   │                   │
│    └────────────────────────────────────────┘                   │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│ 6. Authorizer (RBACAuthorizer) [Optional]                       │
│    - Extract roles/permissions from claims                      │
│    - Enforce access control rules                               │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│ 7. Success                                                      │
│    - Claims stored in flask.g.jwt                               │
│    - Route handler executes                                     │
└─────────────────────────────────────────────────────────────────┘
```

### Component Diagram

```text
┌──────────────────────────────────────────────────────────────────┐
│                        Flask Application                         │
└───────────────────────────┬──────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│                       AuthExtension                              │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐      │
│  │   Extractor    │  │ TokenVerifier  │  │  Authorizer    │      │
│  │  (Protocol)    │  │   (Protocol)   │  │  (Protocol)    │      │
│  └────────────────┘  └────────────────┘  └────────────────┘      │
└──────────────────────────────────────────────────────────────────┘
         │                     │                     │
         │                     │                     │
         ▼                     ▼                     ▼
┌─────────────────┐    ┌─────────────────┐    ┌──────────────┐
│ BearerExtractor │    │   JWTVerifier   │    │RBACAuthorizer│
│ CookieExtractor │    │                 │    │              │
└─────────────────┘    └───────┬─────────┘    └──────┬───────┘
                               │                     │
                               ▼                     ▼
                     ┌──────────────────┐    ┌──────────────┐
                     │   KeyProvider    │    │ ClaimAccess  │
                     │   (Protocol)     │    │              │
                     └─────────┬────────┘    └──────────────┘
                               │
                               ▼
                     ┌──────────────────┐
                     │Auth0JWKSProvider │
                     │  ┌───────────┐   │
                     │  │CacheStore │   │
                     │  │RefreshGate│   │
                     │  └───────────┘   │
                     └──────────────────┘
                               │
                               ▼
                     ┌──────────────────┐
                     │ InMemoryCache    │
                     │ RedisCache       │
                     └──────────────────┘
```

---

## Core Components

### 1. AuthExtension

**Purpose**: Flask integration layer that orchestrates authentication and authorization.

**Responsibilities**:

- Apply JWT verification to Flask routes via decorators
- Extract tokens from requests
- Coordinate verification and authorization
- Convert domain errors to HTTP responses
- Store verified claims in `flask.g.jwt`

**Key Methods**:

- `require(permissions=..., roles=..., require_all_permissions=True)`: Decorator factory for protecting routes
- `init_app(app, ...)`: Flask application factory pattern support

**Example**:

```python
from jwt_verification import AuthExtension

auth = AuthExtension(verifier=jwt_verifier, authorizer=authorizer)

@app.route("/admin")
@auth.require(roles=["admin"])
def admin_endpoint():
    # flask.g.jwt contains verified claims
    user_id = flask.g.jwt.get("sub")
    return {"message": f"Welcome, admin {user_id}"}
```

---

### 2. JWTVerifier

**Purpose**: Provider-agnostic JWT signature and claims verification.

**Responsibilities**:

- Parse JWT header to extract `kid` (key ID)
- Obtain signing key from KeyProvider
- Verify signature using PyJWT
- Validate standard claims (issuer, audience, expiration)

**Configuration**:

```python
from jwt_verification import JWTVerifier, JWTVerifyOptions

options = JWTVerifyOptions(
    issuer="https://your-tenant.auth0.com/",
    audience="your-api-identifier",
    algorithms=("RS256",)  # Explicit allowlist
)

verifier = JWTVerifier(key_provider=key_provider, options=options)
```

**Security Notes**:

- Never trusts the `alg` field from the token header (prevents algorithm confusion attacks)
- Validates `iss` and `aud` to ensure tokens are intended for your API
- Converts all JWT library exceptions to domain-specific errors

---

### 3. Auth0JWKSProvider

**Purpose**: Resolve JWT signing keys from Auth0's JWKS endpoint with intelligent caching and DoS protection.

**Responsibilities**:

- Fetch and cache signing keys from Auth0
- Implement negative caching for unknown key IDs
- Rate-limit JWKS refresh operations
- Provide clean abstraction over PyJWKClient

**Resolution Strategy**:

1. **Cache Lookup** (O(1), fast path)
   - Return cached key if available and not expired

2. **Normal Resolution**
   - Fetch key using PyJWKClient
   - PyJWKClient may internally refresh JWKS if key is missing
   - Cache successful result

3. **Negative Caching**
   - If key not found, cache `kid` as "missing" for short TTL (default: 30s)
   - Subsequent requests for same invalid `kid` fail instantly

4. **Forced Refresh** (rate-limited)
   - If RefreshGate allows: force JWKS fetch and retry once
   - If throttled: fail immediately to prevent DoS
   - Cache result (positive or negative)

**Configuration**:

```python
from jwt_verification import Auth0JWKSProvider, InMemoryCache

provider = Auth0JWKSProvider(
    issuer="https://your-tenant.auth0.com/",
    cache=InMemoryCache(),
    ttl_seconds=600,              # Valid key cache TTL
    missing_ttl_seconds=30,       # Invalid key cache TTL
    min_interval=60.0,            # Min seconds between forced refreshes
    alert_threshold=40,           # Denied refresh attempts before alert
)
```

**Attack Mitigation**:

- **Random `kid` Spam**: Negative caching makes repeated invalid requests O(1)
- **Refresh Amplification**: RefreshGate limits outbound JWKS fetches
- **Cache Bypass**: All resolution paths enforce caching

---

### 4. RBACAuthorizer

**Purpose**: Enforce role-based and permission-based access control.

**Responsibilities**:

- Extract roles and permissions from JWT claims
- Validate user has required roles
- Validate user has required permissions (all or any)
- Raise `Forbidden` error on authorization failure

**Configuration**:

```python
from jwt_verification import (
    RBACAuthorizer,
    ClaimAccess,
    ClaimsMapping,
)

# Configure where roles/permissions live in JWT
mapping = ClaimsMapping(
    permissions_claim="permissions",
    roles_claim="https://your-app.com/roles",  # Custom namespace
    single_role_claim=None,  # Optional: claim with single role string
)

claims_access = ClaimAccess(mapping=mapping)
authorizer = RBACAuthorizer(claims_access)
```

**Authorization Logic**:

- **Roles**: User must have at least ONE of the required roles
- **Permissions**:
  - If `require_all_permissions=True`: User must have ALL required permissions
  - If `require_all_permissions=False`: User must have at least ONE required permission

**Example**:

```python
# User must be admin OR moderator AND have both permissions
@auth.require(
    roles=["admin", "moderator"],
    permissions=["read:posts", "write:posts"],
    require_all_permissions=True
)
def edit_post():
    pass
```

---

### 5. Cache Stores

#### InMemoryCache

**Purpose**: Simple in-process cache for development and single-instance deployments.

**Features**:

- Thread-safe with locking
- TTL-based expiration
- Supports negative caching
- Lazy expiration (on access)

**Limitations**:

- Not shared across processes/containers
- Lost on application restart
- Not suitable for horizontal scaling

**Use Cases**:

- Local development
- Single-server deployments
- Testing

#### RedisCache

**Purpose**: Distributed cache for production multi-instance deployments.

**Features**:

- Shared across all application instances
- Leverages Redis TTL for automatic expiration
- Supports negative caching
- Persistent across restarts

**Configuration**:

```python
import redis
from jwt_verification import RedisCache

redis_client = redis.Redis(
    host='localhost',
    port=6379,
    db=0,
    decode_responses=False  # Important: work with bytes
)

cache = RedisCache(redis_client)
```

**Serialization**:

- Stores PyJWK objects as JSON
- Uses `kid` as Redis key
- Negative cache entries stored with `{"__missing__": True}`

---

### 6. Token Extractors

#### BearerExtractor

**Purpose**: Extract JWT from `Authorization` header.

**Expected Format**:

```text
Authorization: Bearer <JWT>
```

**Behavior**:

- Raises `MissingToken` if header is missing or malformed
- Strips whitespace from token

#### CookieExtractor

**Purpose**: Extract JWT from HTTP cookie.

**Configuration**:

```python
from jwt_verification import CookieExtractor

extractor = CookieExtractor(cookie_name="access_token")
auth = AuthExtension(verifier=verifier, extractor=extractor)
```

**Use Cases**:

- Single-page applications (SPAs) with same-site APIs
- Scenarios where localStorage is undesirable
- CSRF protection required (use with SameSite cookies)

---

### 7. RefreshGate

**Purpose**: Rate-limit JWKS refresh operations to prevent DoS attacks.

**Mechanism**:

- Allows at most one refresh per `min_interval` seconds
- Thread-safe with locking
- Tracks denied attempts
- Optional alerting at threshold

**Configuration**:

```python
from jwt_verification import RefreshGate

gate = RefreshGate(
    min_interval=60.0,      # 1 refresh per minute max
    alert_threshold=40,     # Alert after 40 denied attempts
)
```

**Security Rationale**:

An attacker sending JWTs with random `kid` values could force your service to repeatedly fetch JWKS from Auth0, causing:

- Outbound request amplification
- Auth0 rate-limiting
- Service degradation

RefreshGate ensures forced refreshes happen at a controlled rate.

---

## Security Features

### 1. Signature Verification

**What**: Validates JWT signature using public keys from JWKS endpoint.
**Prevents**: Token forgery, tampering
**Implementation**: PyJWT with explicit algorithm allowlist

### 2. Claims Validation

**What**: Enforces issuer, audience, and expiration checks.

**Prevents**:

- Token reuse across services (audience)
- Accepting tokens from untrusted issuers
- Use of expired tokens

**Configuration**:

```python
JWTVerifyOptions(
    issuer="https://your-tenant.auth0.com/",  # MUST match token
    audience="your-api-identifier",           # MUST match token
    algorithms=("RS256",)                     # Only RSA, no HS256
)
```

### 3. Algorithm Confusion Prevention

**What**: Explicitly specifies allowed signature algorithms.
**Prevents**: Attackers switching from RS256 to HS256 to bypass verification
**Implementation**: Never trusts `alg` header; uses configured allowlist

### 4. Negative Caching

**What**: Caches unknown `kid` values as "missing" for short TTL.
**Prevents**: Repeated expensive JWKS lookups for invalid keys
**Implementation**: Auth0JWKSProvider with `missing_ttl_seconds`

### 5. JWKS Refresh Throttling

**What**: Rate-limits forced JWKS refresh operations.
**Prevents**: DoS via refresh amplification
**Implementation**: RefreshGate with `min_interval`

### 6. Defense in Depth

Multiple layers of protection:

1. **Extractor**: Validates token format
2. **Verifier**: Validates signature and claims
3. **Authorizer**: Validates roles and permissions
4. **Cache**: Prevents repeated cryptographic operations
5. **RefreshGate**: Prevents outbound request amplification

### 7. Secure Defaults

The extension is secure by default:

- Requires explicit issuer and audience
- Uses strong algorithms (RS256)
- Enables all claim validations
- Short TTL for negative cache
- Conservative refresh throttling

---

## Quick Start

### Basic Setup

```python
from flask import Flask
from jwt_verification import (
    AuthExtension,
    Auth0JWKSProvider,
    InMemoryCache,
    JWTVerifier,
    JWTVerifyOptions,
)

app = Flask(__name__)

# 1. Configure cache
cache = InMemoryCache()

# 2. Configure key provider
key_provider = Auth0JWKSProvider(
    issuer="https://your-tenant.auth0.com/",
    cache=cache,
)

# 3. Configure verifier
verifier = JWTVerifier(
    key_provider=key_provider,
    options=JWTVerifyOptions(
        issuer="https://your-tenant.auth0.com/",
        audience="your-api-identifier",
    ),
)

# 4. Create auth extension
auth = AuthExtension(verifier=verifier)

# 5. Protect routes
@app.route("/public")
def public():
    return {"message": "Public endpoint"}

@app.route("/protected")
@auth.require()
def protected():
    return {"message": "Authenticated endpoint"}

if __name__ == "__main__":
    app.run()
```

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

# Create authorizer
claims_access = ClaimAccess(mapping=mapping)
authorizer = RBACAuthorizer(claims_access)

# Create auth extension with authorization
auth = AuthExtension(verifier=verifier, authorizer=authorizer)

@app.route("/admin")
@auth.require(roles=["admin"])
def admin_only():
    return {"message": "Admin access"}

@app.route("/posts", methods=["POST"])
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
    db=0,
    decode_responses=False,
)

cache = RedisCache(redis_client)

key_provider = Auth0JWKSProvider(
    issuer="https://your-tenant.auth0.com/",
    cache=cache,
    ttl_seconds=3600,
)

# Continue with verifier and auth setup...
```

---

## Detailed Usage

### Accessing Verified Claims

After successful verification, claims are stored in `flask.g.jwt`:

```python
from flask import g

@app.route("/profile")
@auth.require()
def profile():
    user_id = g.jwt.get("sub")
    email = g.jwt.get("email")
    permissions = g.jwt.get("permissions", [])
    
    return {
        "user_id": user_id,
        "email": email,
        "permissions": permissions,
    }
```

### Cookie-Based Authentication

For SPAs served from the same domain:

```python
from jwt_verification import CookieExtractor

cookie_extractor = CookieExtractor(cookie_name="access_token")
auth = AuthExtension(
    verifier=verifier,
    authorizer=authorizer,
    extractor=cookie_extractor,
)

@app.route("/api/data")
@auth.require()
def get_data():
    # Token extracted from cookie
    return {"data": "sensitive information"}
```

### ID Token Verification

For verifying ID tokens (typically from cookies after OAuth login):

```python
from jwt_verification import get_verified_id_claims

@app.route("/user-info")
def user_info():
    try:
        claims = get_verified_id_claims(
            verifier=id_token_verifier,
            cookie_name="id_token",
        )
        return {
            "name": claims.get("name"),
            "email": claims.get("email"),
            "picture": claims.get("picture"),
        }
    except MissingToken:
        return {"error": "Not logged in"}, 401
    except (ExpiredToken, InvalidToken) as e:
        return {"error": str(e)}, 401
```

### Custom Claims Mapping

For Auth0 with custom namespaced claims:

```python
mapping = ClaimsMapping(
    permissions_claim="permissions",
    roles_claim="https://myapp.com/roles",
    single_role_claim="https://myapp.com/primary_role",
)

claims_access = ClaimAccess(mapping=mapping)
authorizer = RBACAuthorizer(claims_access)
```

### Flexible Permission Checks

```python
# Require ALL permissions
@auth.require(
    permissions=["read:users", "write:users"],
    require_all_permissions=True
)
def manage_users():
    pass

# Require ANY permission (at least one)
@auth.require(
    permissions=["read:posts", "read:comments"],
    require_all_permissions=False
)
def read_content():
    pass
```

### Multiple Role/Permission Requirements

```python
# Must be admin OR moderator
@auth.require(roles=["admin", "moderator"])
def moderate_content():
    pass

# Must be admin AND have both permissions
@auth.require(
    roles=["admin"],
    permissions=["read:all", "write:all"],
    require_all_permissions=True
)
def full_admin_access():
    pass
```

### Error Handling

The extension converts domain errors to HTTP responses automatically:

- `MissingToken` → 401 Unauthorized
- `ExpiredToken` → 401 Unauthorized
- `InvalidToken` → 401 Unauthorized
- `Forbidden` → 403 Forbidden

Custom error handlers can be added:

```python
from jwt_verification import InvalidToken

@app.errorhandler(401)
def handle_unauthorized(e):
    return {
        "error": "unauthorized",
        "message": str(e.description),
    }, 401

@app.errorhandler(403)
def handle_forbidden(e):
    return {
        "error": "forbidden",
        "message": "Insufficient permissions",
    }, 403
```

### Application Factory Pattern

```python
def create_app(config=None):
    app = Flask(__name__)
    
    # Configure components
    cache = RedisCache(redis_client)
    key_provider = Auth0JWKSProvider(issuer=..., cache=cache)
    verifier = JWTVerifier(key_provider=key_provider, options=...)
    authorizer = RBACAuthorizer(...)
    
    # Create extension
    auth = AuthExtension(verifier=verifier, authorizer=authorizer)
    
    # Register with app
    auth.init_app(app)
    
    # Access later via app.extensions
    # auth = app.extensions["auth_extension"]
    
    return app
```

---

## API Reference

### AuthExtension

```python
class AuthExtension:
    def __init__(
        self,
        verifier: TokenVerifier,
        authorizer: Authorizer | None = None,
        extractor: Extractor | None = None,
    ) -> None:
        """
        Initialize the auth extension.
        
        Args:
            verifier: Token verification implementation
            authorizer: Optional authorization implementation
            extractor: Token extraction implementation (default: BearerExtractor)
        """

    def init_app(
        self,
        app: Flask,
        *,
        verifier: TokenVerifier | None = None,
        authorizer: Authorizer | None = None,
        extractor: Extractor | None = None,
    ) -> None:
        """
        Initialize with Flask app (application factory pattern).
        
        Args:
            app: Flask application instance
            verifier: Override verifier
            authorizer: Override authorizer
            extractor: Override extractor
        """

    def require(
        self,
        *,
        permissions: Sequence[str] = (),
        roles: Sequence[str] = (),
        require_all_permissions: bool = True,
    ):
        """
        Decorator factory for route protection.
        
        Args:
            permissions: Required permissions
            roles: Required roles (user must have at least one)
            require_all_permissions: If True, user must have all permissions;
                                    if False, user needs at least one
        
        Returns:
            Decorator function for Flask routes
        
        Raises:
            401: If token is missing, expired, or invalid
            403: If authorization fails
        """
```

### JWTVerifier

```python
@dataclass(frozen=True, slots=True)
class JWTVerifyOptions:
    """JWT verification configuration."""
    issuer: Optional[str]
    audience: Optional[str]
    algorithms: tuple[str, ...] = ("RS256",)

class JWTVerifier(TokenVerifier):
    def __init__(
        self,
        key_provider: KeyProvider,
        options: JWTVerifyOptions,
    ) -> None:
        """
        Initialize JWT verifier.
        
        Args:
            key_provider: Signing key provider
            options: Verification options (issuer, audience, algorithms)
        """

    def verify(self, token: str) -> Claims:
        """
        Verify JWT and return claims.
        
        Args:
            token: Raw JWT string
        
        Returns:
            Decoded claims dictionary
        
        Raises:
            InvalidToken: If signature invalid or claims validation fails
            ExpiredToken: If token is expired
        """
```

### Auth0JWKSProvider

```python
class Auth0JWKSProvider(KeyProvider):
    def __init__(
        self,
        issuer: str,
        cache: CacheStore | None = None,
        ttl_seconds: int = 600,
        missing_ttl_seconds: int = 30,
        min_interval: float = 60.0,
        alert_threshold: int = 40,
    ) -> None:
        """
        Initialize Auth0 JWKS provider.
        
        Args:
            issuer: Auth0 issuer URL (e.g., "https://tenant.auth0.com/")
            cache: Cache implementation (default: InMemoryCache)
            ttl_seconds: Cache TTL for valid keys
            missing_ttl_seconds: Cache TTL for unknown kids
            min_interval: Minimum seconds between forced JWKS refreshes
            alert_threshold: Denied refresh attempts before alerting
        """

    def get_key_for_token(self, kid: str) -> PyJWK:
        """
        Resolve signing key for given key ID.
        
        Args:
            kid: Key ID from JWT header
        
        Returns:
            PyJWK verification key
        
        Raises:
            InvalidToken: If key cannot be resolved
        """
```

### RBACAuthorizer

```python
@dataclass(frozen=True, slots=True)
class ClaimsMapping:
    """Maps where roles/permissions live in JWT claims."""
    permissions_claim: str = "permissions"
    roles_claim: str = "roles"
    single_role_claim: Optional[str] = None

class ClaimAccess:
    def __init__(self, mapping: ClaimsMapping) -> None:
        """Initialize with claims mapping configuration."""

    def permissions(self, claims: Claims) -> FrozenSet[str]:
        """Extract permissions from claims."""

    def roles(self, claims: Claims) -> FrozenSet[str]:
        """Extract roles from claims."""

class RBACAuthorizer(Authorizer):
    def __init__(self, claims: ClaimAccess) -> None:
        """Initialize with claims accessor."""

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
            require_all_permissions: Permission requirement mode
        
        Raises:
            Forbidden: If authorization fails
        """
```

### Cache Stores

```python
class InMemoryCache:
    def get(self, kid: str) -> Optional[PyJWK]:
        """Get cached key by kid."""

    def set(self, key: PyJWK, ttl_seconds: int) -> None:
        """Cache a signing key."""

    def set_missing(self, kid: str, ttl_seconds: int) -> None:
        """Cache a known-missing kid."""

    def is_missing(self, kid: str) -> bool:
        """Check if kid is cached as missing."""

class RedisCache:
    def __init__(self, redis_client: Any) -> None:
        """Initialize with Redis client."""

    def get(self, kid: str) -> Optional[PyJWK]:
        """Get cached key from Redis."""

    def set(self, key: PyJWK, ttl_seconds: int) -> None:
        """Cache key in Redis with TTL."""

    def set_missing(self, kid: str, ttl_seconds: int) -> None:
        """Cache known-missing kid in Redis."""

    def is_missing(self, kid: str) -> bool:
        """Check if kid is cached as missing in Redis."""
```

### Extractors

```python
class BearerExtractor(Extractor):
    def extract(self) -> str:
        """
        Extract JWT from Authorization header.
        
        Expected: Authorization: Bearer <token>
        
        Raises:
            MissingToken: If header is missing or malformed
        """

class CookieExtractor(Extractor):
    def __init__(self, cookie_name: str = "access_token") -> None:
        """Initialize with cookie name."""

    def extract(self) -> str:
        """
        Extract JWT from cookie.
        
        Raises:
            MissingToken: If cookie is missing
        """
```

### Utility Functions

```python
def get_verified_id_claims(
    verifier: TokenVerifier,
    *,
    cookie_name: str = "id_token",
) -> Claims:
    """
    Verify ID token from cookie and return claims.
    
    Args:
        verifier: Token verifier configured for ID tokens
        cookie_name: Name of cookie containing ID token
    
    Returns:
        Verified claims from ID token
    
    Raises:
        MissingToken: If cookie is missing
        ExpiredToken: If token is expired
        InvalidToken: If signature or claims validation fails
    """
```

### Error Types

```python
class AuthError(Exception):
    """Base authentication/authorization error."""

class MissingToken(AuthError):
    """Token is missing from request."""

class InvalidToken(AuthError):
    """Token is malformed or signature invalid."""

class ExpiredToken(AuthError):
    """Token is expired."""

class Forbidden(AuthError):
    """Token is valid but insufficient permissions."""
```

---

## Testing

### Unit Testing Components

#### Testing JWTVerifier

```python
from unittest.mock import Mock
from jwt_verification import (
    JWTVerifier,
    JWTVerifyOptions,
    InvalidToken,
)

def test_verifier_validates_issuer():
    mock_key_provider = Mock()
    mock_key_provider.get_key_for_token.return_value = test_key
    
    verifier = JWTVerifier(
        key_provider=mock_key_provider,
        options=JWTVerifyOptions(
            issuer="https://expected-issuer.com/",
            audience="test-api",
        ),
    )
    
    # Token with wrong issuer should fail
    with pytest.raises(InvalidToken):
        verifier.verify(token_with_wrong_issuer)
```

#### Testing RBACAuthorizer

```python
from jwt_verification import (
    RBACAuthorizer,
    ClaimAccess,
    ClaimsMapping,
    Forbidden,
)

def test_authorizer_requires_all_permissions():
    mapping = ClaimsMapping()
    claims_access = ClaimAccess(mapping)
    authorizer = RBACAuthorizer(claims_access)
    
    claims = {
        "permissions": ["read:posts", "write:posts"],
    }
    
    # Should succeed with all permissions
    authorizer.authorize(
        claims,
        permissions=frozenset(["read:posts", "write:posts"]),
        roles=frozenset(),
        require_all_permissions=True,
    )
    
    # Should fail with missing permission
    with pytest.raises(Forbidden):
        authorizer.authorize(
            claims,
            permissions=frozenset(["read:posts", "delete:posts"]),
            roles=frozenset(),
            require_all_permissions=True,
        )
```

#### Testing Auth0JWKSProvider

```python
from jwt_verification import (
    Auth0JWKSProvider,
    InMemoryCache,
)

def test_provider_caches_keys():
    cache = InMemoryCache()
    provider = Auth0JWKSProvider(
        issuer="https://test.auth0.com/",
        cache=cache,
    )
    
    # First call fetches from JWKS
    key1 = provider.get_key_for_token("test-kid")
    
    # Second call uses cache (verify no additional JWKS fetch)
    key2 = provider.get_key_for_token("test-kid")
    
    assert key1 == key2
```

### Integration Testing

```python
import pytest
from flask import Flask
from jwt_verification import AuthExtension

@pytest.fixture
def app():
    app = Flask(__name__)
    app.config["TESTING"] = True
    
    auth = AuthExtension(verifier=test_verifier)
    
    @app.route("/protected")
    @auth.require()
    def protected():
        return {"message": "success"}
    
    return app

@pytest.fixture
def client(app):
    return app.test_client()

def test_protected_route_requires_token(client):
    response = client.get("/protected")
    assert response.status_code == 401

def test_protected_route_accepts_valid_token(client):
    headers = {"Authorization": f"Bearer {valid_test_token}"}
    response = client.get("/protected", headers=headers)
    assert response.status_code == 200
    assert response.json["message"] == "success"

def test_protected_route_rejects_expired_token(client):
    headers = {"Authorization": f"Bearer {expired_test_token}"}
    response = client.get("/protected", headers=headers)
    assert response.status_code == 401
```

### Mock Key Providers for Testing

```python
from jwt import PyJWK
from jwt_verification.protocols import KeyProvider

class MockKeyProvider(KeyProvider):
    """Simple key provider for testing."""
    
    def __init__(self, keys: dict[str, PyJWK]):
        self._keys = keys
    
    def get_key_for_token(self, kid: str) -> PyJWK:
        if kid not in self._keys:
            raise InvalidToken(f"Unknown kid: {kid}")
        return self._keys[kid]

# Usage in tests
test_keys = {
    "test-kid-1": PyJWK.from_dict(test_jwk_dict_1),
    "test-kid-2": PyJWK.from_dict(test_jwk_dict_2),
}
mock_provider = MockKeyProvider(test_keys)
```

---

## Deployment

### Production Checklist

- [ ] **Use Redis for caching** in multi-instance deployments
- [ ] **Configure appropriate TTLs**:
  - Key cache: 3600s (1 hour) or longer
  - Negative cache: 30-60s
- [ ] **Set conservative refresh throttling**:
  - `min_interval`: 60-120s
  - `alert_threshold`: 20-50
- [ ] **Enable logging and monitoring**
- [ ] **Use HTTPS only** for all API endpoints
- [ ] **Validate Auth0 configuration**:
  - Correct issuer URL
  - Correct API identifier (audience)
  - RBAC enabled in Auth0
- [ ] **Test key rotation** with Auth0
- [ ] **Configure error monitoring** (Sentry, etc.)
- [ ] **Set up alerts** for:
  - High rate of invalid tokens
  - JWKS refresh throttling
  - Redis cache failures

### Environment Configuration

```python
import os
from jwt_verification import (
    Auth0JWKSProvider,
    RedisCache,
    JWTVerifier,
    JWTVerifyOptions,
)
import redis

# Environment variables
AUTH0_DOMAIN = os.environ["AUTH0_DOMAIN"]
AUTH0_API_IDENTIFIER = os.environ["AUTH0_API_IDENTIFIER"]
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

# Redis setup
redis_client = redis.from_url(REDIS_URL, decode_responses=False)
cache = RedisCache(redis_client)

# Key provider setup
issuer = f"https://{AUTH0_DOMAIN}/"
key_provider = Auth0JWKSProvider(
    issuer=issuer,
    cache=cache,
    ttl_seconds=3600,
    missing_ttl_seconds=60,
    min_interval=120.0,
    alert_threshold=30,
)

# Verifier setup
verifier = JWTVerifier(
    key_provider=key_provider,
    options=JWTVerifyOptions(
        issuer=issuer,
        audience=AUTH0_API_IDENTIFIER,
        algorithms=("RS256",),
    ),
)
```

### Docker Deployment

**docker-compose.yml**:

```yaml
version: '3.8'

services:
  api:
    build: .
    ports:
      - "5000:5000"
    environment:
      - AUTH0_DOMAIN=your-tenant.auth0.com
      - AUTH0_API_IDENTIFIER=your-api-identifier
      - REDIS_URL=redis://redis:6379/0
    depends_on:
      - redis

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data

volumes:
  redis-data:
```

### Monitoring and Observability

#### Logging Example

```python
import logging
from jwt_verification import RefreshGate

logger = logging.getLogger(__name__)

# Add logging to RefreshGate
class MonitoredRefreshGate(RefreshGate):
    def allow(self) -> bool:
        allowed = super().allow()
        
        if not allowed:
            with self._lock:
                if self._retry_attempts >= self._alert_threshold:
                    logger.warning(
                        "JWKS refresh throttled heavily",
                        extra={
                            "retry_attempts": self._retry_attempts,
                            "threshold": self._alert_threshold,
                        },
                    )
        
        return allowed
```

#### Metrics Example

```python
from prometheus_client import Counter, Histogram

jwt_verification_total = Counter(
    'jwt_verification_total',
    'Total JWT verification attempts',
    ['result']  # success, expired, invalid, missing
)

jwt_verification_duration = Histogram(
    'jwt_verification_duration_seconds',
    'JWT verification duration'
)

# In your AuthExtension wrapper
@jwt_verification_duration.time()
def verify_with_metrics(token):
    try:
        claims = verifier.verify(token)
        jwt_verification_total.labels(result='success').inc()
        return claims
    except ExpiredToken:
        jwt_verification_total.labels(result='expired').inc()
        raise
    except InvalidToken:
        jwt_verification_total.labels(result='invalid').inc()
        raise
```

### Scaling Considerations

#### Horizontal Scaling

- **Cache**: Use Redis for shared state across instances
- **Refresh Throttling**: RefreshGate operates per-process
  - Consider distributed rate limiting (Redis-based) for strict guarantees
  - Current implementation is acceptable for most use cases

#### Vertical Scaling

- **Memory**: InMemoryCache grows with number of unique `kid` values
  - Typical: 1-10 keys, <1KB each
  - Redis eliminates memory concerns

#### Performance Tuning

- **Cache Hit Rate**: Monitor and adjust TTL
- **JWKS Fetches**: Should be rare after warmup
- **Negative Cache**: Reduces impact of invalid tokens

---

## Troubleshooting

### Common Issues

#### 1. "Invalid token: Unable to resolve key"

**Cause**: Key provider cannot find signing key for `kid`.

**Solutions**:

- Verify `issuer` matches exactly (including trailing slash)
- Check Auth0 JWKS endpoint is accessible
- Verify token's `kid` exists in JWKS
- Check for clock drift (token may not be valid yet)
- Ensure Redis is running (if using RedisCache)

#### 2. "Missing bearer token"

**Cause**: Authorization header missing or malformed.

**Solutions**:

- Verify client sends `Authorization: Bearer <token>`
- Check for extra whitespace or typos
- Ensure token is not in cookie (use CookieExtractor if needed)

#### 3. "decode error: Signature verification failed"

**Cause**: Token signature doesn't match public key.

**Solutions**:

- Verify `issuer` configuration matches token's `iss` claim
- Check for key rotation (wait for cache expiry or force refresh)
- Ensure token is from correct Auth0 tenant
- Verify token hasn't been tampered with

#### 4. "decode error: Token is expired"

**Cause**: Token's `exp` claim is in the past.

**Solutions**:

- Client needs to refresh token using refresh token
- Check for clock drift between servers
- Verify token lifetime settings in Auth0

#### 5. "Key refresh throttled"

**Cause**: RefreshGate preventing frequent JWKS fetches.

**Solutions**:

- This is expected during attacks—wait for `min_interval` to pass
- If legitimate: reduce `min_interval` (but increases DoS risk)
- Investigate source of invalid `kid` values

#### 6. 403 Forbidden errors

**Cause**: User lacks required roles or permissions.

**Solutions**:

- Verify user has correct roles in Auth0
- Check RBAC is enabled in Auth0 API settings
- Verify permissions are included in access token
- Check `ClaimsMapping` matches your token structure

### Debugging Tips

#### Enable Debug Logging

```python
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('jwt_verification')
logger.setLevel(logging.DEBUG)
```

#### Inspect JWT Claims

```python
import jwt

# Decode WITHOUT verification (for debugging only!)
unverified = jwt.decode(token, options={"verify_signature": False})
print("Token claims:", unverified)
print("Kid:", jwt.get_unverified_header(token).get("kid"))
```

#### Test JWKS Endpoint

```bash
curl https://your-tenant.auth0.com/.well-known/jwks.json
```

#### Verify Cache Contents

```python
# InMemoryCache
print("Cached keys:", list(cache._store.keys()))

# RedisCache
print("Cached keys:", redis_client.keys("*"))
```

#### Test Token Manually

```python
from jwt_verification import JWTVerifier

try:
    claims = verifier.verify(test_token)
    print("Success:", claims)
except Exception as e:
    print("Error:", type(e).__name__, str(e))
```

### Performance Issues

#### Slow Response Times

- **Check**: Cache hit rate
- **Solution**: Increase TTL or warm up cache

#### High Memory Usage

- **Check**: InMemoryCache size
- **Solution**: Switch to RedisCache

#### Many JWKS Fetches

- **Check**: Logs for cache misses
- **Solution**: Increase TTL, check for clock drift

---

## Advanced Topics

### Custom Key Providers

Implement the `KeyProvider` protocol for custom key sources:

```python
from jwt import PyJWK
from jwt_verification.protocols import KeyProvider
from jwt_verification import InvalidToken

class CustomKeyProvider(KeyProvider):
    """Load keys from custom source (database, file, etc.)."""
    
    def __init__(self, key_source):
        self._source = key_source
    
    def get_key_for_token(self, kid: str) -> PyJWK:
        key_data = self._source.fetch_key(kid)
        if not key_data:
            raise InvalidToken(f"Unknown kid: {kid}")
        return PyJWK.from_dict(key_data)
```

### Custom Extractors

Extract tokens from custom headers or query parameters:

```python
from flask import request
from jwt_verification.protocols import Extractor
from jwt_verification import MissingToken

class QueryParamExtractor(Extractor):
    """Extract token from query parameter."""
    
    def __init__(self, param_name: str = "token"):
        self._param = param_name
    
    def extract(self) -> str:
        token = request.args.get(self._param)
        if not token:
            raise MissingToken(f"Missing {self._param} query parameter")
        return token
```

### Custom Authorization Logic

Implement complex authorization rules:

```python
from jwt_verification.protocols import Authorizer, Claims
from jwt_verification import Forbidden

class CustomAuthorizer(Authorizer):
    """Custom authorization with business logic."""
    
    def authorize(
        self,
        claims: Claims,
        *,
        permissions: FrozenSet[str],
        roles: FrozenSet[str],
        require_all_permissions: bool,
    ) -> None:
        # Custom logic: require admin for write operations
        user_permissions = set(claims.get("permissions", []))
        
        if any(p.startswith("write:") for p in permissions):
            if "admin" not in claims.get("roles", []):
                raise Forbidden("Write operations require admin role")
        
        # Standard permission check
        if require_all_permissions:
            if not permissions.issubset(user_permissions):
                raise Forbidden
        elif permissions:
            if not permissions.intersection(user_permissions):
                raise Forbidden
```

### Multi-Tenant Support

Support multiple Auth0 tenants:

```python
from jwt_verification import Auth0JWKSProvider, JWTVerifier

class MultiTenantVerifier:
    """Route to correct tenant based on token issuer."""
    
    def __init__(self, tenant_configs: dict):
        self._verifiers = {}
        
        for tenant_id, config in tenant_configs.items():
            provider = Auth0JWKSProvider(issuer=config["issuer"])
            self._verifiers[tenant_id] = JWTVerifier(
                key_provider=provider,
                options=JWTVerifyOptions(
                    issuer=config["issuer"],
                    audience=config["audience"],
                ),
            )
    
    def verify(self, token: str) -> Claims:
        # Extract issuer from token
        unverified = jwt.decode(token, options={"verify_signature": False})
        issuer = unverified.get("iss")
        
        # Route to correct verifier
        for tenant_id, verifier in self._verifiers.items():
            if verifier._opt.issuer == issuer:
                return verifier.verify(token)
        
        raise InvalidToken("Unknown issuer")
```

### Graceful Key Rotation

Handle Auth0 key rotation seamlessly:

```python
# Extension already handles this automatically:
# 1. Auth0 publishes new key to JWKS
# 2. Old tokens use old kid → cached key still valid
# 3. New tokens use new kid → cache miss → JWKS fetch → success
# 4. Old key expires from cache after TTL
# 5. Old tokens become invalid naturally

# For immediate rotation (emergency):
# Clear cache to force refresh
redis_client.flushdb()  # RedisCache
# or
cache._store.clear()  # InMemoryCache
```

### Rate Limiting by User

Combine with Flask-Limiter:

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask import g

limiter = Limiter(
    app,
    key_func=lambda: g.jwt.get("sub") if hasattr(g, "jwt") else get_remote_address(),
)

@app.route("/api/resource")
@auth.require()
@limiter.limit("100 per hour")
def rate_limited_endpoint():
    return {"message": "Rate limited by user ID"}
```

### Conditional Authentication

Make authentication optional for certain routes:

```python
from flask import g
from jwt_verification import MissingToken

def optional_auth(view):
    """Decorator for optional authentication."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        try:
            token = auth._extractor.extract()
            g.jwt = auth._verifier.verify(token)
            g.authenticated = True
        except (MissingToken, AuthError):
            g.authenticated = False
        
        return view(*args, **kwargs)
    return wrapper

@app.route("/content")
@optional_auth
def public_content():
    if g.get("authenticated"):
        # Return personalized content
        user_id = g.jwt.get("sub")
        return {"message": f"Welcome back, {user_id}"}
    else:
        # Return public content
        return {"message": "Welcome, guest"}
```

---

## Best Practices

### 1. Never Log Tokens

```python
# ❌ BAD - tokens in logs
logger.info(f"Verifying token: {token}")

# ✅ GOOD - log metadata only
logger.info(f"Verifying token for user: {claims.get('sub')}")
```

### 2. Use Short Token Lifetimes

Configure Auth0 for:

- Access tokens: 15 minutes - 1 hour
- Refresh tokens: 7-30 days
- ID tokens: 1 hour

### 3. Validate All Claims

Always configure issuer and audience:

```python
# ❌ BAD - accepts tokens from any issuer
options = JWTVerifyOptions(issuer=None, audience=None)

# ✅ GOOD - explicit validation
options = JWTVerifyOptions(
    issuer="https://your-tenant.auth0.com/",
    audience="your-api-identifier",
)
```

### 4. Use Redis in Production

```python
# ❌ BAD - not shared across instances
cache = InMemoryCache()

# ✅ GOOD - shared cache
cache = RedisCache(redis_client)
```

### 5. Monitor and Alert

Set up alerts for:

- Spike in 401 errors
- Spike in 403 errors
- JWKS refresh throttling
- Cache failures

### 6. Handle Errors Gracefully

```python
# ❌ BAD - reveals internals
except InvalidToken as e:
    return {"error": str(e)}, 401

# ✅ GOOD - generic message
except InvalidToken:
    return {"error": "Invalid token"}, 401
```

### 7. Test Token Rotation

Regularly test Auth0 key rotation:

- Force rotation in Auth0 dashboard
- Verify new tokens work immediately
- Verify old tokens continue working during overlap

### 8. Secure Cookie Settings

If using CookieExtractor:

```python
response.set_cookie(
    "access_token",
    token,
    httponly=True,      # Prevent JavaScript access
    secure=True,        # HTTPS only
    samesite="Strict",  # CSRF protection
)
```

### 9. Principle of Least Privilege

Grant minimal permissions:

```python
# ❌ BAD - overly permissive
@auth.require(roles=["admin"])

# ✅ GOOD - specific permission
@auth.require(permissions=["read:specific_resource"])
```

### 10. Document Custom Claims

Clearly document custom claims structure:

```python
# Document expected token structure
"""
Token claims structure:
{
    "sub": "auth0|123456",
    "iss": "https://your-tenant.auth0.com/",
    "aud": "your-api-identifier",
    "exp": 1234567890,
    "permissions": ["read:posts", "write:posts"],
    "https://your-app.com/roles": ["admin", "moderator"],
    "https://your-app.com/metadata": {
        "plan": "premium"
    }
}
"""
```

---

## FAQ

### Q: Can I use this with providers other than Auth0?

**A:** Yes! Implement a custom `KeyProvider` for your provider's JWKS endpoint, or use `JWTVerifier` with any compliant key provider.

### Q: How do I handle token refresh?

**A:** Token refresh is a client-side responsibility. Clients should:

1. Detect 401 response
2. Use refresh token to get new access token from Auth0
3. Retry request with new access token

### Q: What happens during Auth0 key rotation?

**A:** The extension handles rotation seamlessly:

- Both old and new keys are in JWKS
- Cached keys continue to work
- New tokens use new key (cache miss → fetch → success)
- Old keys expire naturally from cache

### Q: Can I customize error responses?

**A:** Yes, use Flask error handlers:

```python
@app.errorhandler(401)
def custom_unauthorized(e):
    return custom_response, 401
```

### Q: How do I test with real Auth0 tokens?

**A:** Use Auth0's test tokens from the dashboard, or set up a test tenant. For unit tests, mock the key provider.

### Q: What's the performance impact?

**A:** Minimal with caching:

- First request: JWKS fetch (~100ms)
- Cached requests: ~1-5ms per verification
- Redis adds ~1-2ms overhead

### Q: Can I use this with WebSockets?

**A:** Yes, verify the token during WebSocket handshake and store claims for the connection lifetime.

### Q: How do I handle users with dynamic permissions?

**A:** Permissions are cached in the JWT. To revoke access:

1. Update permissions in Auth0
2. Wait for current tokens to expire
3. For immediate revocation: implement token blacklist (requires state management)

### Q: Can I use HS256 instead of RS256?

**A:** Not recommended. RS256 (asymmetric) is more secure for distributed systems. If you must use HS256, ensure the secret is never exposed.

---

## License

This extension is part of the auth0_Flask project. See the main project README for license information.

## Contributing

Contributions are welcome! Please ensure:

- All tests pass
- Code is typed with mypy
- Documentation is updated
- Security considerations are addressed

## Support

For issues or questions:

1. Check this documentation
2. Review closed issues on GitHub
3. Open a new issue with detailed reproduction steps

---

**Version:** 1.0.0  
**Last Updated:** February 23, 2026
