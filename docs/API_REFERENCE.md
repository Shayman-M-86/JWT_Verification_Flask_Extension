# API Reference

Complete API reference for the JWT Verification Extension.

## Table of Contents

- [Core Classes](#core-classes)
- [Protocols](#protocols)
- [Data Classes](#data-classes)
- [Exceptions](#exceptions)
- [Utility Functions](#utility-functions)
- [Type Aliases](#type-aliases)

---

## Core Classes

### AuthExtension

Flask extension for JWT authentication and authorization.

```python
class AuthExtension:
    def __init__(
        self,
        verifier: TokenVerifier,
        authorizer: Authorizer | None = None,
        extractor: Extractor | None = None,
    ) -> None
```

**Parameters:**
- `verifier` (TokenVerifier): Token verification implementation
- `authorizer` (Authorizer | None): Optional authorization implementation
- `extractor` (Extractor | None): Token extraction implementation (default: BearerExtractor)

**Methods:**

#### `init_app`

```python
def init_app(
    self,
    app: Flask,
    *,
    verifier: TokenVerifier | None = None,
    authorizer: Authorizer | None = None,
    extractor: Extractor | None = None,
) -> None
```

Initialize with Flask application (application factory pattern).

**Parameters:**
- `app` (Flask): Flask application instance
- `verifier` (TokenVerifier | None): Override verifier
- `authorizer` (Authorizer | None): Override authorizer
- `extractor` (Extractor | None): Override extractor

**Side Effects:**
- Registers extension in `app.extensions["auth_extension"]`

**Example:**
```python
auth = AuthExtension(verifier=verifier)
auth.init_app(app)
```

#### `require`

```python
def require(
    self,
    *,
    permissions: Sequence[str] = (),
    roles: Sequence[str] = (),
    require_all_permissions: bool = True,
)
```

Decorator factory for protecting Flask routes.

**Parameters:**
- `permissions` (Sequence[str]): Required permissions
- `roles` (Sequence[str]): Required roles (user must have at least one)
- `require_all_permissions` (bool): If True, user must have all permissions; if False, user needs at least one

**Returns:**
- Decorator function for Flask routes

**Raises:**
- `401 Unauthorized`: If token is missing, expired, or invalid
- `403 Forbidden`: If authorization fails

**Side Effects:**
- Stores verified claims in `flask.g.jwt`

**Example:**
```python
@app.route("/admin")
@auth.require(roles=["admin"])
def admin_endpoint():
    return {"message": "Admin only"}
```

---

### JWTVerifier

Provider-agnostic JWT signature and claims verification.

```python
class JWTVerifier(TokenVerifier):
    def __init__(
        self,
        key_provider: KeyProvider,
        options: JWTVerifyOptions,
    ) -> None
```

**Parameters:**
- `key_provider` (KeyProvider): Signing key provider
- `options` (JWTVerifyOptions): Verification options (issuer, audience, algorithms)

**Methods:**

#### `verify`

```python
def verify(self, token: str) -> Claims
```

Verify JWT and return claims.

**Parameters:**
- `token` (str): Raw JWT string

**Returns:**
- `Claims`: Decoded claims dictionary

**Raises:**
- `InvalidToken`: If signature invalid or claims validation fails
- `ExpiredToken`: If token is expired

**Process:**
1. Extract `kid` from unverified header
2. Get verification key from KeyProvider
3. Verify signature using PyJWT
4. Validate issuer, audience, algorithms
5. Return decoded claims

**Example:**
```python
claims = verifier.verify(token)
user_id = claims["sub"]
```

---

### Auth0JWKSProvider

Resolve JWT signing keys from Auth0's JWKS endpoint with caching and DoS protection.

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
    ) -> None
```

**Parameters:**
- `issuer` (str): Auth0 issuer URL (e.g., "https://tenant.auth0.com/")
- `cache` (CacheStore | None): Cache implementation (default: InMemoryCache)
- `ttl_seconds` (int): Cache TTL for valid keys in seconds (default: 600)
- `missing_ttl_seconds` (int): Cache TTL for unknown kids in seconds (default: 30)
- `min_interval` (float): Minimum seconds between forced JWKS refreshes (default: 60.0)
- `alert_threshold` (int): Denied refresh attempts before alerting (default: 40)

**Derived Properties:**
- JWKS URL: `{issuer}.well-known/jwks.json`

**Methods:**

#### `get_key_for_token`

```python
def get_key_for_token(self, kid: str) -> PyJWK
```

Resolve signing key for given key ID.

**Parameters:**
- `kid` (str): Key ID from JWT header

**Returns:**
- `PyJWK`: Verification key

**Raises:**
- `InvalidToken`: If key cannot be resolved

**Resolution Strategy:**
1. Check cache (O(1), fast path)
2. Try PyJWKClient.get_signing_key (may internally refresh JWKS)
3. On failure, negative-cache the kid (30s TTL)
4. If RefreshGate allows: force JWKS refresh and retry
5. If throttled or still not found: raise InvalidToken

**Example:**
```python
provider = Auth0JWKSProvider(
    issuer="https://tenant.auth0.com/",
    cache=RedisCache(redis_client),
    ttl_seconds=3600,
)
key = provider.get_key_for_token("auth0-kid-123")
```

---

### RBACAuthorizer

Enforce role-based and permission-based access control.

```python
class RBACAuthorizer(Authorizer):
    def __init__(self, claims: ClaimAccess) -> None
```

**Parameters:**
- `claims` (ClaimAccess): Claims accessor for extracting roles/permissions

**Methods:**

#### `authorize`

```python
def authorize(
    self,
    claims: Claims,
    *,
    permissions: FrozenSet[str],
    roles: FrozenSet[str],
    require_all_permissions: bool,
) -> None
```

Enforce authorization rules.

**Parameters:**
- `claims` (Claims): Verified JWT claims
- `permissions` (FrozenSet[str]): Required permissions
- `roles` (FrozenSet[str]): Required roles
- `require_all_permissions` (bool): Permission requirement mode

**Raises:**
- `Forbidden`: If authorization fails

**Logic:**
- **Roles**: User must have at least ONE of the required roles
- **Permissions** (require_all_permissions=True): User must have ALL required permissions
- **Permissions** (require_all_permissions=False): User must have at least ONE required permission

**Example:**
```python
authorizer = RBACAuthorizer(ClaimAccess(mapping))
authorizer.authorize(
    claims,
    permissions=frozenset(["read:posts", "write:posts"]),
    roles=frozenset(["editor"]),
    require_all_permissions=True,
)
```

---

### ClaimAccess

Normalize claims into strongly-typed role/permission sets.

```python
class ClaimAccess:
    def __init__(self, mapping: ClaimsMapping) -> None
```

**Parameters:**
- `mapping` (ClaimsMapping): Configuration for where roles/permissions live in JWT

**Methods:**

#### `permissions`

```python
def permissions(self, claims: Claims) -> FrozenSet[str]
```

Extract permissions from claims.

**Parameters:**
- `claims` (Claims): JWT claims dictionary

**Returns:**
- `FrozenSet[str]`: Set of permission strings

**Supports:**
- List of strings: `["read:posts", "write:posts"]`
- Space-separated string: `"read:posts write:posts"`
- Empty/missing claim: returns empty set

#### `roles`

```python
def roles(self, claims: Claims) -> FrozenSet[str]
```

Extract roles from claims.

**Parameters:**
- `claims` (Claims): JWT claims dictionary

**Returns:**
- `FrozenSet[str]`: Set of role strings

**Supports:**
- List of strings: `["admin", "editor"]`
- Single string: `"admin"`
- Multiple claim sources (single_role_claim + roles_claim)

**Example:**
```python
claims_access = ClaimAccess(ClaimsMapping())
user_perms = claims_access.permissions(claims)
user_roles = claims_access.roles(claims)
```

---

### InMemoryCache

Thread-safe in-process cache for development and single-instance deployments.

```python
class InMemoryCache:
    def __init__(self) -> None
```

**Methods:**

#### `get`

```python
def get(self, kid: str) -> Optional[PyJWK]
```

Get cached key by kid.

**Parameters:**
- `kid` (str): Key ID

**Returns:**
- `PyJWK | None`: Cached key or None if not found/expired

**Side Effects:**
- Removes expired entries on access (lazy expiration)

#### `set`

```python
def set(self, key: PyJWK, ttl_seconds: int) -> None
```

Cache a signing key.

**Parameters:**
- `key` (PyJWK): Signing key to cache
- `ttl_seconds` (int): Time-to-live in seconds

**Raises:**
- `ValueError`: If key doesn't have a kid

#### `set_missing`

```python
def set_missing(self, kid: str, ttl_seconds: int) -> None
```

Cache a known-missing kid (negative cache).

**Parameters:**
- `kid` (str): Key ID to mark as missing
- `ttl_seconds` (int): Time-to-live in seconds

#### `is_missing`

```python
def is_missing(self, kid: str) -> bool
```

Check if kid is cached as missing.

**Parameters:**
- `kid` (str): Key ID

**Returns:**
- `bool`: True if kid is cached as missing (and not expired)

**Example:**
```python
cache = InMemoryCache()
cache.set(key, ttl_seconds=600)
cached_key = cache.get("kid-123")
```

---

### RedisCache

Redis-backed distributed cache for production multi-instance deployments.

```python
class RedisCache:
    def __init__(self, redis_client: Any) -> None
```

**Parameters:**
- `redis_client` (Any): Redis client instance (from redis-py)

**Note:** Requires `redis_client` with `decode_responses=False`

**Methods:**

Same interface as InMemoryCache: `get`, `set`, `set_missing`, `is_missing`

**Serialization:**
- Keys stored as JSON under Redis key = kid
- Uses Redis SETEX for automatic TTL expiration
- Negative cache entries: `{"__missing__": True}`

**Example:**
```python
import redis
redis_client = redis.Redis(host='localhost', decode_responses=False)
cache = RedisCache(redis_client)
```

---

### BearerExtractor

Extract JWT from Authorization header.

```python
class BearerExtractor(Extractor):
    def extract(self) -> str
```

**Expected Header:**
```
Authorization: Bearer <JWT>
```

**Returns:**
- `str`: JWT token

**Raises:**
- `MissingToken`: If header is missing or doesn't start with "Bearer "

**Example:**
```python
extractor = BearerExtractor()
auth = AuthExtension(verifier=verifier, extractor=extractor)
```

---

### CookieExtractor

Extract JWT from HTTP cookie.

```python
class CookieExtractor(Extractor):
    def __init__(self, cookie_name: str = "access_token") -> None
```

**Parameters:**
- `cookie_name` (str): Name of cookie containing JWT (default: "access_token")

**Methods:**

#### `extract`

```python
def extract(self) -> str
```

**Returns:**
- `str`: JWT token from cookie

**Raises:**
- `MissingToken`: If cookie is missing

**Example:**
```python
extractor = CookieExtractor(cookie_name="jwt_token")
auth = AuthExtension(verifier=verifier, extractor=extractor)
```

---

### RefreshGate

Thread-safe rate limiter for JWKS refresh operations.

```python
class RefreshGate:
    def __init__(
        self,
        min_interval: float = 60.0,
        alert_threshold: int = 40
    ) -> None
```

**Parameters:**
- `min_interval` (float): Minimum seconds between allowed refreshes (default: 60.0)
- `alert_threshold` (int): Denied attempts before alerting (default: 40)

**Methods:**

#### `allow`

```python
def allow(self) -> bool
```

Check if refresh operation is allowed.

**Returns:**
- `bool`: True if allowed, False if throttled

**Side Effects:**
- Updates internal state (next allowed time, retry counter)
- Increments retry counter on denial
- Triggers alert hook at threshold (TODO in implementation)

**Thread Safety:**
- Uses threading.Lock for concurrent access

**Example:**
```python
gate = RefreshGate(min_interval=120.0, alert_threshold=30)
if gate.allow():
    # Perform expensive refresh operation
    refresh_jwks()
else:
    # Throttled - use cached data or fail
    raise InvalidToken("Refresh throttled")
```

---

## Protocols

### TokenVerifier

Protocol for JWT verification implementations.

```python
class TokenVerifier(Protocol):
    def verify(self, token: str) -> Claims: ...
```

**Methods:**

#### `verify`

Verify JWT and return decoded claims.

**Parameters:**
- `token` (str): Raw JWT string

**Returns:**
- `Claims`: Decoded claims dictionary

**Raises:**
- `AuthError` subclasses on failure

**Implementations:**
- `JWTVerifier`: Standard JWT verification with PyJWT

---

### KeyProvider

Protocol for signing key resolution.

```python
class KeyProvider(Protocol):
    def get_key_for_token(self, kid: str) -> PyJWK: ...
```

**Methods:**

#### `get_key_for_token`

Resolve verification key for given key ID.

**Parameters:**
- `kid` (str): Key ID from JWT header

**Returns:**
- `PyJWK`: Verification key

**Raises:**
- `InvalidToken`: If key cannot be resolved

**Implementations:**
- `Auth0JWKSProvider`: Fetch keys from Auth0 JWKS endpoint

---

### Authorizer

Protocol for authorization implementations.

```python
class Authorizer(Protocol):
    def authorize(
        self,
        claims: Claims,
        *,
        permissions: FrozenSet[str],
        roles: FrozenSet[str],
        require_all_permissions: bool,
    ) -> None: ...
```

**Methods:**

#### `authorize`

Enforce authorization rules.

**Parameters:**
- `claims` (Claims): Verified JWT claims
- `permissions` (FrozenSet[str]): Required permissions
- `roles` (FrozenSet[str]): Required roles
- `require_all_permissions` (bool): Permission requirement mode

**Raises:**
- `Forbidden`: If authorization fails

**Implementations:**
- `RBACAuthorizer`: Role-based and permission-based authorization

---

### CacheStore

Protocol for cache implementations.

```python
class CacheStore(Protocol):
    def get(self, kid: str) -> PyJWK | None: ...
    def set(self, key: PyJWK, ttl_seconds: int) -> None: ...
    def set_missing(self, kid: str, ttl_seconds: int) -> None: ...
    def is_missing(self, kid: str) -> bool: ...
```

**Methods:**

See `InMemoryCache` for detailed method documentation.

**Implementations:**
- `InMemoryCache`: In-process dictionary cache
- `RedisCache`: Redis-backed distributed cache

---

### Extractor

Protocol for token extraction from requests.

```python
class Extractor(Protocol):
    def extract(self) -> str: ...
```

**Methods:**

#### `extract`

Extract JWT from Flask request.

**Returns:**
- `str`: Raw JWT string

**Raises:**
- `MissingToken`: If token cannot be extracted

**Implementations:**
- `BearerExtractor`: Extract from Authorization header
- `CookieExtractor`: Extract from cookie

---

## Data Classes

### JWTVerifyOptions

```python
@dataclass(frozen=True, slots=True)
class JWTVerifyOptions:
    issuer: Optional[str]
    audience: Optional[str]
    algorithms: tuple[str, ...] = ("RS256",)
```

Configuration for JWT verification.

**Fields:**
- `issuer` (str | None): Expected `iss` claim (e.g., "https://tenant.auth0.com/")
- `audience` (str | None): Expected `aud` claim (your API identifier)
- `algorithms` (tuple[str, ...]): Allowed signature algorithms (default: ("RS256",))

**Security Notes:**
- Never set algorithms to include "none" or weak algorithms
- Always specify issuer and audience for production
- Use Only RS256 for Auth0

**Example:**
```python
options = JWTVerifyOptions(
    issuer="https://tenant.auth0.com/",
    audience="my-api-identifier",
    algorithms=("RS256",),
)
```

---

### ClaimsMapping

```python
@dataclass(frozen=True, slots=True)
class ClaimsMapping:
    permissions_claim: str = "permissions"
    roles_claim: str = "roles"
    single_role_claim: Optional[str] = None
```

Configuration for where roles/permissions live in JWT claims.

**Fields:**
- `permissions_claim` (str): Claim containing permissions list (default: "permissions")
- `roles_claim` (str): Claim containing roles list (default: "roles")
- `single_role_claim` (str | None): Optional claim containing single role string

**Auth0 Configuration:**

For custom namespaced claims:
```python
mapping = ClaimsMapping(
    permissions_claim="permissions",
    roles_claim="https://myapp.com/roles",
    single_role_claim="https://myapp.com/primary_role",
)
```

For standard claims:
```python
mapping = ClaimsMapping()  # Use defaults
```

**Example Token Structure:**
```json
{
  "sub": "auth0|123",
  "permissions": ["read:posts", "write:posts"],
  "roles": ["editor", "user"],
  "https://myapp.com/primary_role": "editor"
}
```

---

## Exceptions

### AuthError

```python
class AuthError(Exception):
    """Base authentication/authorization error."""
```

Base class for all auth-related errors.

**Usage:**
```python
from jwt_verification import AuthError

try:
    auth_operation()
except AuthError as e:
    # Handle any auth error
    pass
```

---

### MissingToken

```python
class MissingToken(AuthError):
    """Raised when Authorization header is missing/invalid."""
```

Raised by extractors when token cannot be found in request.

**HTTP Mapping:** 401 Unauthorized

**Example:**
```python
try:
    token = extractor.extract()
except MissingToken:
    return {"error": "No token provided"}, 401
```

---

### InvalidToken

```python
class InvalidToken(AuthError):
    """Raised for malformed tokens, invalid signatures, bad issuer/audience, key resolution failures."""
```

Raised when token is present but invalid.

**Causes:**
- Signature verification failure
- Wrong issuer
- Wrong audience
- Malformed token structure
- Unknown kid
- Key resolution failure

**HTTP Mapping:** 401 Unauthorized

**Example:**
```python
try:
    claims = verifier.verify(token)
except InvalidToken as e:
    logger.warning(f"Invalid token: {e}")
    return {"error": "Invalid token"}, 401
```

---

### ExpiredToken

```python
class ExpiredToken(AuthError):
    """Raised when token is expired."""
```

Raised when token's `exp` claim is in the past.

**HTTP Mapping:** 401 Unauthorized

**Client Action:** Request new token using refresh token

**Example:**
```python
try:
    claims = verifier.verify(token)
except ExpiredToken:
    return {"error": "Token expired", "action": "refresh"}, 401
```

---

### Forbidden

```python
class Forbidden(AuthError):
    """Raised when token is valid but does not meet required roles/permissions."""
```

Raised by authorizers when user lacks required authorization.

**HTTP Mapping:** 403 Forbidden

**Distinction:**
- 401 Unauthorized: "Who are you?" (authentication failed)
- 403 Forbidden: "I know who you are, but you can't do this" (authorization failed)

**Example:**
```python
try:
    authorizer.authorize(claims, permissions=..., roles=...)
except Forbidden:
    return {"error": "Insufficient permissions"}, 403
```

---

## Utility Functions

### get_verified_id_claims

```python
def get_verified_id_claims(
    verifier: TokenVerifier,
    *,
    cookie_name: str = "id_token",
) -> Claims
```

Verify ID token from cookie and return claims.

**Parameters:**
- `verifier` (TokenVerifier): Token verifier configured for ID tokens
- `cookie_name` (str): Name of cookie containing ID token (default: "id_token")

**Returns:**
- `Claims`: Verified claims from ID token

**Raises:**
- `MissingToken`: If cookie is missing
- `ExpiredToken`: If token is expired
- `InvalidToken`: If signature or claims validation fails

**Use Case:**
ID tokens contain user profile information and are typically stored in cookies after OAuth login.

**Example:**
```python
@app.route("/user-info")
def user_info():
    claims = get_verified_id_claims(
        verifier=id_token_verifier,
        cookie_name="id_token",
    )
    return {
        "name": claims.get("name"),
        "email": claims.get("email"),
        "picture": claims.get("picture"),
    }
```

**Configuration:**
```python
# ID token verifier uses client ID as audience
id_token_verifier = JWTVerifier(
    key_provider=provider,
    options=JWTVerifyOptions(
        issuer="https://tenant.auth0.com/",
        audience="your-client-id",  # NOT API identifier
    ),
)
```

---

## Type Aliases

### Claims

```python
type Claims = Mapping[str, Any]
```

JWT claims represented as a read-only dictionary.

**Standard Claims:**
- `sub` (str): Subject (user ID)
- `iss` (str): Issuer
- `aud` (str | list[str]): Audience
- `exp` (int): Expiration timestamp
- `iat` (int): Issued at timestamp
- `nbf` (int): Not before timestamp

**Custom Claims:**
- `email` (str): User email
- `name` (str): User name
- `permissions` (list[str]): User permissions
- `roles` (list[str]): User roles
- Any custom namespaced claims

**Example:**
```python
claims: Claims = verifier.verify(token)
user_id: str = claims["sub"]
email: str | None = claims.get("email")
permissions: list = claims.get("permissions", [])
```

---

### ViewFunc

```python
type ViewFunc = Callable[..., Any]
```

Flask view function type (any callable with any signature and return type).

**Example:**
```python
def my_view() -> dict:
    return {"message": "hello"}

def another_view(user_id: int) -> Response:
    return jsonify({"user_id": user_id})

# Both are ViewFunc
```

---

## Import Guide

### All-in-One Import

```python
from jwt_verification import (
    # Core classes
    AuthExtension,
    JWTVerifier,
    JWTVerifyOptions,
    Auth0JWKSProvider,
    RBACAuthorizer,
    ClaimAccess,
    ClaimsMapping,
    
    # Cache stores
    InMemoryCache,
    RedisCache,
    
    # Extractors
    BearerExtractor,
    CookieExtractor,
    
    # Utilities
    RefreshGate,
    get_verified_id_claims,
    
    # Errors
    AuthError,
    MissingToken,
    InvalidToken,
    ExpiredToken,
    Forbidden,
    
    # Protocols (for type hints)
    TokenVerifier,
    KeyProvider,
    Authorizer,
    CacheStore,
    Extractor,
    Claims,
    ViewFunc,
)
```

### Selective Imports

```python
# Minimal setup
from jwt_verification import (
    AuthExtension,
    Auth0JWKSProvider,
    JWTVerifier,
    JWTVerifyOptions,
)

# With RBAC
from jwt_verification import (
    RBACAuthorizer,
    ClaimAccess,
    ClaimsMapping,
)

# With Redis
from jwt_verification import RedisCache

# Error handling
from jwt_verification import (
    MissingToken,
    ExpiredToken,
    InvalidToken,
    Forbidden,
)
```

---

## Version Information

**Version:** 1.0.0  
**Python:** 3.14+  
**Dependencies:**
- PyJWT[crypto] >= 2.8.0
- Flask >= 2.3.0
- cryptography >= 41.0.0
- redis (optional, for RedisCache)

**Last Updated:** February 23, 2026
