from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass
from functools import wraps
from typing import Any, Callable, FrozenSet, Mapping, Optional, Protocol, Sequence, cast

import jwt
from flask import Flask, abort, g, request
from jwt import PyJWK, PyJWKClient

"""
Auth module: JWT verification + key resolution (Auth0 JWKS) + optional RBAC enforcement.

Design goals
------------
- **Composable**: swap TokenVerifier / KeyProvider / CacheStore implementations without changing the Flask app.
- **Expandable**: add additional KeyProviders (e.g., your future auth API) without touching the verifier or extension.
- **Safe-by-default**: strict JWT verification (issuer/audience/alg allowlist) and refresh-throttling on key misses.
- **Testable**: each component has a single responsibility and can be unit tested in isolation.

High-level flow (per request)
-----------------------------
1. `AuthExtension.require(...)` decorator runs.
2. `BearerExtractor` pulls the raw JWT from `Authorization: Bearer <token>`.
3. `JWTVerifier.verify(token)`:
   - Reads unverified header to get `kid`
   - Asks KeyProvider for the verification key for that `kid`
   - Runs `jwt.decode(...)` with issuer/audience/algorithms checks
4. Optional `Authorizer` enforces roles/permissions.
5. On success: verified claims are stored in `flask.g.jwt`.

Security notes
--------------
- Never trust claims until signature verification succeeds.
- Only allow known algorithms (avoid algorithm confusion).
- Validate `iss` and `aud` to ensure the token was minted for *your API*.
- Throttle JWKS refresh attempts so attackers cannot DoS you by sending random `kid`s.

"""


# ============================================================
# Types
# ============================================================

# Claims returned after JWT verification
type Claims = Mapping[str, Any]

# Flask view function type (any signature, any return)
type ViewFunc = Callable[..., Any]


# ============================================================
# Protocols (ports)
# ============================================================


class TokenVerifier(Protocol):
    """
    Verifies a JWT and returns decoded claims on success.
    Should raise AuthError subclasses on failure.
    """

    def verify(self, token: str) -> Claims: ...


class CacheStore(Protocol):
    """
    Caches resolved keys, typically by 'kid'.

    Notes:
    - For production multi-instance deployments, prefer a distributed store (Redis).
    - TTL handling may be implemented in the store (Redis) or in the caller.
    """

    def get(self, kid: str) -> PyJWK | None: ...
    def set(self, key: PyJWK, ttl_seconds: int) -> None: ...
    def set_missing(self, kid: str, ttl_seconds: int) -> None: ...
    def is_missing(self, kid: str) -> bool: ...


class KeyProvider(Protocol):
    """
    Given a key id (kid), returns the verification key material required by jwt.decode.
    Implementations may:
    - fetch from a JWKS endpoint (Auth0)
    - fetch from your own auth service (placeholder later)
    - load from disk, env, etc.
    """

    def get_key_for_token(self, kid: str) -> PyJWK: ...


class Authorizer(Protocol):
    """
    Optional authorization step after token verification.
    Enforces roles/permissions from claims.
    Should raise Forbidden if authorization fails.
    """

    def authorize(
        self,
        claims: Claims,
        *,
        permissions: FrozenSet[str],
        roles: FrozenSet[str],
        require_all_permissions: bool,
    ) -> None: ...


class Extractor(Protocol):
    """
    Extracts the raw JWT from a Flask request.
    """

    def extract(self) -> str: ...


# ============================================================
# Errors (domain exceptions)
# ============================================================


class AuthError(Exception):
    """Base auth error."""


class MissingToken(AuthError):
    """Raised when Authorization header is missing/invalid."""


class InvalidToken(AuthError):
    """Raised for malformed tokens, invalid signatures, bad issuer/audience, key resolution failures."""


class ExpiredToken(AuthError):
    """Raised when token is expired."""


class Forbidden(AuthError):
    """Raised when token is valid but does not meet required roles/permissions."""


# ============================================================
# Extractor
# ============================================================


class BearerExtractor(Extractor):
    """
    Extracts the raw JWT from a Flask request.

    Expected format:
        Authorization: Bearer <JWT>
    """

    def extract(self) -> str:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            raise MissingToken("Missing bearer token")
        return auth.split(" ", 1)[1].strip()


class CookieExtractor(Extractor):
    def __init__(self, cookie_name: str = "access_token") -> None:
        self._name = cookie_name

    def extract(self) -> str:
        token = request.cookies.get(self._name)
        if not token:
            raise MissingToken("Missing access token cookie")
        return token


# ============================================================
# Generic JWT verifier (provider-agnostic)
# ============================================================


@dataclass(frozen=True, slots=True)
class JWTVerifyOptions:
    """
    Parameters that define what tokens are considered valid for this API.

    issuer:
        Expected `iss` claim. For Auth0 typically: "https://<domain>/"
    audience:
        Expected `aud` claim, usually your API Identifier in Auth0.
    algorithms:
        Allowed algorithms (explicit allowlist). Avoid trusting the token header.
    """

    issuer: Optional[str]
    audience: Optional[str]
    algorithms: tuple[str, ...] = ("RS256",)


class JWTVerifier(TokenVerifier):
    """
    Verifies JWTs using an injected KeyProvider.

    Responsibilities:
    - parse unverified header to get `kid`
    - ask KeyProvider to resolve the correct verification key
    - decode and validate token signature + standard claims

    KeyProvider handles:
    - caching
    - JWKS refresh policies / throttling
    """

    def __init__(
        self,
        key_provider: KeyProvider,
        options: JWTVerifyOptions,
    ) -> None:
        self._keys = key_provider
        self._opt = options

    def verify(self, token: str) -> Claims:
        # Step 1: read header without verification (safe for 'kid' extraction)
        try:
            kid = jwt.get_unverified_header(token).get("kid")
            if not isinstance(kid, str):
                raise InvalidToken("Missing or invalid 'kid' in token header")
            key: PyJWK = self._keys.get_key_for_token(kid)
        except AuthError:
            # Preserve domain errors
            raise
        except Exception as e:
            # Normalize anything else to InvalidToken
            raise InvalidToken("Unable to resolve key") from e

        # Step 2: verify signature + claims
        try:
            return jwt.decode(
                token,
                key,
                algorithms=list(self._opt.algorithms),
                audience=self._opt.audience,
                issuer=self._opt.issuer,
            )

        except jwt.ExpiredSignatureError as e:
            raise ExpiredToken from e
        except jwt.InvalidTokenError as e:
            raise InvalidToken(f"decode error: {e}") from e


# ============================================================
# RefreshGate (anti-refresh DoS)
# ============================================================


class RefreshGate:
    """
    Simple, thread-safe refresh limiter.

    Behavior:
    - allow() returns True at most once per min_interval_seconds
    - additional calls within interval return False and increment a counter
    - when enough denials occur, you can log/alert (hook left as a placeholder)
    """

    def __init__(self, min_interval: float = 60.0, alert_threshold: int = 40) -> None:
        self._min_interval = min_interval
        self._alert_threshold = alert_threshold

        self._lock = threading.Lock()
        self._next_allowed_at: float = 0.0
        self._retry_attempts: int = 0

    def allow(self) -> bool:
        now = time.time()
        with self._lock:
            if now < self._next_allowed_at:
                self._retry_attempts += 1
                if self._retry_attempts >= self._alert_threshold:
                    # TODO: log / metrics / alert hook
                    # Example:
                    # logger.warning("JWKS refresh throttled frequently")
                    pass
                return False

            self._next_allowed_at = now + self._min_interval
            self._retry_attempts = 0
            return True


# ============================================================
# Auth0 Key Provider (implemented)
# ============================================================


class Auth0JWKSProvider(KeyProvider):
    """
    Resolves JWT signing keys from an Auth0 JWKS endpoint with caching and
    refresh throttling.

    Responsibilities
    ----------------
    1. Resolve the correct signing key for a given `kid`.
    2. Cache resolved keys locally to avoid repeated lookups.
    3. Negative-cache unknown `kid` values to make attacker traffic cheap.
    4. Rate-limit forced JWKS refresh operations to prevent outbound DoS.
    5. Provide a clean abstraction over PyJWKClient for application code.

    Resolution Strategy
    -------------------
    For each requested `kid`:

    1) Cache lookup (fast path)
        - If key is cached → return immediately.

    2) Normal resolution
        - Attempt `PyJWKClient.get_signing_key(kid)`
        - PyJWT may internally refresh once if the key is missing.

    3) Negative caching
        - If resolution fails, the `kid` is cached as "missing" for a short TTL.
        - Prevents repeated expensive lookups for attacker-provided random keys.

    4) Forced refresh (rate-limited)
        - If still unresolved and the RefreshGate allows:
              fetch JWKS with refresh=True
              retry resolution once
        - If throttled, fail fast.

    5) Failure
        - Raises InvalidToken if key cannot be resolved.

    Security Properties
    -------------------
    Protects against:
        - Random `kid` spam attacks
        - Outbound JWKS request amplification
        - Cache bypass attempts

    Maintains compatibility with:
        - Legitimate key rotation
        - Auth0 JWKS updates
        - Short-lived cache invalidation

    Parameters
    ----------
    issuer : str
        Issuer base URL (e.g., "https://tenant.auth0.com/").
        JWKS URL is derived as `{issuer}.well-known/jwks.json`.

    cache : CacheStore
        Cache implementation for resolved keys.
        May support negative caching via `set_missing`.

    ttl_seconds : int
        TTL for successfully resolved signing keys.

    missing_ttl_seconds : int
        TTL for negative cache entries (unknown kids).

    min_interval : float
        Minimum interval between forced JWKS refresh attempts.

    alert_threshold : int
        Denial threshold before optional alerting in RefreshGate.

    Notes
    -----
    - PyJWKClient already caches the JWKS set internally.
      This provider adds:
          • per-kid caching
          • negative caching
          • refresh throttling
          • multi-store compatibility

    - RefreshGate operates per process.
      For horizontally scaled systems, consider distributed coordination.

    - Negative caching dramatically reduces attacker impact by converting
      repeated invalid `kid` attempts into constant-time failures.

    Example
    -------
    provider = Auth0JWKSProvider(
        issuer="https://example.auth0.com/",
        cache=InMemoryCache(),
    )

    key = provider.get_key_for_token(kid)
    """

    def __init__(
        self,
        issuer: str,
        cache: InMemoryCache,  # or CacheStore + optional set_missing
        ttl_seconds: int = 600,
        missing_ttl_seconds: int = 30,
        min_interval: float = 60.0,
        alert_threshold: int = 40,
    ) -> None:
        self._ttl = ttl_seconds
        self._missing_ttl = missing_ttl_seconds
        self._cache = cache
        self._gate = RefreshGate(
            min_interval=min_interval, alert_threshold=alert_threshold
        )
        self._client = PyJWKClient(
            f"{issuer}.well-known/jwks.json",
            cache_jwk_set=True,
            lifespan=ttl_seconds,
        )

    def get_key_for_token(self, kid: str) -> PyJWK:
        cached = self._cache.get(kid)

        # If you implement set_missing(), cached may be None meaning "known missing"
        if cached is None and kid in getattr(self._cache, "_store", {}):
            # known missing (in-memory example); for a real CacheStore add explicit API
            raise InvalidToken("Unknown kid (cached)")

        if cached:
            return cached

        # 1) Try normal resolution (PyJWT may refresh-on-miss internally once)
        try:
            jwk = self._client.get_signing_key(kid)
            self._cache.set(jwk, ttl_seconds=self._ttl)
            return jwk
        except Exception:
            # negative-cache this kid to make spam cheap
            if hasattr(self._cache, "set_missing"):
                self._cache.set_missing(kid, ttl_seconds=self._missing_ttl)

        # 2) Optional forced refresh, but rate-limited
        if not self._gate.allow():
            raise InvalidToken("Key refresh throttled")

        # Force refresh of JWKS set, then retry once
        try:
            self._client.get_signing_keys(refresh=True)  # forces JWKS fetch
            jwk = self._client.get_signing_key(kid)
            self._cache.set(jwk, ttl_seconds=self._ttl)
            return jwk
        except Exception as e:
            if hasattr(self._cache, "set_missing"):
                self._cache.set_missing(kid, ttl_seconds=self._missing_ttl)
            raise InvalidToken("Unable to resolve signing key") from e


# ============================================================
# Cache stores
# ============================================================


@dataclass
class _CacheItem:
    value: PyJWK | None  # None means "known-missing"
    expires_at: float


class InMemoryCache(CacheStore):
    """
    Simple in-process cache.

    Good for:
    - local dev
    - single instance deployments

    Not ideal for:
    - multiple processes/containers (each has its own cache)

    NOTE: This cache currently ignores ttl_seconds (no expiration).
    For correctness, consider storing (value, expires_at) like your earlier CacheItem pattern.
    """

    def __init__(self) -> None:
        self._store: dict[str, _CacheItem] = {}

    def get(self, kid: str) -> Optional[PyJWK]:
        item = self._store.get(kid)
        if not item:
            return None
        if time.time() >= item.expires_at:
            self._store.pop(kid, None)
            return None
        return item.value  # may be None (known-missing)

    def set(self, key: PyJWK, ttl_seconds: int) -> None:
        kid = key.key_id
        if not kid:
            raise ValueError("Key must have kid")
        self._store[kid] = _CacheItem(value=key, expires_at=time.time() + ttl_seconds)

    def set_missing(self, kid: str, ttl_seconds: int) -> None:
        self._store[kid] = _CacheItem(value=None, expires_at=time.time() + ttl_seconds)

    def is_missing(self, kid: str) -> bool:
        item = self._store.get(kid)
        if not item:
            return False
        if time.time() >= item.expires_at:
            self._store.pop(kid, None)
            return False
        return item.value is None  # known-missing if value is None


class RedisCache(CacheStore):
    """
    Redis-backed cache store.

    Behavior:
    - Stores the underlying JWK dict as JSON under key=kid
    - Uses Redis TTL (setex) to expire automatically

    NOTE:
    - Uses a private attribute `key._jwk_data` to serialize.
      Consider wrapping PyJWK storage in your own DTO if you want to avoid private usage.
    """

    def __init__(self, redis_client: Any) -> None:
        self._client = redis_client

    def get(self, kid: str) -> Optional[PyJWK]:
        data = self._client.get(kid)
        if data is None:
            return None
        try:
            return PyJWK.from_dict(json.loads(data))
        except Exception as e:
            raise RuntimeError("Failed to parse cached key") from e

    def set(self, key: PyJWK, ttl_seconds: int) -> None:
        try:
            kid = key.key_id
            if kid is None:
                raise ValueError("Key must have a key_id (kid) to be cached")
            self._client.setex(
                kid,
                ttl_seconds,
                json.dumps(key._jwk_data),  # pyright: ignore[reportPrivateUsage]
            )
        except Exception as e:
            raise RuntimeError("Failed to set cache") from e


# ============================================================
# Claims access + Authorizer (generic RBAC)
# ============================================================


@dataclass(frozen=True, slots=True)
class ClaimsMapping:
    """
    Maps "where" roles/permissions live in the JWT.

    For Auth0:
    - permissions are often in "permissions" if RBAC is enabled + added to access token
    - roles are often a custom namespaced claim (e.g. "https://yourapp/roles")
      In that case, set roles_claim to that namespace.
    """

    permissions_claim: str = "permissions"
    roles_claim: str = "roles"
    single_role_claim: Optional[str] = None


class ClaimAccess:
    """
    Normalizes raw claims into strongly-typed role/permission sets.
    """

    def __init__(self, mapping: ClaimsMapping) -> None:
        self._m = mapping

    def permissions(self, claims: Claims) -> FrozenSet[str]:
        raw = claims.get(self._m.permissions_claim, [])
        if isinstance(raw, str):
            # supports "read:foo write:bar" style
            return frozenset(raw.split())
        if isinstance(raw, (list, tuple, set, frozenset)):
            raw_seq = cast(Sequence[object], raw)
            cleaned = [item for item in raw_seq if isinstance(item, str)]
            return frozenset(cleaned)
        return frozenset()

    def roles(self, claims: Claims) -> FrozenSet[str]:
        roles: set[str] = set()

        if self._m.single_role_claim:
            r = claims.get(self._m.single_role_claim)
            if isinstance(r, str):
                roles.add(r)

        raw = claims.get(self._m.roles_claim, [])
        if isinstance(raw, str):
            roles.add(raw)
        elif isinstance(raw, (list, tuple, set, frozenset)):
            raw_seq = cast(Sequence[object], raw)
            roles.update(item for item in raw_seq if isinstance(item, str))

        return frozenset(roles)


class RBACAuthorizer(Authorizer):
    """
    Enforces role/permission requirements against verified claims.

    - roles: user must have at least one of required roles
    - permissions: depending on `require_all_permissions`, must have all or any
    """

    def __init__(self, claims: ClaimAccess) -> None:
        self._claims = claims

    def authorize(
        self,
        claims: Claims,
        *,
        permissions: FrozenSet[str],
        roles: FrozenSet[str],
        require_all_permissions: bool,
    ) -> None:
        if roles:
            user_roles = self._claims.roles(claims)
            if not user_roles.intersection(roles):
                raise Forbidden

        if permissions:
            user_perms = self._claims.permissions(claims)

            if require_all_permissions:
                if not permissions.issubset(user_perms):
                    raise Forbidden
            else:
                if not permissions.intersection(user_perms):
                    raise Forbidden


# ============================================================
# Flask Extension
# ============================================================

_EXT_KEY = "auth_extension"


class AuthExtension:
    """
    Flask decorator glue.

    Responsibilities:
    - Extract token from request
    - Verify token (TokenVerifier)
    - Store verified claims in `flask.g.jwt`
    - Optionally authorize roles/permissions (Authorizer)
    - Convert domain errors to HTTP responses (abort)

    Pattern:
        auth = AuthExtension()
        auth.init_app(app, verifier=verifier, authorizer=authorizer)

    Usage:
        auth = AuthExtension(verifier, authorizer)
        @app.get("/admin")
        @auth.require(roles=["admin"])
        def admin(): ...
    """

    def __init__(
        self,
        verifier: TokenVerifier,
        authorizer: Authorizer | None = None,
        extractor: Extractor = BearerExtractor(),
    ) -> None:
        self._verifier: TokenVerifier = verifier
        self._authorizer: Authorizer | None = authorizer
        self._extractor: Extractor = extractor

    def init_app(
        self,
        app: Flask,
        *,
        verifier: TokenVerifier | None = None,
        authorizer: Authorizer | None = None,
        extractor: Extractor | None = None,
    ) -> None:
        if verifier is not None:
            self._verifier = verifier
        if authorizer is not None:
            self._authorizer = authorizer
        if extractor is not None:
            self._extractor = extractor

        # register on app so you can access it anywhere via current_app.extensions
        app.extensions[_EXT_KEY] = self

    def require(
        self,
        *,
        permissions: Sequence[str] = (),
        roles: Sequence[str] = (),
        require_all_permissions: bool = True,
    ):
        """
        Decorator factory.
        - permissions: required permissions for this route
        - roles: required roles for this route
        - require_all_permissions:
            True  -> user must have all permissions listed
            False -> user must have at least one of the permissions listed
        """
        permissions_set = frozenset(permissions)
        roles_set = frozenset(roles)

        def decorator(view: ViewFunc) -> ViewFunc:
            @wraps(view)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                try:
                    token = self._extractor.extract()
                    claims = self._verifier.verify(token)

                    # Make claims accessible to route handlers
                    g.jwt = claims

                    # Optional authorization step
                    if self._authorizer:
                        self._authorizer.authorize(
                            claims,
                            permissions=permissions_set,
                            roles=roles_set,
                            require_all_permissions=require_all_permissions,
                        )

                except MissingToken:
                    abort(401, description="Missing token")
                except ExpiredToken:
                    abort(401, description="Expired token")
                except InvalidToken as e:
                    abort(401, description=f"Invalid token: {e}")
                except Forbidden:
                    abort(403, description="Forbidden")

                return view(*args, **kwargs)

            return wrapper

        return decorator


def get_verified_id_claims(
    verifier: TokenVerifier,
    *,
    cookie_name: str = "id_token",
) -> Claims:
    """
    Return verified ID-token claims from the current Flask request.

    - Extracts ID token from cookie (default "id_token")
    - Verifies signature + issuer + audience
    - Returns decoded claims

    Raises:
        MissingToken, ExpiredToken, InvalidToken
    """
    token = request.cookies.get(cookie_name)
    if not token:
        raise MissingToken("Missing id_token cookie")
    return verifier.verify(token)
