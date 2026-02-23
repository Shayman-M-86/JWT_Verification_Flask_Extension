"""
Protocol definitions (interfaces) for the authentication system.
"""

from typing import Any, Callable, FrozenSet, Mapping, Protocol

from jwt import PyJWK

# Claims returned after JWT verification
type Claims = Mapping[str, Any]

# Flask view function type (any signature, any return)
type ViewFunc = Callable[..., Any]


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
