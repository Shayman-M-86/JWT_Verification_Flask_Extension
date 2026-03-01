"""Protocol definitions for the JWT verification extension.

This module defines structural interfaces using Protocol (PEP 544) for:
- Token verification
- Key resolution
- Caching
- Authorization
- Token extraction

Using protocols allows for duck-typing and easier testing/mocking without
requiring explicit inheritance. Any class that implements the required methods
satisfies the protocol.

Type aliases provide semantic clarity and adapt easily to future changes.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from jwt import PyJWK

# ============================================================================
# Type Aliases
# ============================================================================

type Claims = Mapping[str, Any]
"""Represents the decoded JWT payload as an immutable mapping.
"""

type ViewFunc = Callable[..., Any]
"""Type alias for Flask view functions (callable that takes any args and returns any)."""


# ============================================================================
# Core Protocols
# ============================================================================


class TokenVerifier(Protocol):
    """Protocol for JWT verification implementations.

    Implementers must provide a verify() method that:
    1. Validates the token's structure and signature
    2. Returns the decoded claims payload

    This protocol is provider-agnostic, allowing for different JWT libraries
    or custom verification logic.
    """

    def verify(self, token: str) -> Claims:
        """Verify a JWT and return its decoded claims.

        Args:
            token: The raw JWT string (e.g., from Authorization: Bearer <token>)

        Returns:
            Immutable mapping of verified claims from the token payload.

        Raises:
            InvalidToken: Token is malformed, signature invalid, or claims invalid
            ExpiredToken: Token's exp claim has passed
            AuthError: Any other verification failure
        """
        ...


class CacheStore(Protocol):
    """Protocol for caching signing keys.

    Implementers must provide methods for storing PyJWK objects, keyed by the
    kid (key ID) from the JWT header.

    Caching reduces JWKS endpoint requests, improving performance and reducing
    load on the identity provider.

    Negative caching (storing missing keys) prevents repeated lookups for
    invalid key IDs.
    """

    def get(self, kid: str) -> PyJWK | None:
        """Retrieve a cached signing key by its ID.

        Args:
            kid: Key ID from the JWT header.

        Returns:
            PyJWK object if cached, None if not found.

        Note:
            Check is_missing() to distinguish between "not cached" and
            "cached as missing" (negative caching).
        """
        ...

    def set(self, key: PyJWK, ttl_seconds: int) -> None:
        """Store a signing key in the cache with a TTL.

        Args:
            key: PyJWK object to cache (kid must be in key._jwk_data['kid']).
            ttl_seconds: Time-to-live in seconds. After this duration, the cached
                        entry should be considered expired.
        """
        ...

    def set_missing(self, kid: str, ttl_seconds: int) -> None:
        """Mark a key ID as missing (negative caching).

        Args:
            kid: Key ID that was looked up but not found.
            ttl_seconds: Time-to-live for the negative cache entry.

        Note:
            This prevents repeated failed lookups for non-existent key IDs,
            protecting against certain DoS attacks.
        """
        ...

    def is_missing(self, kid: str) -> bool:
        """Check if a key ID is marked as missing.

        Args:
            kid: Key ID to check.

        Returns:
            True if kid was previously looked up and marked as missing,
            False otherwise.
        """
        ...


class KeyProvider(Protocol):
    """Protocol for resolving JWT signing keys.

    Implementers must provide a get_key_for_token() method that resolves a
    signing key given a key ID (kid) from the JWT header.

    Common implementations:
    - JWKS endpoint fetcher (e.g., Auth0JWKSProvider)
    - Static key loader
    - Database-backed key store
    """

    def get_key_for_token(self, kid: str) -> PyJWK:
        """Resolve a signing key by its ID.

        Args:
            kid: Key ID from the JWT header.

        Returns:
            PyJWK object containing the signing key.

        Raises:
            InvalidToken: If kid cannot be resolved.

        Note:
            Implementations should use caching internally to avoid repeated network
            requests. Consider implementing forced refresh for key rotation scenarios.
        """
        ...


class Authorizer(Protocol):
    """Protocol for RBAC (Role-Based Access Control) implementations.

    Implementers must provide an authorize() method that checks if decoded
    JWT claims satisfy authorization requirements (roles, permissions, etc.).

    This protocol enables flexible authorization strategies while maintaining
    a consistent interface.
    """

    def authorize(
        self,
        claims: Claims,
        *,
        permissions: frozenset[str],
        roles: frozenset[str],
        require_all_permissions: bool,
    ) -> None:
        """Check if claims satisfy authorization requirements.

        Args:
            claims: Decoded JWT claims to check.
            roles: Required roles. If non-empty, user must have at least one.
            permissions: Required permissions.
            require_all_permissions: If True, user must have ALL permissions.
                                    If False (default), user must have ANY permission.

        Raises:
            Forbidden: If authorization requirements are not met.

        Note:
            Implementations must fail closed (raise Forbidden) if requirements cannot
            be evaluated due to missing or malformed claims.
        """
        ...


class Extractor(Protocol):
    """Protocol for extracting JWT tokens from HTTP requests.

    Implementers must provide an extract() method that retrieves the raw JWT
    string from a Flask request context.

    Common implementations:
    - Authorization: Bearer <token> header
    - Cookie-based storage
    - Query parameter (generally discouraged for security)
    """

    def extract(self) -> str:
        """Extract the raw JWT string from the Flask request.

        Returns:
            Raw JWT string.

        Raises:
            MissingToken: Token not found or improperly formatted.

        Security Note:
            Implementations should validate the extraction format (e.g., ensuring
            "Bearer" prefix for Authorization headers) to fail fast on malformed requests.
        """
        ...
