"""JWT verification implementation using PyJWT.

This module provides a provider-agnostic JWT verifier that:
- Extracts the key ID (kid) from token headers
- Resolves signing keys via an injected KeyProvider
- Validates signatures and claims using PyJWT
- Maps PyJWT exceptions to domain-specific error types

The verifier is the core component that bridges key resolution and actual
cryptographic verification, while remaining independent of any specific
identity provider.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import jwt

from .errors import AuthError, ExpiredToken, InvalidToken
from .protocols import Claims, KeyProvider, TokenVerifier

if TYPE_CHECKING:
    from .protocols import KeyProvider


@dataclass(frozen=True, slots=True)
class JWTVerifyOptions:
    """Configuration for JWT validation rules.

    Attributes:
        issuer: Expected issuer claim. For Auth0, typically
            "https://<your-tenant>.<region>.auth0.com/"
        audience: Expected audience claim. In Auth0, this is the API Identifier.
        algorithms: Tuple of allowed signing algorithms. Default: ("RS256",)
        leeway: Clock skew tolerance in seconds. Default: 0
    """

    issuer: str | None
    audience: str | None
    algorithms: tuple[str, ...] = ("RS256",)
    leeway: int = 0


class JWTVerifier(TokenVerifier):
    """JWT verification using PyJWT with pluggable key resolution.

    Extracts the key ID from token headers, resolves signing keys via a KeyProvider,
    and validates signatures and claims.
    """

    def __init__(
        self,
        key_provider: KeyProvider,
        options: JWTVerifyOptions,
    ) -> None:
        """Initialize the JWT verifier.

        Args:
            key_provider: Provider for resolving signing keys by kid.
            options: JWT validation configuration.
        """
        self._keys = key_provider
        self._opt = options

    def verify(self, token: str) -> Claims:
        """Verify a JWT and return its decoded claims.

        Extracts the kid from token header, resolves the signing key, and validates
        the signature and standard claims using PyJWT.

        Args:
            token: Raw JWT string.

        Returns:
            Claims: Mapping of verified claims from the token payload.

        Raises:
            InvalidToken: If token is malformed, signature is invalid, or kid cannot be resolved.
            ExpiredToken: If token's exp claim has passed.
            AuthError: For any other verification failure.
        """
        try:
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")

            # Validate kid is present and is a string
            if not kid or not isinstance(kid, str):
                raise InvalidToken(
                    "Token header missing required 'kid' claim or 'kid' is not a string"
                )

            key = self._keys.get_key_for_token(kid)

        except AuthError:
            raise
        except Exception as e:
            raise InvalidToken(f"Key resolution failed: {e}") from e

        try:
            decoded_claims = jwt.decode(
                token,
                key,  # PyJWK object is directly usable by jwt.decode
                algorithms=list(self._opt.algorithms),  # Explicit allowlist
                audience=self._opt.audience,
                issuer=self._opt.issuer,
                leeway=self._opt.leeway,  # Clock skew tolerance
            )

            return decoded_claims

        except jwt.ExpiredSignatureError as e:
            raise ExpiredToken("Token has expired") from e

        except jwt.InvalidTokenError as e:
            raise InvalidToken(f"Token validation failed: {e}") from e
