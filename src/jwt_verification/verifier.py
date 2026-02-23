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
from .protocols import Claims

if TYPE_CHECKING:
    from .protocols import KeyProvider


@dataclass(frozen=True, slots=True)
class JWTVerifyOptions:
    """Configuration for JWT validation rules.

    These options define what constitutes a valid token for your application.
    Misconfiguration can lead to security vulnerabilities, so validate carefully.

    Attributes:
        issuer: Expected `iss` (issuer) claim. For Auth0, typically
            "https://<your-tenant>.<region>.auth0.com/" (note trailing slash).
            If None, issuer is not validated (not recommended for production).

        audience: Expected `aud` (audience) claim. In Auth0, this is your
            API Identifier. Can be a single string or a list. If None, audience
            is not validated (not recommended for production).

        algorithms: Tuple of allowed signing algorithms. MUST be an explicit
            allowlist to prevent algorithm confusion attacks. RS256 is standard
            for Auth0. Never use 'none'. Default: ("RS256",)

        leeway: Clock skew tolerance in seconds for exp/nbf/iat validation.
            Accommodates minor time differences between systems. Don't set too
            high as it weakens expiration enforcement. Default: 0 (no leeway).

    Security Invariants:
        - Never allow algorithm='none' (PyJWT rejects this by default, but be aware)
        - Always validate iss and aud in production
        - Use RS256 or stronger asymmetric algorithms for API tokens
        - Keep leeway minimal (<30 seconds) to maintain tight expiration enforcement
        - Validate these options match your identity provider's configuration

    Example:
        ```python
        # Auth0 configuration
        options = JWTVerifyOptions(
            issuer="https://dev-abc123.us.auth0.com/",
            audience="https://api.example.com",
            algorithms=("RS256",),
            leeway=10  # 10 second clock skew tolerance
        )

        verifier = JWTVerifier(
            key_provider=auth0_provider,
            options=options
        )
        ```
    """

    issuer: str | None
    audience: str | None
    algorithms: tuple[str, ...] = ("RS256",)
    leeway: int = 0


class JWTVerifier:
    """Provider-agnostic JWT verification using PyJWT.

    This class implements the TokenVerifier protocol and delegates key resolution
    to an injected KeyProvider. This separation allows the verifier to remain
    provider-agnostic while supporting different key sources (JWKS endpoints,
    static keys, databases, etc.).

    Architecture:
        1. Extract kid from token header (unverified)
        2. Resolve signing key via KeyProvider
        3. Verify signature and claims via PyJWT
        4. Map exceptions to domain errors

    Thread Safety:
        This class is thread-safe assuming the KeyProvider is thread-safe.
        The JWTVerifyOptions are frozen and immutable.

    Example:
        ```python
        provider = Auth0JWKSProvider(
            domain="dev-abc123.us.auth0.com",
            cache_store=InMemoryCache()
        )

        options = JWTVerifyOptions(
            issuer="https://dev-abc123.us.auth0.com/",
            audience="https://api.example.com",
            algorithms=("RS256",),
            leeway=10
        )

        verifier = JWTVerifier(key_provider=provider, options=options)

        # Later, in a request handler:
        try:
            claims = verifier.verify(raw_token)
            user_id = claims.get("sub")
        except ExpiredToken:
            # Token expired, prompt re-authentication
        except InvalidToken:
            # Token invalid, reject request
        ```

    Attributes:
        _keys: KeyProvider responsible for resolving signing keys.
        _opt: Immutable verification options (issuer, audience, algorithms, leeway).
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

        Security Note:
            The options object defines your security policy. Invalid configuration
            can compromise security. Ensure issuer, audience, and algorithms are
            correctly set for your environment.
        """
        self._keys = key_provider
        self._opt = options

    def verify(self, token: str) -> Claims:
        """Verify a JWT and return its decoded claims.

        This method:
        1. Extracts kid from token header (without signature verification)
        2. Resolves the signing key via KeyProvider
        3. Verifies signature and validates claims via PyJWT
        4. Returns immutable claims mapping on success

        Args:
            token: Raw JWT string (typically from Authorization: Bearer header).

        Returns:
            Mapping of verified claims from the token payload. Common claims:
                - sub: Subject (user ID)
                - iss: Issuer
                - aud: Audience
                - exp: Expiration time (Unix timestamp)
                - iat: Issued at time (Unix timestamp)
                - Custom claims (roles, permissions, etc.)

        Raises:
            InvalidToken: If token is malformed, signature is invalid, claims
                         validation fails, or kid cannot be resolved.
            ExpiredToken: If token's exp claim has passed (accounting for leeway).
            AuthError: For any other verification failure.

        Security Notes:
            - Signature verification prevents token tampering
            - Claims validation ensures tokens are used correctly (right iss/aud)
            - Algorithm allowlist prevents algorithm confusion attacks
            - Leeway accommodates clock skew but should be minimal
            - Returned claims should be treated as untrusted for authz decisions
              (always validate roles/permissions against requirements)

        Implementation Details:
            - Uses jwt.get_unverified_header() safely (only for kid extraction)
            - Normalizes PyJWT exceptions to domain-specific error types
            - Preserves exception chains for debugging
        """
        # Step 1: Extract kid from token header (cheap, no crypto)
        # This is safe because we don't trust the header - just need the kid
        # to know which key to use for verification.
        try:
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")

            # Validate kid is present and is a string
            if not kid or not isinstance(kid, str):
                raise InvalidToken(
                    "Token header missing required 'kid' claim or 'kid' is not a string"
                )

            # Resolve the signing key
            key = self._keys.get_key_for_token(kid)

        except AuthError:
            # Preserve domain errors (like InvalidToken from KeyProvider)
            raise
        except Exception as e:
            # Normalize unexpected errors to InvalidToken
            raise InvalidToken(f"Key resolution failed: {e}") from e

        # Step 2: Verify signature + validate claims
        # PyJWT does the heavy lifting here: signature verification, exp/nbf/iat
        # validation, issuer/audience checks, etc.
        try:
            decoded_claims = jwt.decode(
                token,
                key,  # PyJWK object is directly usable by jwt.decode
                algorithms=list(self._opt.algorithms),  # Explicit allowlist
                audience=self._opt.audience,
                issuer=self._opt.issuer,
                leeway=self._opt.leeway,  # Clock skew tolerance
            )

            # Mypy hint: jwt.decode returns dict[str, Any], which satisfies Claims
            return decoded_claims

        except jwt.ExpiredSignatureError as e:
            # Map PyJWT's ExpiredSignatureError to our domain error
            raise ExpiredToken("Token has expired") from e

        except jwt.InvalidTokenError as e:
            # Catch-all for other PyJWT validation failures:
            # - Invalid signature
            # - Invalid claims (iss, aud mismatch)
            # - Malformed token structure
            # - Algorithm not in allowlist
            # - etc.
            raise InvalidToken(f"Token validation failed: {e}") from e
