"""
Generic JWT verifier (provider-agnostic).
"""

from dataclasses import dataclass
from typing import Optional

import jwt

from .errors import AuthError, ExpiredToken, InvalidToken
from .protocols import Claims, KeyProvider, TokenVerifier


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
            key = self._keys.get_key_for_token(kid)
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
