"""
JWT verification and Flask authentication extension.

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

Example usage
-----------

.. code-block:: python

    from jwt_verification import (
        AuthExtension,
        JWTVerifier,
        JWTVerifyOptions,
        Auth0JWKSProvider,
        InMemoryCache,
        RBACAuthorizer,
        ClaimAccess,
        ClaimsMapping,
    )

    # Set up key provider with caching
    cache = InMemoryCache()
    key_provider = Auth0JWKSProvider(
        issuer="https://your-tenant.auth0.com/",
        cache=cache,
        ttl_seconds=600,
    )

    # Set up JWT verifier
    jwt_verifier = JWTVerifier(
        key_provider=key_provider,
        options=JWTVerifyOptions(
            issuer="https://your-tenant.auth0.com/",
            audience="your-api-identifier",
        ),
    )

    # Optional: Set up RBAC
    claims_access = ClaimAccess(
        mapping=ClaimsMapping(
            permissions_claim="permissions",
            roles_claim="roles",
        )
    )
    authorizer = RBACAuthorizer(claims_access)

    # Create Flask extension
    auth = AuthExtension(verifier=jwt_verifier, authorizer=authorizer)

    # Use in routes
    @app.route("/protected")
    @auth.require(roles=["admin"])
    def protected_route():
        return {"message": "Only admins can access this"}
"""

# Authorization
from .authorization import ClaimAccess, ClaimsMapping, RBACAuthorizer

# Cache stores
from .cache_stores import InMemoryCache, RedisCache

# Errors
from .errors import AuthError, ExpiredToken, Forbidden, InvalidToken, MissingToken

# Extractors
from .extractors import BearerExtractor, CookieExtractor

# Flask extension
from .flask_extension import AuthExtension, get_verified_id_claims

# Key providers
from .key_providers import Auth0JWKSProvider

# Protocols
from .protocols import (
    Authorizer,
    CacheStore,
    Claims,
    Extractor,
    KeyProvider,
    TokenVerifier,
    ViewFunc,
)

# Refresh gate
from .refresh_gate import RefreshGate

# Verifier
from .verifier import JWTVerifier, JWTVerifyOptions

__all__ = [
    # Errors
    "AuthError",
    "ExpiredToken",
    "Forbidden",
    "InvalidToken",
    "MissingToken",
    # Protocols
    "Authorizer",
    "CacheStore",
    "Claims",
    "Extractor",
    "KeyProvider",
    "TokenVerifier",
    "ViewFunc",
    # Extractors
    "BearerExtractor",
    "CookieExtractor",
    # Verifier
    "JWTVerifier",
    "JWTVerifyOptions",
    # Refresh gate
    "RefreshGate",
    # Cache stores
    "InMemoryCache",
    "RedisCache",
    # Authorization
    "ClaimAccess",
    "ClaimsMapping",
    "RBACAuthorizer",
    # Key providers
    "Auth0JWKSProvider",
    # Flask extension
    "AuthExtension",
    "get_verified_id_claims",
]
