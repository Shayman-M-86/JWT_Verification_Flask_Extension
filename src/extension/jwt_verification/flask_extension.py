"""
Flask extension for JWT authentication and authorization.
"""

from functools import wraps
from typing import Any, Sequence

from flask import Flask, abort, g, request

from .errors import ExpiredToken, Forbidden, InvalidToken, MissingToken
from .extractors import BearerExtractor
from .protocols import Authorizer, Extractor, TokenVerifier, ViewFunc

_EXT_KEY = "auth_extension"


class AuthExtension:
    """
    Flask decorator glue for JWT authentication.

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
        extractor: Extractor | None = None,
    ) -> None:
        self._verifier: TokenVerifier = verifier
        self._authorizer: Authorizer | None = authorizer
        self._extractor: Extractor = extractor or BearerExtractor()

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
):
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
