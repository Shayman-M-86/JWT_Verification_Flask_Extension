"""Flask extension for JWT authentication and authorization.

This module provides the main integration point between the JWT verification
extension and Flask applications. It implements a decorator-based approach
for protecting routes with authentication and authorization requirements.

Key Components:
- AuthExtension: Main decorator class for protecting Flask routes
- get_verified_id_claims: Utility for verifying ID tokens from cookies

Security Model:
1. Extract token from request (header or cookie)
2. Verify token signature and claims
3. Store verified claims in flask.g.jwt for route access
4. Optionally enforce RBAC requirements (roles/permissions)
5. Convert auth errors to appropriate HTTP responses (401/403)
"""

from __future__ import annotations

from collections.abc import Sequence
from functools import wraps
from typing import TYPE_CHECKING, Any, Final

from flask import Flask, abort, g, request

from .errors import AuthError
from .extractors import BearerExtractor

if TYPE_CHECKING:
    from .protocols import Authorizer, Claims, Extractor, TokenVerifier, ViewFunc

_EXT_KEY: Final[str] = "auth_extension"
"""Flask extensions registry key for AuthExtension."""


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
        """Initialize the Flask app with the AuthExtension.

        Args:
            app (Flask): The Flask application instance.
            verifier (TokenVerifier | None, optional): Token verifier instance. Defaults to None.
            authorizer (Authorizer | None, optional): Authorizer instance. Defaults to None.
            extractor (Extractor | None, optional): Token extractor instance. Defaults to None.
        """
        if verifier is not None:
            self._verifier = verifier
        if authorizer is not None:
            self._authorizer = authorizer
        if extractor is not None:
            self._extractor = extractor

        app.extensions[_EXT_KEY] = self

    def require(
        self,
        *,
        permissions: Sequence[str] = (),
        roles: Sequence[str] = (),
        require_all_permissions: bool = True,
    ):
        """Decorator to protect Flask routes with JWT authentication and optional RBAC.

        Verification behavior:
        - Extract token using configured extractor
        - Verify token using configured verifier (signature + claims)
        - On success: Store decoded claims in `flask.g.jwt` and call the view

        Authorization behavior:
        - If an authorizer is configured, call it with the decoded claims and
          specified permissions/roles.
        - If ``self._authorizer`` is ``None``, only authentication is enforced
            (no permission/role checks).
        - Permission matching strategy is controlled by
            ``require_all_permissions``:
            - ``True``: caller must satisfy *all* listed permissions.
            - ``False``: caller must satisfy *at least one* listed permission.

        Error mapping:
        - ``MissingToken``  -> HTTP 401 (\"Missing token\")
        - ``ExpiredToken``  -> HTTP 401 (\"Expired token\")
        - ``InvalidToken``  -> HTTP 401 (\"Invalid token: <reason>\")
        - ``Forbidden``     -> HTTP 403 (\"Forbidden\")
        - Any other Error   -> HTTP 401 (\"Authentication failed\")
        -
        Args:
                permissions (Sequence[str], optional):
                        Permission identifiers required to access the endpoint.
                        Defaults to an empty sequence (no permission requirement unless
                        enforced by external authorizer policy).
                roles (Sequence[str], optional):
                        Role identifiers required to access the endpoint.
                        Defaults to an empty sequence.
                require_all_permissions (bool, optional):
                        Controls whether all permissions are required (AND) or any single
                        permission is sufficient (OR). Defaults to ``True``.
        Returns:
        Callable[[ViewFunc], ViewFunc]:
                        A decorator that wraps a Flask view function with JWT
                        authentication/authorization checks.
        Side Effects:
                - Writes decoded JWT claims to ``flask.g.jwt`` before calling the view.
                - May terminate request handling early via ``flask.abort``.
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

                except AuthError as e:
                    abort(e.error_code, description=e.description)
                except Exception:
                    abort(401, description="Authentication failed")

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
        abort(401, description="Missing token")
    try:
        claims: Claims = verifier.verify(token)
    except AuthError as e:
        abort(e.error_code, description=e.description)
    except Exception:
        abort(401, description="Authentication failed")
    return claims
