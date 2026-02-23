"""
Tests for the AuthExtension Flask integration.

Tests the decorator-based JWT verification and authorization.
"""

from typing import Any

from flask import Flask, g

import src.extension.JWT_verification as m


class OkVerifier(m.TokenVerifier):
    """Mock TokenVerifier that accepts 'GOOD' tokens."""

    def verify(self, token: str) -> dict[str, Any]:
        if token != "GOOD":
            raise m.InvalidToken("Invalid token")
        return {
            "sub": "u1",
            "permissions": ["read:a"],
            "roles": ["user"],
            "email": "user@example.com",
            "email_verified": True,
        }


class DenyAuthorizer(m.Authorizer):
    """Mock Authorizer that always denies."""

    def authorize(
        self,
        claims: m.Claims,
        *,
        permissions: frozenset[str],
        roles: frozenset[str],
        require_all_permissions: bool,
    ) -> None:
        raise m.Forbidden()


class PassAuthorizer(m.Authorizer):
    """Mock Authorizer that always allows."""

    def authorize(
        self,
        claims: m.Claims,
        *,
        permissions: frozenset[str],
        roles: frozenset[str],
        require_all_permissions: bool,
    ) -> None:
        return None


class TestAuthExtensionBasics:
    """Test basic AuthExtension functionality."""

    def test_auth_extension_missing_token_returns_401(self, app: Flask):
        """Missing token should return 401."""
        auth = m.AuthExtension(verifier=OkVerifier())

        @app.get("/x")
        @auth.require()
        def x():  # type: ignore
            return {"ok": True}

        c = app.test_client()
        r = c.get("/x")
        assert r.status_code == 401

    def test_auth_extension_invalid_token_returns_401(self, app: Flask):
        """Invalid token should return 401."""
        auth = m.AuthExtension(verifier=OkVerifier())

        @app.get("/x")
        @auth.require()
        def x():  # type: ignore
            return {"ok": True}

        c = app.test_client()
        r = c.get("/x", headers={"Authorization": "Bearer BAD"})
        assert r.status_code == 401


class TestAuthExtensionWithAuthorization:
    """Test AuthExtension with authorization."""

    def test_auth_extension_sets_g_jwt_and_allows(self, app: Flask):
        """Valid token should set g.jwt and allow access."""
        authz = PassAuthorizer()
        auth = m.AuthExtension(verifier=OkVerifier(), authorizer=authz)

        @app.get("/x")
        @auth.require(permissions=["read:a"])
        def x():  # type: ignore
            return {"sub": g.jwt["sub"], "email": g.jwt.get("email")}

        c = app.test_client()
        r = c.get("/x", headers={"Authorization": "Bearer GOOD"})
        assert r.status_code == 200
        data = r.get_json()
        assert data["sub"] == "u1"
        assert data["email"] == "user@example.com"

    def test_auth_extension_forbidden_returns_403(self, app: Flask):
        """Authorization failure should return 403."""
        auth = m.AuthExtension(verifier=OkVerifier(), authorizer=DenyAuthorizer())

        @app.get("/x")
        @auth.require(roles=["admin"])
        def x():  # type: ignore
            return {"ok": True}

        c = app.test_client()
        r = c.get("/x", headers={"Authorization": "Bearer GOOD"})
        assert r.status_code == 403


class TestAuthExtensionWithRoles:
    """Test AuthExtension with role-based access control."""

    def test_auth_extension_role_check_passes(self, app: Flask):
        """User with correct role should have access."""
        authz = PassAuthorizer()
        auth = m.AuthExtension(verifier=OkVerifier(), authorizer=authz)

        @app.get("/user")
        @auth.require(roles=["user"])
        def user_endpoint():  # type: ignore
            return {"message": "user access granted"}

        c = app.test_client()
        r = c.get("/user", headers={"Authorization": "Bearer GOOD"})
        assert r.status_code == 200

    def test_auth_extension_permission_check_passes(self, app: Flask):
        """User with correct permission should have access."""
        authz = PassAuthorizer()
        auth = m.AuthExtension(verifier=OkVerifier(), authorizer=authz)

        @app.get("/read")
        @auth.require(permissions=["read:a"])
        def read_endpoint():  # type: ignore
            return {"message": "read access granted"}

        c = app.test_client()
        r = c.get("/read", headers={"Authorization": "Bearer GOOD"})
        assert r.status_code == 200


class TestAuthExtensionClaimsAccess:
    """Test accessing claims from g.jwt."""

    def test_can_access_all_claims(self, app: Flask):
        """All JWT claims should be accessible via g.jwt."""
        authz = PassAuthorizer()
        auth = m.AuthExtension(verifier=OkVerifier(), authorizer=authz)

        @app.get("/claims")
        @auth.require()
        def claims_endpoint():  # type: ignore
            return {
                "sub": g.jwt["sub"],
                "roles": g.jwt["roles"],
                "permissions": g.jwt["permissions"],
                "email": g.jwt["email"],
                "email_verified": g.jwt["email_verified"],
            }

        c = app.test_client()
        r = c.get("/claims", headers={"Authorization": "Bearer GOOD"})
        assert r.status_code == 200
        data = r.get_json()
        assert data["sub"] == "u1"
        assert "user" in data["roles"]
        assert "read:a" in data["permissions"]
        assert data["email"] == "user@example.com"
        assert data["email_verified"] is True
