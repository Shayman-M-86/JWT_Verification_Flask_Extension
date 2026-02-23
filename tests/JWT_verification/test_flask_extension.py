from typing import Any

from flask import Flask, g

import src.extension.JWT_verification as m


class OkVerifier(m.TokenVerifier):
    def verify(self, token: str) -> dict[str, Any]:
        assert token == "GOOD"
        return {"sub": "u1", "permissions": ["read:a"], "roles": ["user"]}


class DenyAuthorizer(m.Authorizer):
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
    def authorize(
        self,
        claims: m.Claims,
        *,
        permissions: frozenset[str],
        roles: frozenset[str],
        require_all_permissions: bool,
    ) -> None:
        return None


def test_auth_extension_missing_token_returns_401(app: Flask):
    auth = m.AuthExtension(verifier=OkVerifier())

    @app.get("/x")
    @auth.require()
    def x():  # type: ignore
        return {"ok": True}

    c = app.test_client()
    r = c.get("/x")
    assert r.status_code == 401


def test_auth_extension_sets_g_and_allows(app: Flask):
    authz = PassAuthorizer()
    auth = m.AuthExtension(verifier=OkVerifier(), authorizer=authz)

    @app.get("/x")
    @auth.require(permissions=["read:a"])
    def x():  # type: ignore
        return {"sub": g.jwt["sub"]}

    c = app.test_client()
    r = c.get("/x", headers={"Authorization": "Bearer GOOD"})
    assert r.status_code == 200
    assert r.get_json()["sub"] == "u1"


def test_auth_extension_forbidden_returns_403(app: Flask):
    auth = m.AuthExtension(verifier=OkVerifier(), authorizer=DenyAuthorizer())

    @app.get("/x")
    @auth.require(roles=["admin"])
    def x():  # type: ignore
        return {"ok": True}

    c = app.test_client()
    r = c.get("/x", headers={"Authorization": "Bearer GOOD"})
    assert r.status_code == 403
