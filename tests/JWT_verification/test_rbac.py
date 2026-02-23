import pytest
import src.extension.JWT_verification as m


def test_claim_access_permissions_from_string():
    ca = m.ClaimAccess(m.ClaimsMapping(permissions_claim="permissions"))
    claims = {"permissions": "read:a write:b"}
    assert ca.permissions(claims) == frozenset({"read:a", "write:b"})


def test_claim_access_permissions_from_list():
    ca = m.ClaimAccess(m.ClaimsMapping(permissions_claim="permissions"))
    claims: dict[str, list[str | int]] = {"permissions": ["read:a", "write:b", 123]}
    assert ca.permissions(claims) == frozenset({"read:a", "write:b"})


def test_rbac_roles_denied():
    ca = m.ClaimAccess(m.ClaimsMapping(roles_claim="roles"))
    authz = m.RBACAuthorizer(ca)
    claims = {"roles": ["user"]}

    with pytest.raises(m.Forbidden):
        authz.authorize(
            claims,
            permissions=frozenset(),
            roles=frozenset({"admin"}),
            require_all_permissions=True,
        )


def test_rbac_permissions_all_required():
    ca = m.ClaimAccess(m.ClaimsMapping(permissions_claim="permissions"))
    authz = m.RBACAuthorizer(ca)
    claims = {"permissions": ["read:a"]}

    with pytest.raises(m.Forbidden):
        authz.authorize(
            claims,
            permissions=frozenset({"read:a", "write:a"}),
            roles=frozenset(),
            require_all_permissions=True,
        )


def test_rbac_permissions_any_required():
    ca = m.ClaimAccess(m.ClaimsMapping(permissions_claim="permissions"))
    authz = m.RBACAuthorizer(ca)
    claims = {"permissions": ["read:a"]}

    # require_all_permissions=False means any match is enough
    authz.authorize(
        claims,
        permissions=frozenset({"read:a", "write:a"}),
        roles=frozenset(),
        require_all_permissions=False,
    )
