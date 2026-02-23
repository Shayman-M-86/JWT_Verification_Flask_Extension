"""
Tests for Role-Based Access Control (RBAC).

Tests permission and role claim extraction and authorization.
"""

import pytest

import src.extension.jwt_verification as m


class TestPermissionExtraction:
    """Test permission extraction from claims."""

    def test_claim_access_permissions_from_string(self):
        """Should parse space-separated permissions from string."""
        ca = m.ClaimAccess(m.ClaimsMapping(permissions_claim="permissions"))
        claims = {"permissions": "read:a write:b"}
        assert ca.permissions(claims) == frozenset({"read:a", "write:b"})

    def test_claim_access_permissions_from_list(self):
        """Should extract permissions from list, filtering non-strings."""
        ca = m.ClaimAccess(m.ClaimsMapping(permissions_claim="permissions"))
        claims: dict[str, list[str | int]] = {"permissions": ["read:a", "write:b", 123]}
        assert ca.permissions(claims) == frozenset({"read:a", "write:b"})

    def test_claim_access_permissions_empty(self):
        """Should return empty frozenset when no permissions."""
        ca = m.ClaimAccess(m.ClaimsMapping(permissions_claim="permissions"))
        claims: dict[str, list[str]] = {}
        assert ca.permissions(claims) == frozenset()


class TestRBACAuthorization:
    """Test RBAC authorization logic."""

    def test_rbac_roles_denied(self):
        """Should deny access when required role missing."""
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

    def test_rbac_roles_allowed(self):
        """Should allow access when required role present."""
        ca = m.ClaimAccess(m.ClaimsMapping(roles_claim="roles"))
        authz = m.RBACAuthorizer(ca)
        claims = {"roles": ["user", "admin"]}

        # Should not raise
        authz.authorize(
            claims,
            permissions=frozenset(),
            roles=frozenset({"admin"}),
            require_all_permissions=True,
        )


class TestPermissionAuthorization:
    """Test permission-based authorization."""

    def test_rbac_permissions_all_required_denied(self):
        """Should deny when not all required permissions present."""
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

    def test_rbac_permissions_all_required_allowed(self):
        """Should allow when all required permissions present."""
        ca = m.ClaimAccess(m.ClaimsMapping(permissions_claim="permissions"))
        authz = m.RBACAuthorizer(ca)
        claims = {"permissions": ["read:a", "write:a", "delete:a"]}

        # Should not raise
        authz.authorize(
            claims,
            permissions=frozenset({"read:a", "write:a"}),
            roles=frozenset(),
            require_all_permissions=True,
        )

    def test_rbac_permissions_any_required_denied(self):
        """Should deny when no matching permission found."""
        ca = m.ClaimAccess(m.ClaimsMapping(permissions_claim="permissions"))
        authz = m.RBACAuthorizer(ca)
        claims = {"permissions": ["read:a"]}

        with pytest.raises(m.Forbidden):
            authz.authorize(
                claims,
                permissions=frozenset({"write:b", "delete:b"}),
                roles=frozenset(),
                require_all_permissions=False,
            )

    def test_rbac_permissions_any_required_allowed(self):
        """Should allow when at least one permission matches."""
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


class TestMultipleRolesAndPermissions:
    """Test combined role and permission checks."""

    def test_rbac_both_roles_and_permissions_allowed(self):
        """Should allow when both roles and permissions match."""
        ca = m.ClaimAccess(
            m.ClaimsMapping(roles_claim="roles", permissions_claim="permissions")
        )
        authz = m.RBACAuthorizer(ca)
        claims = {
            "roles": ["user", "moderator"],
            "permissions": ["read:posts", "write:posts"],
        }

        # Both checks should pass
        authz.authorize(
            claims,
            permissions=frozenset({"read:posts"}),
            roles=frozenset({"moderator"}),
            require_all_permissions=False,
        )

    def test_rbac_missing_role_fails(self):
        """Should fail if role check fails even with good permissions."""
        ca = m.ClaimAccess(
            m.ClaimsMapping(roles_claim="roles", permissions_claim="permissions")
        )
        authz = m.RBACAuthorizer(ca)
        claims = {"roles": ["user"], "permissions": ["read:posts", "write:posts"]}

        with pytest.raises(m.Forbidden):
            authz.authorize(
                claims,
                permissions=frozenset({"read:posts"}),
                roles=frozenset({"admin"}),  # Missing role
                require_all_permissions=False,
            )
