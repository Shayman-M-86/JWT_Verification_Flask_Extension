"""Claims access and role-based access control (RBAC) authorization.

This module provides secure, fail-closed authorization mechanisms for extracting
and validating role-based and permission-based access control from JWT claims.

Security Notes
--------------
All claim extraction functions implement fail-closed security: malformed or
unexpected claim formats result in empty sets rather than errors, ensuring
that authorization checks deny access by default.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import cast

from .errors import Forbidden
from .protocols import Authorizer, Claims


@dataclass(frozen=True, slots=True)
class ClaimsMapping:
    """Configuration mapping for role and permission claim locations in JWT.

    Defines where to find authorization data within the JWT claims structure.
    Different identity providers and configurations may store roles and
    permissions in different claim keys.

    Attributes:
        permissions_claim: The claim key containing user permissions.
            Default is "permissions" (standard for Auth0 with RBAC enabled).
        roles_claim: The claim key containing user roles as a list.
            Default is "roles". For Auth0, this is often a namespaced claim
            like "https://yourapp.com/roles".
        single_role_claim: Optional claim key containing a single role string.
            Use when your JWT includes both list-based and single-value role claims.
            Set to None if not applicable.

    Examples:
        Standard Auth0 configuration:
            >>> mapping = ClaimsMapping(
            ...     permissions_claim="permissions",
            ...     roles_claim="https://yourapp.com/roles"
            ... )

        Configuration with both single and multiple roles:
            >>> mapping = ClaimsMapping(
            ...     roles_claim="roles",
            ...     single_role_claim="primary_role"
            ... )

    Security Notes:
        - Claim keys should match your identity provider's configuration exactly.
        - Using namespaced claims (e.g., "https://yourapp.com/roles") prevents
          conflicts with standard JWT claims.
        - Misconfigured claim keys result in empty authorization sets (fail-closed).
    """

    permissions_claim: str = "permissions"
    roles_claim: str = "roles"
    single_role_claim: str | None = None


class ClaimAccess:
    """Extracts and normalizes role and permission data from JWT claims.

    This class provides secure, type-safe extraction of authorization data
    from verified JWT claims. It handles various claim formats and ensures
    consistent frozenset outputs for authorization decisions.

    Security Notes:
        - All extraction methods are fail-closed: unexpected formats return
          empty frozensets, causing authorization to deny access.
        - Only string values are extracted from claims; other types are ignored.
        - Malformed claims do not raise exceptions to avoid information disclosure.

    Args:
        mapping: Configuration defining where roles/permissions are located
            in the JWT claims structure.

    Examples:
        >>> mapping = ClaimsMapping(permissions_claim="permissions")
        >>> accessor = ClaimAccess(mapping)
        >>> claims = {"permissions": ["read:data", "write:data"]}
        >>> accessor.permissions(claims)
        frozenset({'read:data', 'write:data'})
    """

    def __init__(self, mapping: ClaimsMapping) -> None:
        """Initialize the claim accessor with a claims mapping configuration.

        Args:
            mapping: Defines which claim keys contain roles and permissions.
        """
        self._m = mapping

    def permissions(self, claims: Claims) -> frozenset[str]:
        """Extract permissions from JWT claims.

        Supports multiple permission claim formats:
        - List/tuple/set of strings: ["read:foo", "write:bar"]
        - Space-separated string: "read:foo write:bar"
        - Single string: "read:foo"

        Args:
            claims: Verified JWT claims dictionary.

        Returns:
            Immutable set of permission strings. Returns empty frozenset if:
            - The claim is missing
            - The claim has an unexpected type
            - The claim contains no valid string values

        Security Notes:
            - Non-string items in sequences are silently ignored (fail-closed).
            - Missing or malformed claims return empty set, causing denial.
            - No exceptions are raised to avoid leaking claim structure info.

        Examples:
            >>> accessor.permissions({"permissions": ["read:data", "write:data"]})
            frozenset({'read:data', 'write:data'})

            >>> accessor.permissions({"permissions": "read:foo write:bar"})
            frozenset({'read:foo', 'write:bar'})

            >>> accessor.permissions({"permissions": ["read", 123, "write"]})
            frozenset({'read', 'write'})  # Non-strings filtered out

            >>> accessor.permissions({})
            frozenset()  # Missing claim returns empty set
        """
        raw = claims.get(self._m.permissions_claim, [])

        if isinstance(raw, str):
            return frozenset(raw.split())

        if isinstance(raw, (list, tuple, set, frozenset)):
            raw_seq = cast(Sequence[object], raw)
            cleaned = [item for item in raw_seq if isinstance(item, str)]
            return frozenset(cleaned)

        # Fail-closed: unexpected types return empty set
        return frozenset()

    def roles(self, claims: Claims) -> frozenset[str]:
        """Extract roles from JWT claims.

        Supports extracting roles from both list-based and single-value claims.
        If both single_role_claim and roles_claim are configured, roles from
        both sources are combined.

        Args:
            claims: Verified JWT claims dictionary.

        Returns:
            Immutable set of role strings. Returns empty frozenset if:
            - All configured role claims are missing
            - All role claims have unexpected types
            - The claims contain no valid string values

        Security Notes:
            - Non-string items in sequences are silently ignored (fail-closed).
            - Missing or malformed claims return empty set, causing denial.
            - No exceptions are raised to avoid leaking claim structure info.
            - Multiple role sources are combined with set union.

        Examples:
            >>> mapping = ClaimsMapping(roles_claim="roles")
            >>> accessor = ClaimAccess(mapping)
            >>> accessor.roles({"roles": ["admin", "user"]})
            frozenset({'admin', 'user'})

            >>> accessor.roles({"roles": "admin"})
            frozenset({'admin'})

            >>> mapping = ClaimsMapping(
            ...     roles_claim="roles",
            ...     single_role_claim="primary_role"
            ... )
            >>> accessor = ClaimAccess(mapping)
            >>> accessor.roles({"roles": ["user"], "primary_role": "admin"})
            frozenset({'admin', 'user'})

            >>> accessor.roles({})
            frozenset()  # Missing claims return empty set
        """
        roles: set[str] = set()

        # Extract from single role claim if configured
        if self._m.single_role_claim:
            r = claims.get(self._m.single_role_claim)
            if isinstance(r, str):
                roles.add(r)

        raw = claims.get(self._m.roles_claim, [])

        if isinstance(raw, str):
            roles.add(raw)
        elif isinstance(raw, (list, tuple, set, frozenset)):
            raw_seq = cast(Sequence[object], raw)
            # Filter to only string values for security (fail-closed)
            roles.update(item for item in raw_seq if isinstance(item, str))
        # Unexpected types are silently ignored (fail-closed)

        return frozenset(roles)


class RBACAuthorizer(Authorizer):
    """Role-Based Access Control (RBAC) authorizer implementation.
    """

    def __init__(self, claims: ClaimAccess) -> None:
        """Initialize the RBAC authorizer with a claim accessor.

        Args:
            claims (ClaimAccess): Instance for extracting roles and permissions from claims.
        """
        self._claims = claims

    def authorize(
        self,
        claims: Claims,
        *,
        permissions: frozenset[str],
        roles: frozenset[str],
        require_all_permissions: bool,
    ) -> None:
        """Authorize access based on role and permission requirements.

        Args:
            claims (Claims): Verified JWT claims dictionary containing authorization data.
            permissions (frozenset[str]): Set of permissions required for access.
            roles (frozenset[str]): Set of roles required for access (any-of semantics).
            require_all_permissions (bool): If True, all permissions are required;
                                            if False, any permission is sufficient.

        Raises:
            Forbidden: If the claims do not satisfy the required roles and permissions.
        """
        # Enforce role requirements (any-of semantics)
        if roles:
            user_roles = self._claims.roles(claims)
            # User must have at least one of the required roles
            if not user_roles.intersection(roles):
                raise Forbidden("User does not have required roles")

        if permissions:
            user_perms = self._claims.permissions(claims)

            if require_all_permissions:
                if not permissions.issubset(user_perms):
                    raise Forbidden("User does not have all required permissions")
            else:
                if not permissions.intersection(user_perms):
                    raise Forbidden("User does not have any of the required permissions")
