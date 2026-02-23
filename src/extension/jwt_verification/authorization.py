"""
Claims access and role-based access control (RBAC) authorization.
"""

from dataclasses import dataclass
from typing import FrozenSet, Optional, Sequence, cast

from .errors import Forbidden
from .protocols import Authorizer, Claims


@dataclass(frozen=True, slots=True)
class ClaimsMapping:
    """
    Maps "where" roles/permissions live in the JWT.

    For Auth0:
    - permissions are often in "permissions" if RBAC is enabled + added to access token
    - roles are often a custom namespaced claim (e.g. "https://yourapp/roles")
      In that case, set roles_claim to that namespace.
    """

    permissions_claim: str = "permissions"
    roles_claim: str = "roles"
    single_role_claim: Optional[str] = None


class ClaimAccess:
    """
    Normalizes raw claims into strongly-typed role/permission sets.
    """

    def __init__(self, mapping: ClaimsMapping) -> None:
        self._m = mapping

    def permissions(self, claims: Claims) -> FrozenSet[str]:
        raw = claims.get(self._m.permissions_claim, [])
        if isinstance(raw, str):
            # supports "read:foo write:bar" style
            return frozenset(raw.split())
        if isinstance(raw, (list, tuple, set, frozenset)):
            raw_seq = cast(Sequence[object], raw)
            cleaned = [item for item in raw_seq if isinstance(item, str)]
            return frozenset(cleaned)
        return frozenset()

    def roles(self, claims: Claims) -> FrozenSet[str]:
        roles: set[str] = set()

        if self._m.single_role_claim:
            r = claims.get(self._m.single_role_claim)
            if isinstance(r, str):
                roles.add(r)

        raw = claims.get(self._m.roles_claim, [])
        if isinstance(raw, str):
            roles.add(raw)
        elif isinstance(raw, (list, tuple, set, frozenset)):
            raw_seq = cast(Sequence[object], raw)
            roles.update(item for item in raw_seq if isinstance(item, str))

        return frozenset(roles)


class RBACAuthorizer(Authorizer):
    """
    Enforces role/permission requirements against verified claims.

    - roles: user must have at least one of required roles
    - permissions: depending on `require_all_permissions`, must have all or any
    """

    def __init__(self, claims: ClaimAccess) -> None:
        self._claims = claims

    def authorize(
        self,
        claims: Claims,
        *,
        permissions: FrozenSet[str],
        roles: FrozenSet[str],
        require_all_permissions: bool,
    ) -> None:
        if roles:
            user_roles = self._claims.roles(claims)
            if not user_roles.intersection(roles):
                raise Forbidden

        if permissions:
            user_perms = self._claims.permissions(claims)

            if require_all_permissions:
                if not permissions.issubset(user_perms):
                    raise Forbidden
            else:
                if not permissions.intersection(user_perms):
                    raise Forbidden
