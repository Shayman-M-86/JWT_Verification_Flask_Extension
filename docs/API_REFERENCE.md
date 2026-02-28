# API Reference

## Core Classes

### AuthExtension

Main Flask integration layer.

```python
AuthExtension(
    verifier,
    authorizer=None,
    extractor=None
)
```

Decorator:

```python
@auth.require(
    roles=None,
    permissions=None,
    require_all_permissions=True
)
```

---

### JWTVerifier

Handles signature and claims validation.

```python
JWTVerifier(
    key_provider,
    options
)
```

---

### JWTVerifyOptions

Fields:

- issuer
- audience
- leeway
- algorithms

---

### Auth0JWKSProvider

Retrieves signing keys from JWKS endpoint.

```python
Auth0JWKSProvider(
    issuer,
    cache=None,
    ttl_seconds=3600
)
```

---

### RBACAuthorizer

Role and permission validation.

```python
RBACAuthorizer(access)
```

---

### ClaimsMapping

Maps token claims.

```python
ClaimsMapping(
    permissions_claim="permissions",
    roles_claim="roles"
)
```

---

## Exceptions

- AuthError
- MissingToken
- InvalidToken
- ExpiredToken
- Forbidden

---

## Utilities

- get_verified_id_claims()

---

## Cache Implementations

- InMemoryCache
- RedisCache

