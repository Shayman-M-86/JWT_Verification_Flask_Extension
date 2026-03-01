# Security Overview

This extension focuses on secure JWT verification and authorization.

---

## Core Protections

### Signature Verification

All tokens are verified using public keys from the identity provider.

Prevents:

- Token forgery
- Token tampering
- Unauthorized issuers

---

### Issuer Validation

Ensures tokens originate from the expected identity provider.

---

### Audience Validation

Ensures tokens are intended for this API.

---

### Algorithm Allow‑List

Only trusted algorithms are accepted.

Prevents algorithm confusion attacks.

---

### Expiration Enforcement

Expired tokens are rejected automatically.

---

### JWKS Caching

Keys are cached to:

- Reduce latency
- Prevent excessive provider calls
- Improve resilience

Includes negative caching for unknown keys.

---

### Refresh Throttling

Prevents abuse that could trigger excessive JWKS refresh requests.

---

## Best Practices

- Use HTTPS only
- Keep access tokens short‑lived
- Validate audience and issuer
- Use Redis cache in production
- Monitor authentication failures

---

## Threat Model Summary

Protected assets:

- API endpoints
- User data
- Service availability

Primary threats:

- Forged tokens
- Privilege escalation
- Token replay
- DoS attacks
