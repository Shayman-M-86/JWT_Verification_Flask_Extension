# Security Documentation

This document provides detailed security considerations and best practices for the JWT verification extension.

## Table of Contents

1. [Threat Model](#threat-model)
2. [Security Features](#security-features)
3. [Attack Vectors & Mitigations](#attack-vectors--mitigations)
4. [Security Checklist](#security-checklist)
5. [Defense in Depth](#defense-in-depth)
6. [Incident Response](#incident-response)
7. [Compliance Considerations](#compliance-considerations)

---

## Threat Model

### Assets

**What we're protecting:**
- API endpoints and business logic
- User data accessible through the API
- Service availability and performance
- Auth0 tenant (from abuse/DoS)

### Threat Actors

1. **Unauthenticated Attackers**
   - Goal: Access protected resources without valid credentials
   - Capabilities: Can send arbitrary HTTP requests

2. **Authenticated Users (Privilege Escalation)**
   - Goal: Access resources beyond their permission level
   - Capabilities: Have valid tokens but limited permissions

3. **Compromised Tokens**
   - Goal: Use stolen/leaked tokens
   - Capabilities: Have valid tokens obtained through phishing, XSS, etc.

4. **Denial of Service (DoS) Attackers**
   - Goal: Degrade service availability
   - Capabilities: Can send high volumes of requests

### Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│ TRUSTED: Auth0 Tenant                                       │
│ - Issues valid JWTs                                         │
│ - Manages user identity                                     │
│ - Publishes JWKS                                            │
└─────────────────────────────────────────────────────────────┘
                           │
                           │ JWKS (public keys)
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ SEMI-TRUSTED: Your API Server                               │
│ - Verifies JWT signatures                                   │
│ - Enforces authorization rules                              │
│ - Never has access to signing secrets                       │
└─────────────────────────────────────────────────────────────┘
                           │
                           │ Protected resources
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ UNTRUSTED: Client Applications / End Users                  │
│ - May attempt to forge tokens                               │
│ - May send malicious requests                               │
│ - May attempt DoS attacks                                   │
└─────────────────────────────────────────────────────────────┘
```

---

## Security Features

### 1. Cryptographic Signature Verification

**What:** Every JWT signature is verified using public keys from Auth0's JWKS endpoint.

**How it protects:**
- Prevents token forgery (only Auth0 can create valid signatures)
- Detects token tampering (any modification invalidates signature)
- Ensures authenticity (token was issued by trusted authority)

**Implementation:**
```python
# Uses PyJWT with explicit algorithm allowlist
jwt.decode(
    token,
    key,  # Public key from JWKS
    algorithms=["RS256"],  # No HS256, no "none"
    issuer=expected_issuer,
    audience=expected_audience,
)
```

### 2. Issuer Validation

**What:** Validates the `iss` (issuer) claim matches your Auth0 tenant.

**How it protects:**
- Rejects tokens from other Auth0 tenants
- Prevents cross-tenant token reuse
- Ensures tokens are from your trusted identity provider

**Configuration:**
```python
JWTVerifyOptions(
    issuer="https://your-tenant.auth0.com/",  # Exact match required
    # ...
)
```

### 3. Audience Validation

**What:** Validates the `aud` (audience) claim matches your API identifier.

**How it protects:**
- Prevents token reuse across different APIs
- Ensures tokens are intended for your specific service
- Implements principle of least privilege

**Best practice:**
```python
JWTVerifyOptions(
    audience="your-api-identifier",  # Must match Auth0 API configuration
    # ...
)
```

### 4. Expiration Validation

**What:** Validates the `exp` (expiration) claim is in the future.

**How it protects:**
- Limits window of opportunity for stolen tokens
- Enforces token lifetime policies
- Enables periodic re-authentication

**Considerations:**
- Use short lifetimes (15-60 minutes)
- Account for clock skew (typically ±5 minutes)
- Implement token refresh for long-lived sessions

### 5. Algorithm Confusion Prevention

**What:** Never trusts the `alg` field from token header; uses explicit allowlist.

**How it protects:**
Prevents algorithm confusion attacks:

**Attack scenario:**
1. Attacker obtains your public RSA key
2. Creates token with `alg: HS256` and signs with RSA public key as HMAC secret
3. Naive verifier uses public key as HMAC secret → signature validates!

**Our protection:**
```python
# Only RS256 allowed, regardless of header
algorithms=["RS256"]
```

### 6. Negative Caching

**What:** Caches unknown `kid` values as "missing" for short TTL.

**How it protects:**
- Makes DoS attacks with random `kid` values cheap (O(1) cache lookup)
- Prevents repeated expensive JWKS fetches
- Reduces load on Auth0's JWKS endpoint

**Impact:**
Without negative caching:
- 1000 requests/sec with random `kid` → 1000 JWKS fetches/sec
- With negative caching: 1000 requests/sec → ~33 cache stores/sec (30s TTL)

### 7. JWKS Refresh Throttling

**What:** Rate-limits forced JWKS refresh operations.

**How it protects:**
- Prevents amplification attacks (many API requests → many outbound JWKS fetches)
- Protects against Auth0 rate limiting
- Maintains service availability under attack

**Configuration:**
```python
Auth0JWKSProvider(
    min_interval=60.0,  # Max 1 forced refresh per minute
    # ...
)
```

**Attack mitigation:**
- Attacker sends 1000 req/sec with invalid `kid`
- Without throttling: 1000 JWKS fetches/sec → Auth0 blocks your IP
- With throttling: 1 JWKS fetch/60sec → attack has minimal impact

### 8. Multi-Layer Caching

**What:** Multiple cache layers with different purposes.

**Layers:**
1. **PyJWKClient internal cache**: JWKS document cache
2. **Per-kid cache**: Individual signing key cache
3. **Negative cache**: Known-missing kid cache

**How it protects:**
- Reduces cryptographic operations
- Minimizes network requests
- Provides defense against various attack patterns

### 9. Thread Safety

**What:** All caching and rate-limiting operations are thread-safe.

**How it protects:**
- Prevents race conditions in concurrent environments
- Ensures consistent behavior under load
- Protects RefreshGate from concurrent bypass attempts

**Implementation:**
```python
# RefreshGate uses threading.Lock
with self._lock:
    if now < self._next_allowed_at:
        self._retry_attempts += 1
        return False
    # ...
```

---

## Attack Vectors & Mitigations

### 1. Token Forgery

**Attack:** Attacker creates fake JWT with valid structure but invalid signature.

**Mitigation:**
- ✅ Signature verification with Auth0 public keys
- ✅ Explicit algorithm allowlist (RS256 only)
- ✅ Issuer validation

**Detection:**
- Monitor for `InvalidToken` errors
- Alert on signature verification failures

### 2. Token Replay (Stolen Token)

**Attack:** Attacker obtains valid token (phishing, XSS, etc.) and uses it.

**Mitigation:**
- ⚠️ **Limited by design** - valid token = valid access
- ✅ Short token lifetime limits window
- ✅ Token refresh enables revocation
- 💡 Additional protection: IP allowlisting, device fingerprinting (external)

**Best practices:**
- Use short-lived access tokens (15-60 min)
- Implement refresh token rotation
- Monitor for suspicious access patterns
- Consider token binding (MTLS, DPoP)

### 3. Algorithm Confusion (CVE-2015-9235)

**Attack:** Change `alg` header from RS256 to HS256, sign with public key as HMAC secret.

**Mitigation:**
- ✅ Never trust `alg` field in token
- ✅ Explicit algorithm allowlist in configuration
- ✅ Only RS256 allowed by default

**Prevention:**
```python
# ❌ VULNERABLE
jwt.decode(token, key)  # Trusts alg from token

# ✅ SECURE
jwt.decode(token, key, algorithms=["RS256"])  # Explicit allowlist
```

### 4. Cross-Service Token Reuse

**Attack:** Use token issued for Service A to access Service B.

**Mitigation:**
- ✅ Audience validation (unique per API)
- ✅ Each API has distinct identifier in Auth0

**Configuration:**
```python
# Service A
JWTVerifyOptions(audience="service-a-api")

# Service B
JWTVerifyOptions(audience="service-b-api")
```

### 5. Cross-Tenant Token Reuse

**Attack:** Use token from your Auth0 tenant to access another's API.

**Mitigation:**
- ✅ Issuer validation (unique per tenant)
- ✅ Strict URL matching including trailing slash

**Important:**
```python
# These are DIFFERENT issuers
issuer="https://tenant1.auth0.com/"  # ✅
issuer="https://tenant2.auth0.com/"  # ✅

# Ensure exact match
if token["iss"] != expected_issuer:
    raise InvalidToken()
```

### 6. Privilege Escalation (Token Manipulation)

**Attack:** Modify token claims to gain elevated permissions.

**Mitigation:**
- ✅ Signature verification detects any modification
- ✅ RBAC enforced after verification
- ✅ Permissions embedded in signed token (not user-controllable)

**Why this is secure:**
```
User modifies token: {"role": "admin"}
                              ↓
Signature verification fails (claims don't match signature)
                              ↓
Request rejected with 401
```

### 7. DoS via Invalid Tokens

**Attack:** Send high volume of requests with invalid tokens to consume resources.

**Mitigation:**
- ✅ Negative caching makes repeated invalid `kid` cheap
- ✅ RefreshGate prevents JWKS fetch amplification
- ✅ Fast-fail for malformed tokens
- 💡 Additional: Rate limiting at reverse proxy/WAF level

**Performance:**
- Valid token (cached): ~1-2ms
- Invalid token (negative cached): ~1ms
- Malformed token: <1ms (immediate failure)

### 8. Key Confusion

**Attack:** Trick verifier into using wrong key for verification.

**Mitigation:**
- ✅ `kid` extracted from header determines key lookup
- ✅ Key fetched from trusted JWKS endpoint only
- ✅ No user-controlled key source

### 9. Clock Skew Attacks

**Attack:** Exploit time-based claims (`exp`, `nbf`, `iat`) with clock differences.

**Mitigation:**
- ✅ PyJWT includes default leeway (typically 0, but configurable)
- 💡 Recommendation: Sync server clocks with NTP
- 💡 Monitor for `ExpiredToken` errors (may indicate skew)

**Best practice:**
```python
# If needed, add small leeway for clock skew
jwt.decode(
    token,
    key,
    leeway=10,  # 10 seconds tolerance
)
```

### 10. JWKS Endpoint Compromise

**Attack:** Attacker compromises Auth0 JWKS endpoint or performs MITM attack.

**Mitigation:**
- ✅ HTTPS for all JWKS fetches
- ✅ Certificate validation
- ⚠️ Trust in Auth0's security (external dependency)
- 💡 Additional: JWKS pinning for critical services

### 11. Cache Poisoning

**Attack:** Inject malicious keys into cache.

**Mitigation:**
- ✅ Only Auth0JWKSProvider can write to cache
- ✅ Keys fetched from trusted JWKS endpoint only
- ✅ Redis AUTH (if using RedisCache)
- 💡 Recommendation: Network isolation for Redis

**Redis security:**
```python
redis.Redis(
    host='localhost',
    password=os.environ['REDIS_PASSWORD'],  # Enable AUTH
    ssl=True,  # Use TLS
)
```

### 12. Information Disclosure

**Attack:** Extract sensitive information from error messages or logs.

**Mitigation:**
- ✅ Generic error messages to clients
- ✅ Detailed errors only in server logs
- ⚠️ Never log tokens

**Example:**
```python
# ❌ BAD - reveals internal details
return {"error": f"Key resolution failed: {kid}"}, 401

# ✅ GOOD - generic message
return {"error": "Invalid token"}, 401
```

### 13. Refresh Token Attacks

**Attack:** Steal refresh token for long-term access.

**Mitigation:**
- 💡 This extension handles access tokens only
- 💡 Refresh token security is client-side responsibility
- 💡 Recommendations:
  - Store refresh tokens in secure, httpOnly cookies
  - Implement refresh token rotation
  - Use refresh token reuse detection

---

## Security Checklist

### Development

- [ ] Use explicit issuer and audience in `JWTVerifyOptions`
- [ ] Only allow RS256 algorithm
- [ ] Never log tokens or sensitive claims
- [ ] Use environment variables for Auth0 configuration
- [ ] Implement proper error handling (don't reveal internals)
- [ ] Enable HTTPS for all environments
- [ ] Review custom claims mapping for security implications

### Testing

- [ ] Test with expired tokens
- [ ] Test with tokens from wrong issuer
- [ ] Test with tokens for wrong audience
- [ ] Test with malformed tokens
- [ ] Test with random/invalid `kid` values
- [ ] Test RBAC with insufficient permissions
- [ ] Test DoS scenarios (token spam)
- [ ] Verify negative caching works
- [ ] Verify refresh throttling works

### Production Deployment

- [ ] Use Redis for cache (not InMemoryCache)
- [ ] Configure appropriate TTLs (3600s for keys, 30-60s for negative)
- [ ] Enable Redis AUTH and/or TLS
- [ ] Use HTTPS exclusively (no HTTP)
- [ ] Configure rate limiting at API gateway/WAF
- [ ] Set up monitoring and alerting
- [ ] Enable security headers (HSTS, CSP, etc.)
- [ ] Review Auth0 tenant security settings
- [ ] Enable RBAC in Auth0 API settings
- [ ] Configure CORS appropriately
- [ ] Implement request size limits
- [ ] Set up log aggregation and analysis
- [ ] Configure secret management (never hardcode)

### Ongoing Operations

- [ ] Monitor for unusual authentication patterns
- [ ] Review access logs regularly
- [ ] Test disaster recovery procedures
- [ ] Keep dependencies updated
- [ ] Review Auth0 audit logs
- [ ] Conduct periodic security reviews
- [ ] Test key rotation procedures
- [ ] Maintain incident response plan
- [ ] Monitor Auth0 security bulletins

---

## Defense in Depth

The extension implements multiple security layers that protect independently:

### Layer 1: Transport Security
- **HTTPS** for all API communication
- **TLS** for Redis connections
- **Certificate validation** for JWKS fetches

### Layer 2: Token Extraction
- **Format validation** (Bearer prefix, cookie presence)
- **Request header validation**
- **Fail-fast** on missing/malformed tokens

### Layer 3: Signature Verification
- **RSA signature verification** with public key
- **Algorithm allowlist** (no algorithm confusion)
- **Key resolution** from trusted JWKS only

### Layer 4: Claims Validation
- **Issuer validation** (correct Auth0 tenant)
- **Audience validation** (correct API identifier)
- **Expiration validation** (not expired)

### Layer 5: Authorization
- **Role checking** (at least one required role)
- **Permission checking** (all or any required permissions)
- **Custom business logic** (via custom Authorizer)

### Layer 6: Performance Protection
- **Caching** (reduce cryptographic operations)
- **Negative caching** (make spam attacks cheap)
- **Refresh throttling** (prevent amplification)

### Layer 7: Observability
- **Structured logging**
- **Metrics collection**
- **Alerting on anomalies**

**Result:** Even if one layer fails, others provide protection.

---

## Incident Response

### Suspected Token Compromise

**Detection:**
- Unusual access patterns
- Access from unexpected IPs/locations
- Spike in 401/403 errors

**Response:**
1. Identify compromised user (check `sub` claim in logs)
2. Revoke refresh tokens in Auth0
3. Force password reset for user
4. Wait for access token expiration (or implement blacklist)
5. Review audit logs for unauthorized access
6. Notify affected user

### JWKS Endpoint Issues

**Detection:**
- All token verification failing
- `Unable to resolve signing key` errors
- JWKS fetch failures in logs

**Response:**
1. Check Auth0 status page
2. Verify network connectivity to Auth0
3. Check DNS resolution
4. Review firewall/WAF rules
5. Verify HTTPS certificate validity
6. If Auth0 issue: wait for resolution
7. If local issue: fix and clear cache to recover

### DoS Attack

**Detection:**
- High rate of 401 errors
- JWKS refresh throttling alerts
- Elevated CPU/memory usage

**Response:**
1. Identify attack source (IP, user agent, pattern)
2. Block at WAF/reverse proxy level
3. Verify RefreshGate is throttling effectively
4. Monitor Redis performance
5. Scale horizontally if needed
6. Review logs for other attack vectors

### Cache Compromise

**Detection:**
- Unexpected Redis writes
- Authorization bypass
- Unusual key patterns in cache

**Response:**
1. Clear Redis cache immediately
2. Rotate Redis password
3. Review Redis access logs
4. Enable Redis AUTH if not already
5. Isolate Redis network access
6. Audit application logs for unauthorized access

---

## Compliance Considerations

### GDPR

**Relevant aspects:**
- JWTs contain user identifiers (`sub`, `email`, etc.)
- Claims are processed and logged
- User has right to data deletion

**Recommendations:**
- Implement data retention policies for logs
- Ensure token contains minimal PII
- Use pseudonymous identifiers where possible
- Document data processing in privacy policy

### SOC 2

**Relevant controls:**
- Access control (CC6.1, CC6.2)
- Encryption (CC6.7)
- Monitoring (CC7.1, CC7.2)

**Recommendations:**
- Enable detailed audit logging
- Implement monitoring and alerting
- Document security procedures
- Conduct periodic reviews

### PCI DSS (if handling payments)

**Relevant requirements:**
- Requirement 8: Identify and authenticate access
- Requirement 10: Track and monitor access

**Recommendations:**
- Use unique identifiers for users
- Log all access to cardholder data
- Implement multi-factor authentication (Auth0)
- Regular security testing

### HIPAA (if handling health data)

**Relevant safeguards:**
- Access control (164.312(a)(1))
- Audit controls (164.312(b))
- Integrity (164.312(c)(1))

**Recommendations:**
- Document access controls
- Maintain audit logs for 6+ years
- Implement emergency access procedures
- Regular security assessments

---

## Security Updates

### Keeping Secure

1. **Monitor dependencies:**
   ```bash
   pip install safety
   safety check
   ```

2. **Update regularly:**
   ```bash
   pip install --upgrade PyJWT cryptography
   ```

3. **Subscribe to security advisories:**
   - PyJWT: https://github.com/jpadilla/pyjwt/security
   - Auth0: https://auth0.com/security
   - Flask: https://flask.palletsprojects.com/security/

4. **Review Auth0 changelog:**
   - Breaking changes
   - Security improvements
   - New best practices

---

## Reporting Security Issues

If you discover a security vulnerability:

1. **Do NOT open a public issue**
2. Email security contact (see main project README)
3. Include:
   - Description of vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)
4. Allow reasonable time for response (90 days)

We take security seriously and will respond promptly to all reports.

---

**Last Updated:** February 23, 2026  
**Reviewed By:** Security Team
