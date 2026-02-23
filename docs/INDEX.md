# JWT Verification Extension - Documentation Index

Welcome to the comprehensive documentation for the JWT Verification Extension. This index will help you find the information you need quickly.

## 📚 Documentation Files

### [README.md](./README.md) - Main Documentation

**Comprehensive guide covering everything you need to know.**

Topics covered:

- Overview and architecture
- Core components explained
- Security features
- Quick start guide
- Detailed usage examples
- Complete API reference
- Testing guide
- Deployment guide
- Troubleshooting
- Advanced topics
- Best practices
- FAQ

**Start here if:** You're new to the extension or want a complete understanding.

---

### [SECURITY.md](./SECURITY.md) - Security Documentation

**In-depth security analysis and best practices.**

Topics covered:

- Threat model and trust boundaries
- Security features explained
- Attack vectors and mitigations
- Security checklist
- Defense in depth strategy
- Incident response procedures
- Compliance considerations (GDPR, SOC 2, PCI DSS, HIPAA)
- Reporting security issues

**Start here if:** You need to understand security implications, prepare for audits, or handle security incidents.

---

### [EXAMPLES.md](./EXAMPLES.md) - Code Examples

**Practical code examples for common scenarios.**

Topics covered:

- Basic setup variations
- Authentication examples (public/protected routes, cookies, ID tokens)
- Authorization examples (RBAC, permissions, resource-specific)
- Custom implementations (key providers, authorizers, extractors)
- Integration examples (CORS, rate limiting, SQLAlchemy, Celery)
- Testing examples (unit tests, integration tests, mocks)
- Production patterns (application factory, error handling, logging)

**Start here if:** You want to see working code for specific use cases.

---

### [API_REFERENCE.md](./API_REFERENCE.md) - API Reference

**Quick lookup for all classes, methods, and protocols.**

Topics covered:

- Core classes (AuthExtension, JWTVerifier, Auth0JWKSProvider, RBACAuthorizer, etc.)
- Protocols (TokenVerifier, KeyProvider, Authorizer, CacheStore, Extractor)
- Data classes (JWTVerifyOptions, ClaimsMapping)
- Exceptions (AuthError, MissingToken, InvalidToken, ExpiredToken, Forbidden)
- Utility functions
- Type aliases
- Import guide

**Start here if:** You need quick reference for specific classes or methods.

---

## 🚀 Quick Start Guides

### "I just want to protect my API endpoints"

1. Read: [README.md - Quick Start](./README.md#quick-start)
2. Copy the basic setup code
3. Replace Auth0 credentials
4. Done!

### "I need role-based access control"

1. Read: [README.md - With RBAC](./README.md#with-rbac)
2. Configure ClaimsMapping for your Auth0 setup
3. Add `@auth.require(roles=[...])` to routes
4. See: [EXAMPLES.md - Authorization Examples](./EXAMPLES.md#authorization-examples)

### "I'm deploying to production"

1. Read: [README.md - Deployment](./README.md#deployment)
2. Review: [SECURITY.md - Security Checklist](./SECURITY.md#security-checklist)
3. Configure Redis cache
4. Set up monitoring
5. Review: [README.md - Production Checklist](./README.md#production-checklist)

### "I need to understand security"

1. Read: [SECURITY.md - Threat Model](./SECURITY.md#threat-model)
2. Review: [SECURITY.md - Attack Vectors](./SECURITY.md#attack-vectors--mitigations)
3. Implement: [SECURITY.md - Security Checklist](./SECURITY.md#security-checklist)

---

## 🎯 Common Tasks

### Setting Up Authentication

**Files:** [README.md](./README.md#quick-start), [EXAMPLES.md](./EXAMPLES.md#basic-setup)

```python
from jwt_verification import (
    AuthExtension,
    Auth0JWKSProvider,
    JWTVerifier,
    JWTVerifyOptions,
)

provider = Auth0JWKSProvider(issuer="https://your-tenant.auth0.com/")
verifier = JWTVerifier(
    key_provider=provider,
    options=JWTVerifyOptions(
        issuer="https://your-tenant.auth0.com/",
        audience="your-api-identifier",
    ),
)
auth = AuthExtension(verifier=verifier)

@app.route("/protected")
@auth.require()
def protected():
    return {"message": "Authenticated!"}
```

**See also:**

- [README.md - Basic Setup](./README.md#quick-start)
- [EXAMPLES.md - Authentication Examples](./EXAMPLES.md#authentication-examples)

---

### Adding Authorization (Roles & Permissions)

**Files:** [README.md](./README.md#with-rbac), [EXAMPLES.md](./EXAMPLES.md#authorization-examples)

```python
from jwt_verification import (
    RBACAuthorizer,
    ClaimAccess,
    ClaimsMapping,
)

mapping = ClaimsMapping(
    permissions_claim="permissions",
    roles_claim="roles",
)
authorizer = RBACAuthorizer(ClaimAccess(mapping))
auth = AuthExtension(verifier=verifier, authorizer=authorizer)

@app.route("/admin")
@auth.require(roles=["admin"])
def admin_only():
    return {"message": "Admin access"}

@app.route("/posts", methods=["POST"])
@auth.require(permissions=["write:posts"])
def create_post():
    return {"message": "Post created"}
```

**See also:**

- [API_REFERENCE.md - RBACAuthorizer](./API_REFERENCE.md#rbacauthorizer)
- [EXAMPLES.md - Permission-Based Access Control](./EXAMPLES.md#permission-based-access-control)

---

### Configuring Production Cache

**Files:** [README.md](./README.md#with-redis-cache-production), [README.md - Deployment](./README.md#deployment)

```python
import redis
from jwt_verification import RedisCache

redis_client = redis.Redis(
    host='localhost',
    port=6379,
    password=os.environ['REDIS_PASSWORD'],
    ssl=True,
    decode_responses=False,
)
cache = RedisCache(redis_client)

provider = Auth0JWKSProvider(
    issuer="https://your-tenant.auth0.com/",
    cache=cache,
    ttl_seconds=3600,
)
```

**See also:**

- [API_REFERENCE.md - RedisCache](./API_REFERENCE.md#rediscache)
- [README.md - Scaling Considerations](./README.md#scaling-considerations)

---

### Handling Errors

**Files:** [README.md](./README.md#error-handling), [EXAMPLES.md](./EXAMPLES.md#error-handling)

```python
from jwt_verification import (
    MissingToken,
    ExpiredToken,
    InvalidToken,
    Forbidden,
)

@app.errorhandler(401)
def handle_unauthorized(e):
    return {"error": "Unauthorized", "message": str(e.description)}, 401

@app.errorhandler(403)
def handle_forbidden(e):
    return {"error": "Forbidden", "message": "Insufficient permissions"}, 403
```

**See also:**

- [API_REFERENCE.md - Exceptions](./API_REFERENCE.md#exceptions)
- [EXAMPLES.md - Error Handling](./EXAMPLES.md#error-handling)

---

### Testing Your Implementation

**Files:** [README.md](./README.md#testing), [EXAMPLES.md](./EXAMPLES.md#testing-examples)

```python
import pytest
from flask import Flask

@pytest.fixture
def app():
    app = Flask(__name__)
    auth = AuthExtension(verifier=test_verifier)
    
    @app.route("/protected")
    @auth.require()
    def protected():
        return {"message": "success"}
    
    return app

def test_protected_route(client):
    # Without token
    response = client.get("/protected")
    assert response.status_code == 401
    
    # With valid token
    headers = {"Authorization": f"Bearer {valid_token}"}
    response = client.get("/protected", headers=headers)
    assert response.status_code == 200
```

**See also:**

- [README.md - Testing](./README.md#testing)
- [EXAMPLES.md - Unit Tests](./EXAMPLES.md#unit-tests)

---

## 🔍 Finding Specific Information

### Architecture & Design

- **Component Overview:** [README.md - Architecture](./README.md#architecture)
- **Request Flow:** [README.md - High-Level Request Flow](./README.md#high-level-request-flow)
- **Component Diagram:** [README.md - Component Diagram](./README.md#component-diagram)
- **Design Principles:** [README.md - Architecture Philosophy](./README.md#architecture-philosophy)

### Security

- **Security Overview:** [README.md - Security Features](./README.md#security-features)
- **Detailed Analysis:** [SECURITY.md](./SECURITY.md)
- **Threat Model:** [SECURITY.md - Threat Model](./SECURITY.md#threat-model)
- **Attack Mitigations:** [SECURITY.md - Attack Vectors](./SECURITY.md#attack-vectors--mitigations)
- **Security Checklist:** [SECURITY.md - Security Checklist](./SECURITY.md#security-checklist)

### Core Components

- **AuthExtension:** [README.md - AuthExtension](./README.md#1-authextension), [API_REFERENCE.md](./API_REFERENCE.md#authextension)
- **JWTVerifier:** [README.md - JWTVerifier](./README.md#2-jwtverifier), [API_REFERENCE.md](./API_REFERENCE.md#jwtverifier)
- **Auth0JWKSProvider:** [README.md - Auth0JWKSProvider](./README.md#3-auth0jwksprovider), [API_REFERENCE.md](./API_REFERENCE.md#auth0jwksprovider)
- **RBACAuthorizer:** [README.md - RBACAuthorizer](./README.md#4-rbacauthorizer), [API_REFERENCE.md](./API_REFERENCE.md#rbacauthorizer)
- **Cache Stores:** [README.md - Cache Stores](./README.md#5-cache-stores), [API_REFERENCE.md](./API_REFERENCE.md#inmemorycache)

### Usage Examples

- **Basic Setup:** [README.md - Quick Start](./README.md#quick-start), [EXAMPLES.md - Basic Setup](./EXAMPLES.md#basic-setup)
- **Authentication:** [README.md - Detailed Usage](./README.md#detailed-usage), [EXAMPLES.md - Authentication Examples](./EXAMPLES.md#authentication-examples)
- **Authorization:** [EXAMPLES.md - Authorization Examples](./EXAMPLES.md#authorization-examples)
- **Custom Implementations:** [EXAMPLES.md - Custom Implementations](./EXAMPLES.md#custom-implementations)
- **Integrations:** [EXAMPLES.md - Integration Examples](./EXAMPLES.md#integration-examples)

### Deployment

- **Production Setup:** [README.md - Deployment](./README.md#deployment)
- **Environment Config:** [README.md - Environment Configuration](./README.md#environment-configuration)
- **Docker:** [README.md - Docker Deployment](./README.md#docker-deployment)
- **Monitoring:** [README.md - Monitoring and Observability](./README.md#monitoring-and-observability)
- **Scaling:** [README.md - Scaling Considerations](./README.md#scaling-considerations)

### Troubleshooting

- **Common Issues:** [README.md - Troubleshooting](./README.md#troubleshooting)
- **Debugging Tips:** [README.md - Debugging Tips](./README.md#debugging-tips)
- **Performance Issues:** [README.md - Performance Issues](./README.md#performance-issues)
- **Incident Response:** [SECURITY.md - Incident Response](./SECURITY.md#incident-response)

---

## 📖 Learning Paths

### For New Users

1. **Understand the basics**
   - Read: [README.md - Overview](./README.md#overview)
   - Read: [README.md - Architecture](./README.md#architecture)

2. **Get started quickly**
   - Follow: [README.md - Quick Start](./README.md#quick-start)
   - Try: [EXAMPLES.md - Basic Setup](./EXAMPLES.md#basic-setup)

3. **Add authorization**
   - Read: [README.md - With RBAC](./README.md#with-rbac)
   - Try: [EXAMPLES.md - Authorization Examples](./EXAMPLES.md#authorization-examples)

4. **Understand security**
   - Read: [README.md - Security Features](./README.md#security-features)
   - Skim: [SECURITY.md - Overview](./SECURITY.md)

### For Developers

1. **Understand architecture**
   - Study: [README.md - Architecture](./README.md#architecture)
   - Study: [README.md - Core Components](./README.md#core-components)

2. **Learn the API**
   - Reference: [API_REFERENCE.md](./API_REFERENCE.md)
   - Study examples: [EXAMPLES.md](./EXAMPLES.md)

3. **Implement features**
   - Custom key providers: [EXAMPLES.md - Custom Key Provider](./EXAMPLES.md#custom-key-provider)
   - Custom authorizers: [EXAMPLES.md - Custom Authorizer](./EXAMPLES.md#custom-authorizer)
   - Integrations: [EXAMPLES.md - Integration Examples](./EXAMPLES.md#integration-examples)

4. **Write tests**
   - Follow: [README.md - Testing](./README.md#testing)
   - Examples: [EXAMPLES.md - Testing Examples](./EXAMPLES.md#testing-examples)

### For Security Engineers

1. **Threat analysis**
   - Study: [SECURITY.md - Threat Model](./SECURITY.md#threat-model)
   - Review: [SECURITY.md - Attack Vectors](./SECURITY.md#attack-vectors--mitigations)

2. **Security features**
   - Deep dive: [README.md - Security Features](./README.md#security-features)
   - Understand: [SECURITY.md - Defense in Depth](./SECURITY.md#defense-in-depth)

3. **Security checklist**
   - Complete: [SECURITY.md - Security Checklist](./SECURITY.md#security-checklist)
   - Review: [README.md - Production Checklist](./README.md#production-checklist)

4. **Incident response**
   - Prepare: [SECURITY.md - Incident Response](./SECURITY.md#incident-response)

### For DevOps/SRE

1. **Production setup**
   - Follow: [README.md - Deployment](./README.md#deployment)
   - Configure: [README.md - Environment Configuration](./README.md#environment-configuration)

2. **Scaling**
   - Study: [README.md - Scaling Considerations](./README.md#scaling-considerations)
   - Setup: [README.md - Docker Deployment](./README.md#docker-deployment)

3. **Monitoring**
   - Implement: [README.md - Monitoring and Observability](./README.md#monitoring-and-observability)
   - Examples: [EXAMPLES.md - Logging and Monitoring](./EXAMPLES.md#logging-and-monitoring)

4. **Troubleshooting**
   - Reference: [README.md - Troubleshooting](./README.md#troubleshooting)
   - Handle incidents: [SECURITY.md - Incident Response](./SECURITY.md#incident-response)

---

## 🔗 External Resources

### Auth0 Documentation

- [Auth0 Documentation](https://auth0.com/docs)
- [Auth0 APIs](https://auth0.com/docs/api)
- [JWKS Endpoint](https://auth0.com/docs/secure/tokens/json-web-tokens/json-web-key-sets)
- [RBAC](https://auth0.com/docs/manage-users/access-control/rbac)

### JWT Standards

- [RFC 7519 - JWT](https://tools.ietf.org/html/rfc7519)
- [RFC 7517 - JWK](https://tools.ietf.org/html/rfc7517)
- [RFC 7518 - JWA](https://tools.ietf.org/html/rfc7518)

### Python Libraries

- [PyJWT Documentation](https://pyjwt.readthedocs.io/)
- [Flask Documentation](https://flask.palletsprojects.com/)
- [Redis-py Documentation](https://redis-py.readthedocs.io/)

---

## 📝 Document Summaries

### README.md (Main Documentation)

- **Length:** ~1000 lines
- **Scope:** Comprehensive guide to all aspects of the extension
- **Audience:** Everyone (developers, security, devops)
- **Best for:** Learning the extension from scratch or as complete reference

### SECURITY.md

- **Length:** ~700 lines
- **Scope:** Security analysis, threat model, attack mitigations
- **Audience:** Security engineers, compliance teams, developers
- **Best for:** Security reviews, compliance audits, threat modeling

### EXAMPLES.md

- **Length:** ~800 lines
- **Scope:** Working code examples for common scenarios
- **Audience:** Developers implementing the extension
- **Best for:** Copy-paste solutions, learning by example

### API_REFERENCE.md

- **Length:** ~600 lines
- **Scope:** Complete API reference for all classes and methods
- **Audience:** Developers needing quick reference
- **Best for:** Looking up specific APIs, understanding signatures

---

## 🆘 Getting Help

### Documentation Not Clear?

1. Check the [FAQ](./README.md#faq) in README.md
2. Review related examples in [EXAMPLES.md](./EXAMPLES.md)
3. Search the documentation for keywords
4. Open an issue on GitHub

### Found a Bug?

1. Check [Troubleshooting](./README.md#troubleshooting) in README.md
2. Review error messages in [API_REFERENCE.md - Exceptions](./API_REFERENCE.md#exceptions)
3. Open an issue with reproduction steps

### Security Concern?

1. Review [SECURITY.md](./SECURITY.md)
2. **DO NOT** open public issue
3. Follow [Reporting Security Issues](./SECURITY.md#reporting-security-issues)

---

## 🎓 Glossary

- **JWT**: JSON Web Token - A compact, URL-safe means of representing claims
- **JWKS**: JSON Web Key Set - A set of public keys for verifying JWTs
- **kid**: Key ID - Identifier for a specific signing key in JWKS
- **iss**: Issuer - The entity that issued the JWT
- **aud**: Audience - The intended recipient of the JWT
- **exp**: Expiration - When the JWT expires (Unix timestamp)
- **sub**: Subject - The user identifier
- **RBAC**: Role-Based Access Control - Authorization based on user roles
- **Negative Caching**: Caching known-missing items to avoid repeated lookups
- **RefreshGate**: Rate limiter for JWKS refresh operations
- **Claims**: Data contained in a JWT payload

---

## 📅 Version History

**v1.0.0** (February 23, 2026)

- Initial documentation release
- Comprehensive coverage of all features
- Security analysis and best practices
- Production deployment guide
- Extensive code examples

---

## 📄 License

See main project README for license information.

---

**Quick Navigation:**

- [Main Documentation](./README.md)
- [Security Guide](./SECURITY.md)
- [Code Examples](./EXAMPLES.md)
- [API Reference](./API_REFERENCE.md)

**Need help?** Start with the [Quick Start Guide](./README.md#quick-start) or browse [Common Tasks](#-common-tasks) above.
