# Changelog

All notable changes to the JWT Verification Extension will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned Features
- Distributed refresh gate (Redis-based coordination)
- Token blacklist support for immediate revocation
- Metrics collection hooks (Prometheus, StatsD)
- WebSocket authentication support
- Multi-tenant routing helper
- GraphQL integration example
- AsyncIO support for async Flask frameworks

### Under Consideration
- Support for EdDSA (Ed25519) algorithm
- Custom claim validators
- Token introspection endpoint support
- Dynamic JWKS endpoint discovery

---

## [1.0.0] - 2026-02-23

### Added - Core Features

#### Authentication
- `AuthExtension` - Flask decorator for route protection
- `JWTVerifier` - Generic JWT signature and claims verification
- `BearerExtractor` - Extract tokens from Authorization header
- `CookieExtractor` - Extract tokens from HTTP cookies
- `get_verified_id_claims()` - Utility for ID token verification

#### Authorization
- `RBACAuthorizer` - Role and permission-based access control
- `ClaimAccess` - Claims normalization and extraction
- `ClaimsMapping` - Configurable claims structure mapping
- Support for "all" vs "any" permission requirements
- Support for multiple role requirements

#### Key Management
- `Auth0JWKSProvider` - Auth0 JWKS integration with caching
- `InMemoryCache` - Thread-safe in-process cache
- `RedisCache` - Distributed Redis-backed cache
- Negative caching for unknown key IDs
- Configurable TTL for valid and invalid keys

#### Security Features
- Cryptographic signature verification (RS256)
- Issuer validation
- Audience validation
- Expiration validation
- Algorithm confusion prevention
- JWKS refresh throttling via `RefreshGate`
- Defense against DoS attacks
- Thread-safe operations

#### Error Handling
- `AuthError` - Base exception class
- `MissingToken` - Missing Authorization header/cookie
- `InvalidToken` - Invalid signature or claims
- `ExpiredToken` - Expired token
- `Forbidden` - Insufficient permissions
- Automatic HTTP status code mapping (401, 403)

#### Protocols & Extensibility
- `TokenVerifier` - Protocol for custom verifiers
- `KeyProvider` - Protocol for custom key providers
- `Authorizer` - Protocol for custom authorization logic
- `CacheStore` - Protocol for custom cache implementations
- `Extractor` - Protocol for custom token extraction
- Full support for dependency injection

#### Type Safety
- Comprehensive type hints throughout
- Type aliases for common types (`Claims`, `ViewFunc`)
- Immutable data classes (`JWTVerifyOptions`, `ClaimsMapping`)
- Protocol-based interfaces (structural typing)

### Added - Documentation

#### Main Documentation
- Comprehensive README with architecture overview
- Core component documentation
- Security features explanation
- Quick start guide
- Detailed usage examples
- Complete API reference
- Testing guide
- Deployment guide
- Troubleshooting section
- Advanced topics
- Best practices
- FAQ

#### Security Documentation
- Detailed threat model
- Trust boundary analysis
- Attack vector catalog with mitigations
- Security checklist (development, testing, production, operations)
- Defense in depth strategy
- Incident response procedures
- Compliance considerations (GDPR, SOC 2, PCI DSS, HIPAA)
- Security reporting guidelines

#### Code Examples
- Basic setup variations
- Authentication examples (Bearer, Cookie, ID token)
- Authorization examples (roles, permissions, resource-specific)
- Custom implementations (providers, authorizers, extractors)
- Integration examples (CORS, rate limiting, SQLAlchemy, Celery)
- Testing examples (unit, integration, mocks)
- Production patterns (application factory, error handling, logging)

#### API Reference
- Complete class documentation
- Method signatures and parameters
- Protocol definitions
- Exception catalog
- Utility function reference
- Type alias documentation
- Import guide

#### Additional Documentation
- Documentation index with navigation
- Changelog (this file)

### Configuration

#### Environment Support
- Development configuration
- Production configuration
- Testing configuration
- Docker/container support

#### Caching Options
- In-memory cache for development
- Redis cache for production
- Configurable TTLs
- Negative caching support

#### Customization
- Custom claims mapping
- Custom extractors
- Custom key providers
- Custom authorizers
- Flexible configuration options

### Performance

#### Optimizations
- Multi-layer caching strategy
- Lazy expiration for in-memory cache
- O(1) cache lookups
- Negative caching reduces invalid token cost
- Minimal overhead for valid cached tokens (~1-5ms)

#### Scalability
- Horizontal scaling support (with Redis)
- Thread-safe operations
- Efficient memory usage
- Designed for high-throughput APIs

### Testing

#### Test Infrastructure
- Unit test examples
- Integration test examples
- Mock helpers for testing
- Test key generation utilities
- Fixture examples

### Developer Experience

#### Ease of Use
- Simple decorator-based API
- Sensible defaults
- Clear error messages
- Comprehensive examples
- Type hints for IDE support

#### Debugging
- Detailed logging support
- Debug mode examples
- Error context preservation
- Observable operations

---

## Version Numbering

This project follows [Semantic Versioning](https://semver.org/):

- **MAJOR** version for incompatible API changes
- **MINOR** version for new functionality in a backwards compatible manner
- **PATCH** version for backwards compatible bug fixes

## Release Process

1. Update CHANGELOG.md with changes
2. Update version in __init__.py
3. Update documentation with new version number
4. Tag release in git: `git tag -a v1.0.0 -m "Release 1.0.0"`
5. Push tags: `git push --tags`

## Contributing

When contributing, please:
- Add entries to the "Unreleased" section
- Follow the existing format
- Group changes by type (Added, Changed, Deprecated, Removed, Fixed, Security)
- Include issue/PR references where applicable

## Change Categories

- **Added** - New features
- **Changed** - Changes to existing functionality
- **Deprecated** - Soon-to-be removed features
- **Removed** - Removed features
- **Fixed** - Bug fixes
- **Security** - Security improvements or fixes

---

## Migration Guides

### Upgrading to v1.0.0

This is the initial release. No migration needed.

---

## Deprecation Policy

- Features are deprecated for at least one MINOR version before removal
- Deprecation warnings are logged
- Migration guides provided in this changelog
- Deprecated features documented in API reference

---

## Support

- **Current stable:** v1.0.0
- **Maintenance:** Bug fixes for current major version
- **Security patches:** Applied to current and previous major version

---

**Last Updated:** February 23, 2026  
**Current Version:** 1.0.0
