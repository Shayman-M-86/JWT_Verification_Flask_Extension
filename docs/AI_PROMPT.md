# AI Context — Flask JWT Authorization Extension

This project is a Flask authorization extension for verifying JWT access tokens issued by external identity providers.

It is NOT an authentication server.

The extension performs:

1. Token extraction
2. Signature verification
3. Claims validation
4. Authorization checks
5. Error handling

Architecture is dependency‑injection based with protocol interfaces for:

- Token verification
- Key retrieval
- Authorization logic
- Caching
- Extraction

Typical usage is protecting Flask routes using a decorator.

Example:

@auth.require(permissions=["write:posts"])

The system assumes tokens are issued by a trusted provider such as Auth0.

