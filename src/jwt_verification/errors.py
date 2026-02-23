"""Authentication and authorization errors.

This module defines the exception hierarchy for JWT verification failures.
All errors inherit from AuthError to allow catch-all error handling.

Security Note:
    Error messages are intentionally generic to avoid leaking implementation
    details. Detailed logs should be written server-side, not returned to clients.
"""

from __future__ import annotations


class AuthError(Exception):
    """Base exception for all authentication and authorization failures.

    This is the parent class for all auth-related errors. Application code
    can catch this single exception type to handle any auth failure generically.

    Attributes:
        args: Standard Exception args (typically a message string).
    """


class MissingToken(AuthError):  # noqa: N818
    """Raised when no valid authentication token is found in the request.

    This occurs when:
    - The Authorization header is missing
    - The Authorization header has an invalid format (e.g., not "Bearer <token>")
    - The specified cookie is missing (when using cookie-based extraction)

    This should typically result in an HTTP 401 Unauthorized response.
    """


class InvalidToken(AuthError):  # noqa: N818
    """Raised when a token is present but cannot be verified.

    This occurs when:
    - Token is malformed (not a valid JWT structure)
    - Signature verification fails (wrong key or tampered token)
    - Issuer (iss) doesn't match expected value
    - Audience (aud) doesn't match expected value
    - Algorithm (alg) is not in the allowed list
    - Signing key (kid) cannot be resolved
    - Any other structural or cryptographic validation fails

    This should typically result in an HTTP 401 Unauthorized response.

    Security Note:
        Distinguish this from ExpiredToken for observability, but both should
        return 401 to clients. Do not expose detailed failure reasons externally.
    """


class ExpiredToken(AuthError):  # noqa: N818
    """Raised when a token's expiration time (exp claim) has passed.

    This occurs when:
    - The current time is after the token's exp claim
    - Clock skew (leeway) has been accounted for

    This should typically result in an HTTP 401 Unauthorized response, prompting
    the client to refresh their token.

    Note:
        Treat identically to InvalidToken from a security perspective. The
        distinction helps with metrics and debugging.
    """


class Forbidden(AuthError):  # noqa: N818
    """Raised when a valid token lacks required roles or permissions.

    This occurs when:
    - Token is valid and verified
    - But the token's claims do not satisfy the RBAC requirements (roles/permissions)

    This should result in an HTTP 403 Forbidden response, indicating that
    authentication succeeded but authorization failed.

    Note:
        This is the only error that should result in 403. All others are 401.
    """
