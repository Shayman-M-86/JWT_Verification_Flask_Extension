"""
Authentication and authorization errors.
"""


class AuthError(Exception):
    """Base auth error."""


class MissingToken(AuthError):
    """Raised when Authorization header is missing/invalid."""


class InvalidToken(AuthError):
    """Raised for malformed tokens, invalid signatures, bad issuer/audience, key resolution failures."""


class ExpiredToken(AuthError):
    """Raised when token is expired."""


class Forbidden(AuthError):
    """Raised when token is valid but does not meet required roles/permissions."""
