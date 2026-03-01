"""Token extraction strategies from HTTP requests.

This module provides implementations of the Extractor protocol for retrieving
JWT tokens from different parts of an HTTP request.

Implementations:
- BearerExtractor: Extracts from Authorization: Bearer <token> header (recommended)
- CookieExtractor: Extracts from HTTP cookies (for browser-based apps)

Security Considerations:
- Bearer tokens are standard for APIs and recommended for most use cases
- Cookie-based extraction requires proper CSRF protection
- Never extract tokens from URL query parameters (visible in logs/history)
"""

from __future__ import annotations

from flask import request

from .errors import MissingToken


class BearerExtractor:
    """Extracts JWT from Authorization header using Bearer scheme.

    This is the standard approach for API authentication. Expects requests
    with header format:
        Authorization: Bearer <token>

    Example:
        ```python
        extractor = BearerExtractor()
        auth = AuthExtension(
            verifier=verifier,
            extractor=extractor  # Uses Authorization header
        )
        ```

    Security Notes:
        - Bearer tokens should only be sent over HTTPS
        - Tokens in headers are not vulnerable to CSRF (unlike cookies)
        - Headers are not logged by default in most web servers
    """

    def extract(self) -> str:
        """Extract JWT from Authorization: Bearer header.

        Returns:
            Raw JWT string (without "Bearer " prefix).

        Raises:
            MissingToken: If Authorization header is missing or doesn't use Bearer scheme.

        Implementation Notes:
            - Validates header format before extraction
            - Strips "Bearer " prefix (case-insensitive)
            - Rejects malformed headers to fail fast
        """
        auth_header = request.headers.get("Authorization", "").strip()

        if not auth_header:
            raise MissingToken("Missing Authorization header")

        # Split only once to avoid issues with spaces in token (shouldn't happen but defense)
        parts = auth_header.split(" ", 1)

        # Validate format: "Bearer <token>"
        if len(parts) != 2:
            raise MissingToken("Invalid Authorization header format (expected 'Bearer <token>')")

        scheme, token = parts

        if scheme.lower() != "bearer":
            raise MissingToken("Invalid authorization scheme (expected 'Bearer')")

        token = token.strip()
        if not token:
            raise MissingToken("Bearer token is empty")

        return token


class CookieExtractor:
    """Extracts JWT from an HTTP cookie.

    Useful for browser-based applications where storing tokens in cookies
    provides automatic inclusion in requests and HttpOnly security.

    Example:
        ```python
        extractor = CookieExtractor(cookie_name="access_token")
        auth = AuthExtension(
            verifier=verifier,
            extractor=extractor  # Uses cookie instead of header
        )
        ```

    Security Notes:
        - Cookies MUST use HttpOnly flag to prevent XSS attacks
        - Cookies MUST use Secure flag (HTTPS only)
        - Cookie-based auth is vulnerable to CSRF; implement CSRF protection
        - Consider SameSite=Strict or SameSite=Lax

    Attributes:
        _name: Name of the cookie containing the JWT.
    """

    def __init__(self, cookie_name: str = "access_token") -> None:
        """Initialize cookie extractor.

        Args:
            cookie_name: Name of the cookie to read. Defaults to "access_token".

        Raises:
            ValueError: If cookie_name is empty.
        """
        if not cookie_name or not cookie_name.strip():
            raise ValueError("cookie_name cannot be empty")
        self._name = cookie_name

    def extract(self) -> str:
        """Extract JWT from specified cookie.

        Returns:
            Raw JWT string from cookie value.

        Raises:
            MissingToken: If cookie is not present in request.

        Security Note:
            Does not validate cookie attributes (HttpOnly, Secure, etc.) as those
            are set server-side when writing cookies. This only reads the value.
        """
        token = request.cookies.get(self._name)

        if not token:
            raise MissingToken(f"Missing cookie '{self._name}'")

        return token
