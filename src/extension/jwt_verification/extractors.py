"""
Token extractors - extract JWT from Flask requests.
"""

from flask import request

from .errors import MissingToken
from .protocols import Extractor


class BearerExtractor(Extractor):
    """
    Extracts the raw JWT from a Flask request.

    Expected format:
        Authorization: Bearer <JWT>
    """

    def extract(self) -> str:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            raise MissingToken("Missing bearer token")
        return auth.split(" ", 1)[1].strip()


class CookieExtractor(Extractor):
    """
    Extracts the raw JWT from a Flask cookie.
    """

    def __init__(self, cookie_name: str = "access_token") -> None:
        self._name = cookie_name

    def extract(self) -> str:
        token = request.cookies.get(self._name)
        if not token:
            raise MissingToken("Missing access token cookie")
        return token
