import time
import pytest
from flask import Flask

from jwt import PyJWK
from jwt.utils import base64url_encode


@pytest.fixture()
def app():
    app = Flask(__name__)
    app.config["TESTING"] = True
    return app


@pytest.fixture
def make_oct_jwk():
    """
    Factory fixture that returns a function.

    Usage in tests:
        jwk = make_oct_jwk(kid="k1")
    """

    def _make(*, kid: str = "kid1", secret: bytes = b"supersecret") -> PyJWK:
        jwk_dict = {
            "kty": "oct",
            "kid": kid,
            "k": base64url_encode(secret).decode("ascii"),
            "alg": "HS256",
            "use": "sig",
        }
        return PyJWK.from_dict(jwk_dict)

    return _make


class FakeRedis:
    """
    Minimal redis stub for redisCache tests.
    Stores bytes under keys and supports setex.
    """

    def __init__(self):
        self._store: dict[str, tuple[bytes, int]] = {}

    def get(self, key: str):
        item = self._store.get(key)
        if item is None:
            return None
        data, expires_at = item
        if int(time.time()) >= expires_at:
            self._store.pop(key, None)
            return None
        return data

    def setex(self, key: str, ttl_seconds: int, value: str | bytes):
        expires_at = int(time.time()) + int(ttl_seconds)
        if isinstance(value, str):
            value = value.encode("utf-8")
        self._store[key] = (value, expires_at)

@pytest.fixture
def fake_redis() -> FakeRedis:
    return FakeRedis()