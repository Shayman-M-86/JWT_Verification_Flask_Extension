import pytest
from typing import Any, cast

import src.extension.JWT_verification as m
from jwt import PyJWK
from _pytest.monkeypatch import MonkeyPatch


class DummyProvider:
    """Duck-typed KeyProvider for tests."""

    def __init__(self, key: PyJWK):
        self._key = key
        self.kid: str | None = None

    def get_key_for_token(self, kid: str) -> PyJWK:
        self.kid = kid
        return self._key


def test_jwtverifier_reads_kid_and_calls_keyprovider(monkeypatch: MonkeyPatch):
    dummy_key = cast(
        PyJWK, object()
    )  # we don't need a real PyJWK; only identity checks

    provider = DummyProvider(dummy_key)
    verifier = m.JWTVerifier(
        cast(m.KeyProvider, provider),  # tell the type checker it conforms structurally
        m.JWTVerifyOptions(issuer="iss", audience="aud", algorithms=("RS256",)),
    )

    monkeypatch.setattr(m.jwt, "get_unverified_header", lambda _t: {"kid": "kid123"})  # type: ignore

    def fake_decode(*args: Any, **kwargs: Any):
        # jwt.decode(token, key, algorithms=[...], audience=..., issuer=...)
        token = args[0]
        key = args[1]
        assert token == "TOKEN"
        assert key is dummy_key
        assert kwargs["algorithms"] == ["RS256"]
        assert kwargs["audience"] == "aud"
        assert kwargs["issuer"] == "iss"
        return {"sub": "u1"}

    monkeypatch.setattr(m.jwt, "decode", fake_decode)

    claims = verifier.verify("TOKEN")
    assert claims["sub"] == "u1"
    assert provider.kid == "kid123"


def test_jwtverifier_missing_kid(monkeypatch: MonkeyPatch):
    dummy_key = cast(PyJWK, object())
    provider = DummyProvider(dummy_key)

    verifier = m.JWTVerifier(
        cast(m.KeyProvider, provider),
        m.JWTVerifyOptions(issuer=None, audience=None),
    )

    monkeypatch.setattr(m.jwt, "get_unverified_header", lambda: {})  # type: ignore # no kid

    with pytest.raises(m.InvalidToken):
        verifier.verify("TOKEN")


def test_jwtverifier_expired_maps_to_domain_error(monkeypatch: MonkeyPatch):
    dummy_key = cast(PyJWK, object())
    provider = DummyProvider(dummy_key)

    verifier = m.JWTVerifier(
        cast(m.KeyProvider, provider),
        m.JWTVerifyOptions(issuer=None, audience=None),
    )

    monkeypatch.setattr(m.jwt, "get_unverified_header", lambda _t: {"kid": "k1"}) # type: ignore

    def fake_decode(*args: Any, **kwargs: Any):
        raise m.jwt.ExpiredSignatureError("expired")

    monkeypatch.setattr(m.jwt, "decode", fake_decode)

    with pytest.raises(m.ExpiredToken):
        verifier.verify("TOKEN")


def test_jwtverifier_invalid_maps_to_domain_error(monkeypatch: MonkeyPatch):
    dummy_key = cast(PyJWK, object())
    provider = DummyProvider(dummy_key)

    verifier = m.JWTVerifier(
        cast(m.KeyProvider, provider),
        m.JWTVerifyOptions(issuer=None, audience=None),
    )

    monkeypatch.setattr(m.jwt, "get_unverified_header", lambda _t: {"kid": "k1"})  # type: ignore

    def fake_decode(*args: Any, **kwargs: Any):
        raise m.jwt.InvalidTokenError("bad")

    monkeypatch.setattr(m.jwt, "decode", fake_decode)

    with pytest.raises(m.InvalidToken):
        verifier.verify("TOKEN")
