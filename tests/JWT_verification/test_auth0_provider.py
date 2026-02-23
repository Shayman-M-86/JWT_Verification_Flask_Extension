import pytest
from jwt import PyJWK, PyJWKClient

import src.extension.JWT_verification as m


class DummyJwk(PyJWK):
    """Dummy JWK for testing"""

    def __init__(self, signing_key_id: str | None = None):
        self.signing_key_id = signing_key_id


class DummyCache(m.CacheStore):
    def __init__(self):
        self._d: dict[str, PyJWK] = {}
        self.set_calls: list[tuple[str, int]] = []

    def get(self, kid: str) -> PyJWK | None:
        return self._d.get(kid)

    def set(self, key: PyJWK, ttl_seconds: int):
        if not isinstance(key, DummyJwk):
            raise TypeError("Expected DummyJwk for testing")
        if key.signing_key_id is None:
            raise ValueError("key.signing_key_id cannot be None")
        self._d[key.signing_key_id] = key
        self.set_calls.append((key.signing_key_id, ttl_seconds))


class DummyGate(m.RefreshGate):
    def __init__(self, allow_retry_result: bool):
        # bypass parent init
        self._allow_retry_result = allow_retry_result

    def allow_retry(self) -> bool:
        return self._allow_retry_result


def test_auth0_provider_returns_cached_key(monkeypatch: pytest.MonkeyPatch):
    cache = DummyCache()
    fake_key = DummyJwk(signing_key_id="kid1")
    fake_key.signing_key_id = "kid1"
    cache.set(fake_key, 600)

    provider = m.Auth0JWKSProvider(
        domain="example.au.auth0.com",
        cache=cache,
        ttl_seconds=600,
        Gate=DummyGate(True),
    )

    # If cached, never call PyJWKClient
    claims_key = provider.get_key_for_token("kid1")
    assert claims_key is fake_key


def test_auth0_provider_fetches_and_caches_on_miss(monkeypatch: pytest.MonkeyPatch):
    cache = DummyCache()

    fetched_key = DummyJwk(signing_key_id="kidX")

    class FakeClient(PyJWKClient):
        def __init__(self):
            pass

        def get_signing_key(self, kid: str) -> PyJWK:
            assert kid == "kidX"
            return fetched_key

    provider = m.Auth0JWKSProvider(
        domain="example.au.auth0.com",
        cache=cache,
        ttl_seconds=600,
        Gate=DummyGate(True),
    )
    object.__setattr__(provider, "_client", FakeClient())  # inject fake

    key = provider.get_key_for_token("kidX")
    assert key is fetched_key
    assert cache.get("kidX") is fetched_key
    assert cache.set_calls[0][0] == "kidX"


def test_auth0_provider_raises_when_gate_blocks(monkeypatch: pytest.MonkeyPatch):
    cache = DummyCache()

    provider = m.Auth0JWKSProvider(
        domain="example.au.auth0.com",
        cache=cache,
        ttl_seconds=600,
        Gate=DummyGate(False),
    )

    with pytest.raises(m.InvalidToken):
        provider.get_key_for_token("kid_nope")
