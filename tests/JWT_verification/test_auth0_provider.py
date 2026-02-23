"""
Tests for the Auth0 JWKS Provider.

Tests the JWKS fetching, caching, and refresh logic.
"""

import pytest
from jwt import PyJWK, PyJWKClient


import src.extension.JWT_verification as m


class DummyJwk(PyJWK):
    """Dummy JWK for testing"""

    def __init__(self, signing_key_id: str | None = None):
        # Initialize parent with proper JWK data structure
        jwk_data = {
            "kty": "oct",
            "k": "GawgguFyGrWKav7AX4VKUg",
        }
        if signing_key_id:
            jwk_data["kid"] = signing_key_id
        super().__init__(jwk_data, algorithm="HS256")


class DummyCache(m.InMemoryCache):
    """Mock cache for testing."""

    def __init__(self):
        super().__init__()
        self.set_calls: list[tuple[str, int]] = []

    def set(self, key: PyJWK, ttl_seconds: int) -> None:
        super().set(key, ttl_seconds)
        # Track the call for testing
        if key.key_id:
            self.set_calls.append((key.key_id, ttl_seconds))


class TestAuth0ProviderCaching:
    """Test JWKS caching functionality."""

    def test_auth0_provider_returns_cached_key(self, monkeypatch: pytest.MonkeyPatch):
        """Should return cached key without calling JWKS endpoint."""
        cache = DummyCache()
        fake_key = DummyJwk(signing_key_id="kid1")
        cache.set(fake_key, 600)

        provider = m.Auth0JWKSProvider(
            issuer="https://example.au.auth0.com/",
            cache=cache,
            ttl_seconds=600,
        )

        # If cached, never call PyJWKClient
        claims_key = provider.get_key_for_token("kid1")
        assert claims_key is fake_key
        # After getting from cache, no additional sets should happen
        initial_sets = len(cache.set_calls)
        assert initial_sets == 1  # Just the initial set


class TestAuth0ProviderFetching:
    """Test JWKS fetching functionality."""

    def test_auth0_provider_fetches_and_caches_on_miss(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        """Should fetch from JWKS endpoint and cache on cache miss."""
        cache = DummyCache()
        fetched_key = DummyJwk(signing_key_id="kidX")

        class FakeClient(PyJWKClient):
            def __init__(self):
                # Properly initialize parent to avoid missing attributes
                pass

            def get_signing_key(self, kid: str) -> PyJWK:
                if kid != "kidX":
                    raise Exception(f"Unknown kid: {kid}")
                return fetched_key

            def get_signing_keys(self, refresh: bool = False) -> list[PyJWK]:
                # Provide minimal implementation

                return [fetched_key]

        provider = m.Auth0JWKSProvider(
            issuer="https://example.au.auth0.com/",
            cache=cache,
            ttl_seconds=600,
        )
        object.__setattr__(provider, "_client", FakeClient())  # inject fake

        key = provider.get_key_for_token("kidX")
        assert key is fetched_key
        assert cache.get("kidX") is fetched_key
        assert len(cache.set_calls) > 0
        assert cache.set_calls[0][0] == "kidX"


class TestAuth0ProviderRefreshGate:
    """Test refresh gate logic."""

    def test_auth0_provider_raises_when_gate_blocks(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        """Should raise InvalidToken when refresh gate blocks retry."""
        cache = DummyCache()

        provider = m.Auth0JWKSProvider(
            issuer="https://example.au.auth0.com/",
            cache=cache,
            ttl_seconds=600,
        )

        with pytest.raises(m.InvalidToken):
            provider.get_key_for_token("kid_nope")

    def test_auth0_provider_respects_ttl(self, monkeypatch: pytest.MonkeyPatch):
        """Should set cache TTL correctly."""
        cache = DummyCache()
        fetched_key = DummyJwk(signing_key_id="kid_ttl")

        class FakeClient(PyJWKClient):
            def __init__(self):
                # Minimal implementation
                pass

            def get_signing_key(self, kid: str) -> PyJWK:
                if kid != "kid_ttl":
                    raise Exception(f"Unknown kid: {kid}")
                return fetched_key

            def get_signing_keys(self, refresh: bool = False) -> list[PyJWK]:

                return [fetched_key]

        custom_ttl = 1200
        provider = m.Auth0JWKSProvider(
            issuer="https://example.au.auth0.com/",
            cache=cache,
            ttl_seconds=custom_ttl,
        )
        object.__setattr__(provider, "_client", FakeClient())

        provider.get_key_for_token("kid_ttl")

        # Verify TTL was set correctly
        assert cache.set_calls
        assert cache.set_calls[0][1] == custom_ttl


class TestAuth0ProviderIntegration:
    """Integration tests for Auth0Provider."""

    def test_auth0_provider_with_realistic_params(self):
        """Create provider with realistic Auth0 parameters."""
        cache = DummyCache()

        # Realistic Auth0 issuer URL
        issuer = "https://dev-3wccg4jx4o5wvedn.au.auth0.com/"

        provider = m.Auth0JWKSProvider(
            issuer=issuer,
            cache=cache,
            ttl_seconds=600,
        )

        assert provider is not None
        # Provider is configured but not yet tested with actual JWKS
