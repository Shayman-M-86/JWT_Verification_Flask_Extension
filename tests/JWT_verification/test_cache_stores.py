from collections.abc import Callable
from typing import Any

import pytest

import jwt_verification as m


def test_inmemory_cache_set_get(make_oct_jwk: Callable[..., Any]):
    cache = m.InMemoryCache()
    jwk = make_oct_jwk(kid="k1")

    cache.set(jwk, ttl_seconds=60)
    assert cache.get("k1") is jwk


def test_inmemory_cache_requires_kid():
    cache = m.InMemoryCache()

    # Fake key with no key_id
    class K:
        key_id = None

    with pytest.raises(ValueError):
        cache.set(K(), ttl_seconds=60)  # type: ignore[arg-type]


def test_redis_cache_roundtrip(
    fake_redis: Callable[..., Any], make_oct_jwk: Callable[..., Any]
):

    cache = m.RedisCache(fake_redis)  # type: ignore

    jwk = make_oct_jwk(kid="k2")
    cache.set(jwk, ttl_seconds=60)

    loaded = cache.get("k2")
    assert loaded is not None
    assert loaded.key_id == "k2"


def test_redis_cache_invalid_json_raises(fake_redis: Callable[..., Any]):
    cache = m.RedisCache(fake_redis)  # type: ignore

    fake_redis.setex("bad", 60, "not-json")  # type: ignore
    with pytest.raises(RuntimeError):
        cache.get("bad")
