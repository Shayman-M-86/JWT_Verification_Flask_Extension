"""
Cache store implementations for caching resolved signing keys.
"""

import json
import time
from dataclasses import dataclass
from typing import Any, Optional

from jwt import PyJWK


@dataclass
class _CacheItem:
    """Internal cache item with TTL support."""

    value: PyJWK | None  # None means "known-missing"
    expires_at: float


class InMemoryCache:
    """
    Simple in-process cache.

    Good for:
    - local dev
    - single instance deployments

    Not ideal for:
    - multiple processes/containers (each has its own cache)

    Implementation details:
    - TTL is tracked with expiration timestamps
    - Expired items are removed on access
    - Known-missing cached as value=None
    """

    def __init__(self) -> None:
        self._store: dict[str, _CacheItem] = {}

    def get(self, kid: str) -> Optional[PyJWK]:
        item = self._store.get(kid)
        if not item:
            return None
        if time.time() >= item.expires_at:
            self._store.pop(kid, None)
            return None
        return item.value  # may be None (known-missing)

    def set(self, key: PyJWK, ttl_seconds: int) -> None:
        kid = key.key_id
        if not kid:
            raise ValueError("Key must have kid")
        self._store[kid] = _CacheItem(value=key, expires_at=time.time() + ttl_seconds)

    def set_missing(self, kid: str, ttl_seconds: int) -> None:
        self._store[kid] = _CacheItem(value=None, expires_at=time.time() + ttl_seconds)

    def is_missing(self, kid: str) -> bool:
        item = self._store.get(kid)
        if not item:
            return False
        if time.time() >= item.expires_at:
            self._store.pop(kid, None)
            return False
        return item.value is None  # known-missing if value is None


class RedisCache:
    """
    Redis-backed cache store.

    Behavior:
    - Stores the underlying JWK dict as JSON under key=kid
    - Uses Redis TTL (setex) to expire automatically

    NOTE:
    - Uses a private attribute `key._jwk_data` to serialize.
      Consider wrapping PyJWK storage in your own DTO if you want to avoid private usage.
    """

    def __init__(self, redis_client: Any) -> None:
        self._client = redis_client

    def get(self, kid: str) -> Optional[PyJWK]:
        data = self._client.get(kid)
        if data is None:
            return None
        try:
            return PyJWK.from_dict(json.loads(data))
        except Exception as e:
            raise RuntimeError("Failed to parse cached key") from e

    def set(self, key: PyJWK, ttl_seconds: int) -> None:
        try:
            kid = key.key_id
            if kid is None:
                raise ValueError("Key must have a key_id (kid) to be cached")
            self._client.setex(
                kid,
                ttl_seconds,
                json.dumps(key._jwk_data),  # pyright: ignore[reportPrivateUsage]
            )
        except Exception as e:
            raise RuntimeError("Failed to set cache") from e

    def set_missing(self, kid: str, ttl_seconds: int) -> None:
        """Cache a known-missing kid (negative cache)."""
        try:
            self._client.setex(kid, ttl_seconds, json.dumps({"__missing__": True}))
        except Exception as e:
            raise RuntimeError("Failed to set missing cache") from e

    def is_missing(self, kid: str) -> bool:
        """Check if a kid is cached as missing."""
        data = self._client.get(kid)
        if data is None:
            return False
        try:
            obj = json.loads(data)
            return obj.get("__missing__") is True
        except Exception:
            return False
