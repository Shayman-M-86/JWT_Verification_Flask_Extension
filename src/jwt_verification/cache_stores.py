"""Cache store implementations for JWT signing keys.

This module provides implementations of the CacheStore protocol for caching
resolved signing keys to improve performance and reduce load on JWKS endpoints.

Implementations:
- InMemoryCache: Simple in-process caching (good for dev/single-instance)
- RedisCache: Distributed caching via Redis (good for multi-instance production)

Both implementations support:
- TTL-based expiration
- Negative caching (remembering missing keys to avoid repeated lookups)
- Thread-safe operations

Security Note:
    Caching keys improves performance but introduces a TTL window where rotated
    keys may not be immediately recognized. Balance cache TTL against key rotation
    frequency and security requirements.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from jwt import PyJWK


@dataclass(slots=True)
class _CacheItem:
    """Internal cache entry with TTL tracking.

    Attributes:
        value: PyJWK object if cached, None if key is known-missing (negative cache).
        expires_at: Unix timestamp when this entry should be considered expired.
    """

    value: PyJWK | None  # None means "known-missing" (negative cache)
    expires_at: float


class InMemoryCache:
    """In-process memory cache for JWT signing keys.

    This cache stores PyJWK objects in a Python dict with TTL-based expiration.
    Expired entries are lazily removed on access.


    Storage Behavior:
        - Valid keys: Stored as PyJWK objects with expiration timestamp
        - Missing keys: Stored as None (negative caching) with expiration
        - Expired entries: Removed lazily on next access

    Example:
        ```python
        cache = InMemoryCache()

        # Cache a key
        cache.set(pyjwk_object, ttl_seconds=300)

        # Retrieve key
        key = cache.get("key-id-123")  # Returns PyJWK or None

        # Negative caching
        cache.set_missing("bad-kid", ttl_seconds=60)
        assert cache.is_missing("bad-kid") is True
        ```

    Attributes:
        _store: Internal dict mapping kid -> _CacheItem.
    """

    def __init__(self) -> None:
        """Initialize an empty in-memory cache."""
        self._store: dict[str, _CacheItem] = {}

    def get(self, kid: str) -> PyJWK | None:
        """Retrieve a cached key by ID.

        Args:
            kid: Key ID to lookup.

        Returns:
            PyJWK object if cached and not expired, None otherwise.

        Note:
            Returns None for both "not cached" and "cached as missing". Use
            is_missing() to distinguish if needed.
        """
        item = self._store.get(kid)
        if not item:
            return None

        if time.time() >= item.expires_at:
            # Lazy removal of expired entry
            self._store.pop(kid, None)
            return None

        return item.value

    def set(self, key: PyJWK, ttl_seconds: int) -> None:
        """Cache a signing key with TTL.

        Args:
            key: PyJWK object to cache (must have key_id populated).
            ttl_seconds: Time-to-live in seconds.

        Raises:
            ValueError: If key doesn't have a key_id.

        Security Note:
            Ensure ttl_seconds balances performance vs. key rotation freshness.
            Typical values: 300-3600 seconds.
        """
        kid = key.key_id
        if not kid:
            raise ValueError("PyJWK must have key_id populated to be cached")

        self._store[kid] = _CacheItem(value=key, expires_at=time.time() + ttl_seconds)

    def set_missing(self, kid: str, ttl_seconds: int) -> None:
        """Mark a key ID as missing (negative caching).

        This prevents repeated failed lookups for non-existent keys, protecting
        against certain DoS attacks where attackers send tokens with invalid kids.

        Args:
            kid: Key ID that was looked up but not found.
            ttl_seconds: Time-to-live for the negative cache entry.

        Security Note:
            Negative caching is important for DoS protection, but shorter TTLs
            are recommended (e.g., 60-300 seconds) to allow for key rotation.
        """
        self._store[kid] = _CacheItem(value=None, expires_at=time.time() + ttl_seconds)

    def is_missing(self, kid: str) -> bool:
        """Check if a key ID is marked as missing.

        Args:
            kid: Key ID to check.

        Returns:
            True if kid is cached as missing and not expired, False otherwise.
        """
        item = self._store.get(kid)
        if not item:
            return False

        # Check expiration
        if time.time() >= item.expires_at:
            self._store.pop(kid, None)
            return False

        # is_missing means value is None (negative cache)
        return item.value is None


class RedisCache:
    """Redis-backed distributed cache for JWT signing keys.

    This cache stores PyJWK objects as JSON in Redis, using Redis's native TTL
    mechanisms for expiration.


    Storage Format:
        - Valid keys: JSON serialization of PyJWK internal dict
        - Missing keys: Special JSON marker {"__missing__": true}

    Dependencies:
        Requires redis package: pip install redis

    Example:
        ```python
        import redis

        client = redis.Redis(host='localhost', port=6379, decode_responses=True)
        cache = RedisCache(redis_client=client)

        # Cache a key
        cache.set(pyjwk_object, ttl_seconds=300)

        # Retrieve key
        key = cache.get("key-id-123")  # Returns PyJWK or None

        # Negative caching
        cache.set_missing("bad-kid", ttl_seconds=60)
        assert cache.is_missing("bad-kid") is True
        ```

    Attributes:
        _client: Redis client instance (from redis package).
    """

    def __init__(self, redis_client: Any) -> None:
        """Initialize Redis cache.

        Args:
            redis_client: Redis client instance (from redis package).
                         Must support get() and setex() methods.

        Note:
            The type is Any to avoid hard dependency on redis package types.
            Users can pass any Redis-compatible client (redis-py, fakeredis, etc.).
        """
        self._client = redis_client

    def get(self, kid: str) -> PyJWK | None:
        """Retrieve a cached key by ID.

        Args:
            kid: Key ID to lookup.

        Returns:
            PyJWK object if cached, None if not found or cached as missing.

        Raises:
            RuntimeError: If deserialization fails (corrupted cache data).

        Note:
            Redis handles expiration automatically via TTL.
        """
        from jwt import PyJWK

        data = self._client.get(kid)
        if data is None:
            return None

        try:
            obj = json.loads(data)

            # Check for negative cache marker
            if obj.get("__missing__") is True:
                return None

            # Deserialize PyJWK from internal dict representation
            return PyJWK.from_dict(obj)

        except (json.JSONDecodeError, ValueError, KeyError) as e:
            raise RuntimeError("Failed to deserialize cached key") from e

    def set(self, key: PyJWK, ttl_seconds: int) -> None:
        """Cache a signing key with TTL.

        Args:
            key: PyJWK object to cache (must have key_id populated).
            ttl_seconds: Time-to-live in seconds.

        Raises:
            ValueError: If key doesn't have a key_id.
            RuntimeError: If Redis operation fails.

        Implementation Note:
            Uses PyJWK's internal _jwk_data dict for serialization. This is
            technically private API usage but necessary for round-trip serialization.
        """
        kid = key.key_id
        if not kid:
            raise ValueError("PyJWK must have key_id populated to be cached")

        try:
            # Serialize PyJWK's internal dict to JSON
            self._client.setex(
                kid,
                ttl_seconds,
                json.dumps(key._jwk_data),  # pyright: ignore[reportPrivateUsage]
            )
        except Exception as e:
            raise RuntimeError("Failed to cache key in Redis") from e

    def set_missing(self, kid: str, ttl_seconds: int) -> None:
        """Mark a key ID as missing (negative caching).

        Args:
            kid: Key ID that was looked up but not found.
            ttl_seconds: Time-to-live for the negative cache entry.

        Raises:
            RuntimeError: If Redis operation fails.

        Implementation Note:
            Stores a special JSON marker {"__missing__": true} to distinguish
            from actual keys.
        """
        try:
            self._client.setex(
                kid,
                ttl_seconds,
                json.dumps({"__missing__": True}),
            )
        except Exception as e:
            raise RuntimeError("Failed to cache missing key in Redis") from e

    def is_missing(self, kid: str) -> bool:
        """Check if a key ID is marked as missing.

        Args:
            kid: Key ID to check.

        Returns:
            True if kid is cached as missing, False otherwise.

        Note:
            Returns False if deserialization fails (corrupted data).
        """
        data = self._client.get(kid)
        if data is None:
            return False

        try:
            obj = json.loads(data)
            return obj.get("__missing__") is True
        except (json.JSONDecodeError, ValueError):
            # Corrupted data, treat as not missing
            return False
