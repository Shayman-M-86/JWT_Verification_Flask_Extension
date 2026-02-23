"""
Auth0 JWKS key provider.

Resolves JWT signing keys from an Auth0 JWKS endpoint with caching and
refresh throttling.
"""

from jwt import PyJWK, PyJWKClient

from ..cache_stores import InMemoryCache
from ..errors import InvalidToken
from ..protocols import CacheStore, KeyProvider
from ..refresh_gate import RefreshGate


class Auth0JWKSProvider(KeyProvider):
    """
    Resolves JWT signing keys from an Auth0 JWKS endpoint with caching and
    refresh throttling.

    Responsibilities
    ----------------
    1. Resolve the correct signing key for a given `kid`.
    2. Cache resolved keys locally to avoid repeated lookups.
    3. Negative-cache unknown `kid` values to make attacker traffic cheap.
    4. Rate-limit forced JWKS refresh operations to prevent outbound DoS.
    5. Provide a clean abstraction over PyJWKClient for application code.

    Resolution Strategy
    -------------------
    For each requested `kid`:

    1) Cache lookup (fast path)
        - If key is cached → return immediately.

    2) Normal resolution
        - Attempt `PyJWKClient.get_signing_key(kid)`
        - PyJWT may internally refresh once if the key is missing.

    3) Negative caching
        - If resolution fails, the `kid` is cached as "missing" for a short TTL.
        - Prevents repeated expensive lookups for attacker-provided random keys.

    4) Forced refresh (rate-limited)
        - If still unresolved and the RefreshGate allows:
              fetch JWKS with refresh=True
              retry resolution once
        - If throttled, fail fast.

    5) Failure
        - Raises InvalidToken if key cannot be resolved.

    Security Properties
    -------------------
    Protects against:
        - Random `kid` spam attacks
        - Outbound JWKS request amplification
        - Cache bypass attempts

    Maintains compatibility with:
        - Legitimate key rotation
        - Auth0 JWKS updates
        - Short-lived cache invalidation

    Parameters
    ----------
    issuer : str
        Issuer base URL (e.g., "https://tenant.auth0.com/").
        JWKS URL is derived as `{issuer}.well-known/jwks.json`.

    cache : CacheStore
        Cache implementation for resolved keys.
        May support negative caching via `set_missing`.

    ttl_seconds : int
        TTL for successfully resolved signing keys.

    missing_ttl_seconds : int
        TTL for negative cache entries (unknown kids).

    min_interval : float
        Minimum interval between forced JWKS refresh attempts.

    alert_threshold : int
        Denial threshold before optional alerting in RefreshGate.

    Notes
    -----
    - PyJWKClient already caches the JWKS set internally.
      This provider adds:
          • per-kid caching
          • negative caching
          • refresh throttling
          • multi-store compatibility

    - RefreshGate operates per process.
      For horizontally scaled systems, consider distributed coordination.

    - Negative caching dramatically reduces attacker impact by converting
      repeated invalid `kid` attempts into constant-time failures.

    Example
    -------
    provider = Auth0JWKSProvider(
        issuer="https://example.auth0.com/",
        cache=InMemoryCache(),
    )

    key = provider.get_key_for_token(kid)
    """

    def __init__(
        self,
        issuer: str,
        cache: CacheStore | None = None,
        ttl_seconds: int = 600,
        missing_ttl_seconds: int = 30,
        min_interval: float = 60.0,
        alert_threshold: int = 40,
    ) -> None:
        self._ttl = ttl_seconds
        self._missing_ttl = missing_ttl_seconds
        self._cache = cache or InMemoryCache()
        self._gate = RefreshGate(
            min_interval=min_interval, alert_threshold=alert_threshold
        )
        self._client = PyJWKClient(
            f"{issuer}.well-known/jwks.json",
            cache_jwk_set=True,
            lifespan=ttl_seconds,
        )

    def get_key_for_token(self, kid: str) -> PyJWK:
        cached = self._cache.get(kid)

        # If you implement set_missing(), cached may be None meaning "known missing"
        if cached is None and kid in getattr(self._cache, "_store", {}):
            # known missing (in-memory example); for a real CacheStore add explicit API
            raise InvalidToken("Unknown kid (cached)")

        if cached:
            return cached

        # 1) Try normal resolution (PyJWT may refresh-on-miss internally once)
        try:
            jwk = self._client.get_signing_key(kid)
            self._cache.set(jwk, ttl_seconds=self._ttl)
            return jwk
        except Exception:
            # negative-cache this kid to make spam cheap
            if hasattr(self._cache, "set_missing"):
                self._cache.set_missing(kid, ttl_seconds=self._missing_ttl)

        # 2) Optional forced refresh, but rate-limited
        if not self._gate.allow():
            raise InvalidToken("Key refresh throttled")

        # Force refresh of JWKS set, then retry once
        try:
            self._client.get_signing_keys(refresh=True)  # forces JWKS fetch
            jwk = self._client.get_signing_key(kid)
            self._cache.set(jwk, ttl_seconds=self._ttl)
            return jwk
        except Exception as e:
            if hasattr(self._cache, "set_missing"):
                self._cache.set_missing(kid, ttl_seconds=self._missing_ttl)
            raise InvalidToken("Unable to resolve signing key") from e
