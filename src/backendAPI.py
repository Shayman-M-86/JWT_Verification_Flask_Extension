import os

from dotenv import load_dotenv

from src.extension.jwt_verification import (
    Auth0JWKSProvider,
    AuthExtension,
    CookieExtractor,
    InMemoryCache,
    JWTVerifier,
    JWTVerifyOptions,
)

load_dotenv()
AUTH0_DOMAIN = os.environ.get("AUTH0_DOMAIN")
issuer = f"https://{AUTH0_DOMAIN}/"
AUTH0_CLIENT_ID = os.environ.get("AUTH0_CLIENT_ID")

ALGORITHMS = ["RS256"]
API_AUDIENCE = os.environ.get("AUTH0_API_AUDIENCE")

jwt_options = JWTVerifyOptions(issuer=issuer, audience=API_AUDIENCE)
provider = Auth0JWKSProvider(issuer, cache=InMemoryCache())
verifier = JWTVerifier(provider, jwt_options)
extractor = CookieExtractor("access_token")
auth = AuthExtension(verifier=verifier, extractor=extractor)

issuer = f"https://{AUTH0_DOMAIN}/"  # must match token's iss exactly (trailing /)
id_opts = JWTVerifyOptions(
    issuer=issuer,
    audience=AUTH0_CLIENT_ID,  # ID token aud == client_id
    algorithms=("RS256",),
)

key_provider = Auth0JWKSProvider(issuer=issuer, cache=InMemoryCache())
id_token_verifier = JWTVerifier(key_provider, id_opts)
