import os

from dotenv import load_dotenv

from jwt_verification import (
    Auth0JWKSProvider,
    AuthExtension,
    CookieExtractor,
    InMemoryCache,
    JWTVerifier,
    JWTVerifyOptions,
)

load_dotenv()
GLOBAL_CONFIG = {
    "AUTH0_DOMAIN": os.environ.get("AUTH0_DOMAIN"),
    "AUTH0_CLIENT_ID": os.environ.get("AUTH0_CLIENT_ID"),
    "AUTH0_CLIENT_SECRET": os.environ.get("AUTH0_CLIENT_SECRET"),
    "AUTH0_API_AUDIENCE": os.environ.get("AUTH0_API_AUDIENCE"),
    "FLASK_SECRET_KEY": os.environ.get("FLASK_SECRET_KEY"),
}

AUTH0_DOMAIN = GLOBAL_CONFIG["AUTH0_DOMAIN"]
AUTH0_CLIENT_ID = GLOBAL_CONFIG["AUTH0_CLIENT_ID"]
AUTH0_CLIENT_SECRET = GLOBAL_CONFIG["AUTH0_CLIENT_SECRET"]
AUTH0_API_AUDIENCE = GLOBAL_CONFIG["AUTH0_API_AUDIENCE"]
FLASK_SECRET_KEY = GLOBAL_CONFIG["FLASK_SECRET_KEY"]
ALGORITHMS = ["RS256"]
ISSUER = f"https://{AUTH0_DOMAIN}/"




#configuration for JWT verification
access_options = JWTVerifyOptions(issuer=ISSUER, audience=AUTH0_API_AUDIENCE)
access_provider = Auth0JWKSProvider(ISSUER, cache=InMemoryCache())
access_verifier = JWTVerifier(access_provider, access_options)
access_extractor = CookieExtractor("access_token")
# auth will be the ext imported in the Flask app
auth = AuthExtension(verifier=access_verifier, extractor=access_extractor)

# configuration ID_token verification
id_opts = JWTVerifyOptions(issuer=ISSUER, audience=AUTH0_CLIENT_ID)
id_provider = Auth0JWKSProvider(issuer=ISSUER, cache=InMemoryCache())
# id_token_verifier will be imported in the login provider to verify the
# ID token returned by Auth0 after login
id_token_verifier = JWTVerifier(id_provider, id_opts)
