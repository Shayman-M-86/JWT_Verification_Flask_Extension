
from src.extension.JWT_verification import AuthExtension, InMemoryCache, JWTVerifier, Auth0JWKSProvider, JWTVerifyOptions, CookieExtractor
AUTH0_DOMAIN = "dev-3wccg4jx4o5wvedn.au.auth0.com"
issuer = f"https://{AUTH0_DOMAIN}/"

ALGORITHMS = ["RS256"]
API_AUDIENCE = "test-system"

jwt_options = JWTVerifyOptions(issuer=issuer, audience=API_AUDIENCE)
provider = Auth0JWKSProvider(issuer, cache=InMemoryCache())
verifier = JWTVerifier(provider, jwt_options)
extractor = CookieExtractor("access_token")
auth = AuthExtension(verifier=verifier, extractor=extractor)



