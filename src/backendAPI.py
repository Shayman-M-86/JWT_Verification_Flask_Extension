from flask import Flask, jsonify
from src.extension.JWT_verification import AuthExtension, InMemoryCache, JWTVerifier, Auth0JWKSProvider, JWTVerifyOptions
AUTH0_DOMAIN = "dev-3wccg4jx4o5wvedn.au.auth0.com"
issuer = f"https://{AUTH0_DOMAIN}/"

ALGORITHMS = ["RS256"]
API_AUDIENCE = "test-system"

jwt_options = JWTVerifyOptions(issuer=issuer, audience=API_AUDIENCE)
provider = Auth0JWKSProvider(AUTH0_DOMAIN, cache=InMemoryCache())
verifier = JWTVerifier(provider, jwt_options)
auth = AuthExtension(verifier=verifier)

app = Flask(__name__)
auth.init_app(app)

@app.route("/protected")
@auth.require()
def protected():
    return jsonify(message="This is a protected endpoint"), 200