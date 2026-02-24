"""
Auth0 Login Provider - Flask Application

This module provides OAuth 2.0 authentication using Auth0 for a Flask web application.
It handles login, logout, token management, and protected routes.
"""


from urllib.parse import quote_plus, urlencode

from authlib.integrations.flask_client import OAuth
from flask import (Flask, abort, jsonify, make_response, redirect,
                   render_template, request, url_for)
from flask_cors import CORS

from examples.auth0_demo.app_config import (GLOBAL_CONFIG, auth,
                                            id_token_verifier)
from jwt_verification import get_verified_id_claims


def create_app() -> Flask:
    """
    Create and configure the Flask application with Auth0 integration.

    Returns:
        Flask: Configured Flask application instance
    """
    app = Flask(__name__)

    # Auth0 Configuration
    # Validate required environment variables
    if not all(
        [
            GLOBAL_CONFIG["AUTH0_DOMAIN"],
            GLOBAL_CONFIG["AUTH0_CLIENT_ID"],
            GLOBAL_CONFIG["AUTH0_CLIENT_SECRET"],
            GLOBAL_CONFIG["AUTH0_API_AUDIENCE"],
            GLOBAL_CONFIG["FLASK_SECRET_KEY"],
        ]
    ):
        raise ValueError(
            "Missing required environment variables for Auth0 configuration"
        )

    app.secret_key = GLOBAL_CONFIG["FLASK_SECRET_KEY"]
    base_url: str = f"https://{GLOBAL_CONFIG['AUTH0_DOMAIN']}"

    # Configure secure session cookies
    config_dict: dict[str, str | bool] = {
        "SESSION_COOKIE_SECURE": True,  # Requires HTTPS
        "SESSION_COOKIE_SAMESITE": "Lax",
        "SESSION_COOKIE_HTTPONLY": True,
    }
    app.config.update(config_dict)  # type: ignore[arg-type]

    # Configure CORS for login provider endpoints
    CORS(
        app,
        origins=[
            "https://api.localtest.me:5000",
            "https://api.localtest.me:5001",
        ],
        supports_credentials=True,
        allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
        methods=["GET", "POST", "OPTIONS"],
        max_age=3600,
    )

    # Initialize JWT verification extension
    auth.init_app(app)

    # Configure OAuth with Auth0
    oauth = OAuth(app)
    auth0 = oauth.register(
        "auth0",
        client_id=GLOBAL_CONFIG["AUTH0_CLIENT_ID"],
        client_secret=GLOBAL_CONFIG["AUTH0_CLIENT_SECRET"],
        server_metadata_url=f"{base_url}/.well-known/openid-configuration",
        client_kwargs={"scope": "openid profile email"},
    )

    host = "api.localtest.me"
    app_port = 5000
    print(f"\n🚀 Auth server running at: https://{host}:{app_port}\n")
    # ==================== Routes ====================

    @app.route("/")
    @app.route("/home")
    def home():
        """Render the home page."""
        return render_template("home.html")

    @app.get("/login")
    def login():
        """
        Initiate the Auth0 login flow.

        Redirects the user to Auth0's authorization endpoint.
        """
        redirect_uri = url_for("login_redirect", _external=True, _scheme="https")
        return auth0.authorize_redirect(
            redirect_uri=redirect_uri, audience=GLOBAL_CONFIG["AUTH0_API_AUDIENCE"]
        )

    @app.get("/login-redirect")
    def login_redirect():
        """
        Handle the OAuth callback from Auth0.

        Exchanges the authorization code for access and ID tokens,
        stores them in secure HTTP-only cookies, and redirects to home.
        """
        try:
            token = auth0.authorize_access_token()
        except Exception as e:
            abort(401, description=f"Failed to authorize: {str(e)}")

        access_token = token.get("access_token")
        id_token = token.get("id_token")

        if not access_token:
            abort(401, description="No access token returned from Auth0")

        # Create response and set secure cookies
        resp = make_response(redirect(url_for("home")))

        resp.set_cookie(
            "access_token",
            access_token,
            httponly=True,
            secure=True,
            samesite="Lax",
            path="/",
        )

        if id_token:
            resp.set_cookie(
                "id_token",
                id_token,
                httponly=True,
                secure=True,
                samesite="Lax",
                path="/",
            )

        return resp

    @app.get("/logout")
    def logout():
        """
        Log out the user and clear authentication cookies.

        Redirects to Auth0's logout endpoint and then returns to home.
        """
        logout_url = f"{base_url}/v2/logout?" + urlencode(
            {
                "returnTo": url_for("home", _external=True, _scheme="https"),
                "client_id": GLOBAL_CONFIG["AUTH0_CLIENT_ID"],
            },
            quote_via=quote_plus,
        )

        resp = make_response(redirect(logout_url))

        # Clear authentication cookies
        resp.delete_cookie("access_token", path="/")
        resp.delete_cookie("id_token", path="/")

        return resp

    @app.get("/protected")
    @auth.require()
    def protected():
        """
        Protected profile endpoint that requires valid authentication.

        Displays the user's profile information from the JWT claims.
        """
        try:
            id_claims = get_verified_id_claims(id_token_verifier)
        except Exception:
            id_claims = None
        return render_template("profile.html", user=id_claims)

    # ==================== Error Handlers ====================

    @app.errorhandler(401)
    def unauthorized(error):
        """Handle unauthorized access errors."""
        # Return JSON for API requests
        if request.path.startswith("/api/"):
            return jsonify({
                "status": "denied",
                "message": "Access Denied - Please login first",
                "authenticated": False
            }), 401
        # Return HTML for web routes
        return render_template("401.html", error=error), 401

    return app
