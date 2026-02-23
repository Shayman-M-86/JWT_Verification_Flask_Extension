"""
Auth0 Login Provider - Flask Application

This module provides OAuth 2.0 authentication using Auth0 for a Flask web application.
It handles login, logout, token management, and protected routes.
"""

import os
from urllib.parse import quote_plus, urlencode

from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from flask import Flask, abort, make_response, redirect, render_template, url_for

from src.backendAPI import auth, id_token_verifier
from src.extension.jwt_verification import get_verified_id_claims


def create_app() -> Flask:
    """
    Create and configure the Flask application with Auth0 integration.

    Returns:
        Flask: Configured Flask application instance
    """
    app = Flask(__name__)
    load_dotenv()

    # Auth0 Configuration
    AUTH0_DOMAIN = os.environ.get("AUTH0_DOMAIN")
    AUTH0_CLIENT_ID = os.environ.get("AUTH0_CLIENT_ID")
    AUTH0_CLIENT_SECRET = os.environ.get("AUTH0_CLIENT_SECRET")
    AUTH0_API_AUDIENCE = os.environ.get("AUTH0_API_AUDIENCE")
    FLASK_SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")

    # Validate required environment variables
    if not all(
        [
            AUTH0_DOMAIN,
            AUTH0_CLIENT_ID,
            AUTH0_CLIENT_SECRET,
            AUTH0_API_AUDIENCE,
            FLASK_SECRET_KEY,
        ]
    ):
        raise ValueError(
            "Missing required environment variables for Auth0 configuration"
        )

    app.secret_key = FLASK_SECRET_KEY
    BASE_URL: str = f"https://{AUTH0_DOMAIN}"

    # Configure secure session cookies
    config_dict: dict[str, str | bool] = {
        "SESSION_COOKIE_SECURE": True,  # Requires HTTPS
        "SESSION_COOKIE_SAMESITE": "Lax",
        "SESSION_COOKIE_HTTPONLY": True,
    }
    app.config.update(config_dict)  # type: ignore[arg-type]

    # Initialize JWT verification extension
    auth.init_app(app)

    # Configure OAuth with Auth0
    oauth = OAuth(app)
    auth0 = oauth.register(
        "auth0",
        client_id=AUTH0_CLIENT_ID,
        client_secret=AUTH0_CLIENT_SECRET,
        server_metadata_url=f"{BASE_URL}/.well-known/openid-configuration",
        client_kwargs={"scope": "openid profile email"},
    )

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
            redirect_uri=redirect_uri, audience=AUTH0_API_AUDIENCE
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
        logout_url = f"{BASE_URL}/v2/logout?" + urlencode(
            {
                "returnTo": url_for("home", _external=True, _scheme="https"),
                "client_id": AUTH0_CLIENT_ID,
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
        return render_template("401.html", error=error), 401

    return app
