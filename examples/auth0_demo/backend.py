from flask import Flask, jsonify
from flask_cors import CORS

from examples.auth0_demo.app_config import auth


def create_app() -> Flask:
    """
    Create and configure the Flask application with Auth0 integration.

    Returns:
        Flask: Configured Flask application instance
    """
    app = Flask(__name__)
    auth.init_app(app)

    # Configure CORS to allow requests from login provider
    CORS(
        app,
        origins=[
            "https://api.localtest.me:5000",
            "https://localhost:5000",
            "https://127.0.0.1:5000",
        ],
        supports_credentials=True,
        allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
        methods=["GET", "POST", "OPTIONS"],
        max_age=3600,
    )

    @app.get("/api/test-access")
    @auth.require()
    def test_access():
        """
        Test endpoint to check if user is authenticated.
        Returns JSON with authentication status for frontend testing.
        """
        return jsonify(
            {"status": "success", "message": "Permission Granted ✓", "authenticated": True}
        ), 200

    # Error handler for unauthorized access
    @app.errorhandler(401)
    def unauthorized(error):
        """Handle unauthorized access errors."""
        return jsonify(
            {
                "status": "denied",
                "message": "Access Denied - Please login first",
                "authenticated": False,
            }
        ), 401

    @app.errorhandler(403)
    def forbidden(error):
        """Handle forbidden access errors."""
        return jsonify(
            {
                "status": "denied",
                "message": "Access Denied - You do not have permission to access this resource",
                "authenticated": True,
            }
        ), 403

    @app.errorhandler(500)
    def internal_error(error):
        """Handle internal server errors."""
        return jsonify(
            {
                "status": "error",
                "message": "An unexpected error occurred. Please try again later.",
            }
        ), 500

    @app.errorhandler(404)
    def not_found(error):
        """Handle not found errors."""
        return jsonify(
            {
                "status": "error",
                "message": "Resource not found.",
            }
        ), 404

    return app
