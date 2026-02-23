# Usage Examples

This document provides comprehensive examples for common JWT verification scenarios.

## Table of Contents

1. [Basic Setup](#basic-setup)
2. [Authentication Examples](#authentication-examples)
3. [Authorization Examples](#authorization-examples)
4. [Custom Implementations](#custom-implementations)
5. [Integration Examples](#integration-examples)
6. [Testing Examples](#testing-examples)
7. [Production Patterns](#production-patterns)

---

## Basic Setup

### Minimal Setup

```python
from flask import Flask
from jwt_verification import (
    AuthExtension,
    Auth0JWKSProvider,
    JWTVerifier,
    JWTVerifyOptions,
)

app = Flask(__name__)

# Configure Auth0 integration
provider = Auth0JWKSProvider(
    issuer="https://your-tenant.auth0.com/",
)

verifier = JWTVerifier(
    key_provider=provider,
    options=JWTVerifyOptions(
        issuer="https://your-tenant.auth0.com/",
        audience="your-api-identifier",
    ),
)

auth = AuthExtension(verifier=verifier)

@app.route("/protected")
@auth.require()
def protected():
    return {"message": "You are authenticated!"}
```

### Complete Setup with RBAC

```python
from flask import Flask, g
from jwt_verification import (
    AuthExtension,
    Auth0JWKSProvider,
    InMemoryCache,
    JWTVerifier,
    JWTVerifyOptions,
    RBACAuthorizer,
    ClaimAccess,
    ClaimsMapping,
)

app = Flask(__name__)

# 1. Cache configuration
cache = InMemoryCache()

# 2. Key provider with caching
provider = Auth0JWKSProvider(
    issuer="https://your-tenant.auth0.com/",
    cache=cache,
    ttl_seconds=600,
    missing_ttl_seconds=30,
)

# 3. JWT verifier
verifier = JWTVerifier(
    key_provider=provider,
    options=JWTVerifyOptions(
        issuer="https://your-tenant.auth0.com/",
        audience="your-api-identifier",
    ),
)

# 4. RBAC configuration
mapping = ClaimsMapping(
    permissions_claim="permissions",
    roles_claim="roles",
)
claims_access = ClaimAccess(mapping=mapping)
authorizer = RBACAuthorizer(claims_access)

# 5. Auth extension
auth = AuthExtension(verifier=verifier, authorizer=authorizer)

@app.route("/admin")
@auth.require(roles=["admin"])
def admin_only():
    user_id = g.jwt.get("sub")
    return {"message": f"Welcome, admin {user_id}"}
```

---

## Authentication Examples

### Public vs Protected Routes

```python
from flask import Flask, g
from jwt_verification import AuthExtension

app = Flask(__name__)
auth = AuthExtension(verifier=verifier)

# Public route - no authentication
@app.route("/")
def home():
    return {"message": "Welcome to our API"}

# Protected route - authentication required
@app.route("/profile")
@auth.require()
def profile():
    user_id = g.jwt.get("sub")
    email = g.jwt.get("email")
    return {
        "user_id": user_id,
        "email": email,
    }

# Public route with optional authentication
from functools import wraps
from jwt_verification import MissingToken, AuthError

def optional_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            token = auth._extractor.extract()
            g.jwt = auth._verifier.verify(token)
            g.authenticated = True
        except (MissingToken, AuthError):
            g.authenticated = False
        return f(*args, **kwargs)
    return decorated

@app.route("/content")
@optional_auth
def content():
    if g.get("authenticated"):
        # Personalized content
        return {"message": f"Welcome back, {g.jwt.get('name')}"}
    else:
        # Generic content
        return {"message": "Welcome, guest"}
```

### Cookie-Based Authentication

```python
from flask import Flask, request, make_response
from jwt_verification import (
    AuthExtension,
    CookieExtractor,
)

app = Flask(__name__)

# Configure cookie extraction
cookie_auth = AuthExtension(
    verifier=verifier,
    extractor=CookieExtractor(cookie_name="access_token"),
)

@app.route("/login", methods=["POST"])
def login():
    # After OAuth flow, store token in cookie
    access_token = request.json.get("access_token")
    
    response = make_response({"message": "Logged in"})
    response.set_cookie(
        "access_token",
        access_token,
        httponly=True,
        secure=True,
        samesite="Strict",
        max_age=3600,  # 1 hour
    )
    return response

@app.route("/api/data")
@cookie_auth.require()
def get_data():
    # Token automatically extracted from cookie
    return {"data": "sensitive information"}

@app.route("/logout", methods=["POST"])
def logout():
    response = make_response({"message": "Logged out"})
    response.set_cookie("access_token", "", expires=0)
    return response
```

### ID Token Verification

```python
from flask import Flask, request
from jwt_verification import (
    JWTVerifier,
    JWTVerifyOptions,
    Auth0JWKSProvider,
    get_verified_id_claims,
    MissingToken,
    ExpiredToken,
    InvalidToken,
)

app = Flask(__name__)

# ID token verifier (different configuration from access token)
id_token_verifier = JWTVerifier(
    key_provider=Auth0JWKSProvider(
        issuer="https://your-tenant.auth0.com/",
    ),
    options=JWTVerifyOptions(
        issuer="https://your-tenant.auth0.com/",
        audience="your-client-id",  # Client ID, not API identifier
    ),
)

@app.route("/user-profile")
def user_profile():
    try:
        claims = get_verified_id_claims(
            verifier=id_token_verifier,
            cookie_name="id_token",
        )
        
        return {
            "name": claims.get("name"),
            "email": claims.get("email"),
            "picture": claims.get("picture"),
            "email_verified": claims.get("email_verified"),
        }
    except MissingToken:
        return {"error": "Not logged in"}, 401
    except (ExpiredToken, InvalidToken) as e:
        return {"error": "Session expired"}, 401
```

### Multiple Authentication Methods

```python
from flask import Flask, request, g
from jwt_verification import (
    AuthExtension,
    BearerExtractor,
    CookieExtractor,
    MissingToken,
)

app = Flask(__name__)

class MultiExtractor:
    """Try Bearer token first, fall back to cookie."""
    
    def __init__(self):
        self.bearer = BearerExtractor()
        self.cookie = CookieExtractor("access_token")
    
    def extract(self) -> str:
        try:
            return self.bearer.extract()
        except MissingToken:
            return self.cookie.extract()

auth = AuthExtension(
    verifier=verifier,
    extractor=MultiExtractor(),
)

@app.route("/api/data")
@auth.require()
def get_data():
    # Works with both Authorization header and cookie
    return {"data": "works with both methods"}
```

---

## Authorization Examples

### Role-Based Access Control

```python
from flask import Flask, g
from jwt_verification import AuthExtension

app = Flask(__name__)
auth = AuthExtension(verifier=verifier, authorizer=authorizer)

# Single role required
@app.route("/admin/users")
@auth.require(roles=["admin"])
def manage_users():
    return {"message": "Admin access granted"}

# Multiple roles (user needs at least one)
@app.route("/moderation")
@auth.require(roles=["admin", "moderator"])
def moderate_content():
    # User is either admin OR moderator
    user_roles = g.jwt.get("roles", [])
    return {"message": f"Moderating as: {user_roles}"}

# No role required (just authentication)
@app.route("/dashboard")
@auth.require()
def dashboard():
    return {"message": "Any authenticated user"}
```

### Permission-Based Access Control

```python
@app.route("/posts", methods=["GET"])
@auth.require(permissions=["read:posts"])
def list_posts():
    return {"posts": [...]}

@app.route("/posts", methods=["POST"])
@auth.require(permissions=["write:posts"])
def create_post():
    return {"message": "Post created"}

@app.route("/posts/<post_id>", methods=["DELETE"])
@auth.require(permissions=["delete:posts"])
def delete_post(post_id):
    return {"message": f"Post {post_id} deleted"}

# Multiple permissions - require ALL
@app.route("/admin/settings", methods=["PUT"])
@auth.require(
    permissions=["read:settings", "write:settings"],
    require_all_permissions=True
)
def update_settings():
    return {"message": "Settings updated"}

# Multiple permissions - require ANY (at least one)
@app.route("/content")
@auth.require(
    permissions=["read:posts", "read:comments", "read:users"],
    require_all_permissions=False
)
def view_content():
    # User has at least one of the read permissions
    return {"content": [...]}
```

### Combined Role and Permission Checks

```python
@app.route("/posts/<post_id>", methods=["PUT"])
@auth.require(
    roles=["editor", "admin"],
    permissions=["write:posts"],
    require_all_permissions=True
)
def edit_post(post_id):
    # User must be editor OR admin AND have write:posts permission
    return {"message": f"Post {post_id} updated"}

@app.route("/reports")
@auth.require(
    roles=["manager", "admin"],
    permissions=["read:reports", "read:analytics"],
    require_all_permissions=True
)
def view_reports():
    # Must be manager OR admin
    # AND have both read:reports and read:analytics permissions
    return {"reports": [...]}
```

### Resource-Specific Authorization

```python
from flask import Flask, g, abort

app = Flask(__name__)
auth = AuthExtension(verifier=verifier, authorizer=authorizer)

# Example: Users can only edit their own posts
@app.route("/posts/<post_id>", methods=["PUT"])
@auth.require(permissions=["write:posts"])
def edit_post(post_id):
    user_id = g.jwt.get("sub")
    
    # Fetch post from database
    post = get_post(post_id)
    
    # Check ownership
    if post.author_id != user_id:
        # Check if user is admin (can edit any post)
        user_roles = g.jwt.get("roles", [])
        if "admin" not in user_roles:
            abort(403, "You can only edit your own posts")
    
    # Proceed with update
    update_post(post_id, request.json)
    return {"message": "Post updated"}

# Example: Conditional permissions based on resource state
@app.route("/documents/<doc_id>/publish", methods=["POST"])
@auth.require(permissions=["write:documents"])
def publish_document(doc_id):
    doc = get_document(doc_id)
    
    # Only draft documents can be published
    if doc.status != "draft":
        abort(400, "Only draft documents can be published")
    
    # Managers can publish any draft
    # Regular users can only publish their own drafts
    user_id = g.jwt.get("sub")
    user_roles = g.jwt.get("roles", [])
    
    if doc.author_id != user_id and "manager" not in user_roles:
        abort(403, "Only managers can publish others' documents")
    
    publish(doc_id)
    return {"message": "Document published"}
```

### Dynamic Permission Checking

```python
from flask import Flask, g

app = Flask(__name__)
auth = AuthExtension(verifier=verifier, authorizer=authorizer)

def requires_permission(permission):
    """Helper to check permission programmatically."""
    user_permissions = set(g.jwt.get("permissions", []))
    if permission not in user_permissions:
        abort(403, f"Missing required permission: {permission}")

@app.route("/organizations/<org_id>/data")
@auth.require()  # Just authenticate, check permissions later
def get_org_data(org_id):
    # Determine required permission based on organization
    org = get_organization(org_id)
    
    if org.is_premium:
        requires_permission("read:premium_data")
    else:
        requires_permission("read:basic_data")
    
    return get_data_for_org(org_id)
```

---

## Custom Implementations

### Custom Key Provider

```python
from jwt import PyJWK
from jwt_verification.protocols import KeyProvider
from jwt_verification import InvalidToken

class DatabaseKeyProvider(KeyProvider):
    """Load keys from database instead of JWKS endpoint."""
    
    def __init__(self, db_connection):
        self.db = db_connection
    
    def get_key_for_token(self, kid: str) -> PyJWK:
        # Query database for key
        key_data = self.db.execute(
            "SELECT key_data FROM signing_keys WHERE kid = ?",
            (kid,)
        ).fetchone()
        
        if not key_data:
            raise InvalidToken(f"Unknown key ID: {kid}")
        
        return PyJWK.from_dict(key_data['key_data'])

# Usage
db_provider = DatabaseKeyProvider(db_connection)
verifier = JWTVerifier(
    key_provider=db_provider,
    options=JWTVerifyOptions(
        issuer="https://your-issuer.com/",
        audience="your-api",
    ),
)
```

### Custom Authorizer

```python
from jwt_verification.protocols import Authorizer, Claims
from jwt_verification import Forbidden

class CustomAuthorizer(Authorizer):
    """Custom authorization with business rules."""
    
    def __init__(self, db):
        self.db = db
    
    def authorize(
        self,
        claims: Claims,
        *,
        permissions: frozenset[str],
        roles: frozenset[str],
        require_all_permissions: bool,
    ) -> None:
        user_id = claims.get("sub")
        
        # Check if user is suspended
        user = self.db.get_user(user_id)
        if user.is_suspended:
            raise Forbidden("Account suspended")
        
        # Check if subscription is active (for premium features)
        if any(p.startswith("premium:") for p in permissions):
            if not user.has_active_subscription:
                raise Forbidden("Premium subscription required")
        
        # Standard role/permission checks
        user_roles = set(claims.get("roles", []))
        user_perms = set(claims.get("permissions", []))
        
        if roles and not roles.intersection(user_roles):
            raise Forbidden("Insufficient role")
        
        if permissions:
            if require_all_permissions:
                if not permissions.issubset(user_perms):
                    raise Forbidden("Missing required permissions")
            else:
                if not permissions.intersection(user_perms):
                    raise Forbidden("No matching permissions")

# Usage
custom_auth = AuthExtension(
    verifier=verifier,
    authorizer=CustomAuthorizer(db),
)
```

### Custom Extractor

```python
from flask import request
from jwt_verification.protocols import Extractor
from jwt_verification import MissingToken

class QueryParamExtractor(Extractor):
    """Extract token from URL query parameter."""
    
    def __init__(self, param_name: str = "access_token"):
        self.param = param_name
    
    def extract(self) -> str:
        token = request.args.get(self.param)
        if not token:
            raise MissingToken(f"Missing '{self.param}' query parameter")
        return token

# Usage (for WebSocket handshakes, etc.)
ws_auth = AuthExtension(
    verifier=verifier,
    extractor=QueryParamExtractor(),
)

@app.route("/ws/connect")
@ws_auth.require()
def websocket_handshake():
    # Token from: /ws/connect?access_token=<JWT>
    return {"ws_url": "wss://..."}
```

### Custom Claims Mapping

```python
from jwt_verification import ClaimsMapping, ClaimAccess, RBACAuthorizer

# For Auth0 with custom namespaced claims
custom_mapping = ClaimsMapping(
    permissions_claim="permissions",
    roles_claim="https://myapp.com/roles",
    single_role_claim="https://myapp.com/primary_role",
)

claims_access = ClaimAccess(mapping=custom_mapping)
authorizer = RBACAuthorizer(claims_access)

# Example token structure:
# {
#   "sub": "auth0|123",
#   "permissions": ["read:data", "write:data"],
#   "https://myapp.com/roles": ["user", "editor"],
#   "https://myapp.com/primary_role": "editor"
# }
```

---

## Integration Examples

### Flask-CORS Integration

```python
from flask import Flask
from flask_cors import CORS
from jwt_verification import AuthExtension

app = Flask(__name__)

# Configure CORS
CORS(app, resources={
    r"/api/*": {
        "origins": ["https://yourdomain.com"],
        "methods": ["GET", "POST", "PUT", "DELETE"],
        "allow_headers": ["Authorization", "Content-Type"],
    }
})

auth = AuthExtension(verifier=verifier)

@app.route("/api/data")
@auth.require()
def api_endpoint():
    return {"data": "CORS enabled"}
```

### Flask-Limiter Integration

```python
from flask import Flask, g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from jwt_verification import AuthExtension

app = Flask(__name__)
auth = AuthExtension(verifier=verifier)

# Rate limit by user ID (from JWT) if authenticated, otherwise by IP
def rate_limit_key():
    if hasattr(g, 'jwt'):
        return g.jwt.get("sub")
    return get_remote_address()

limiter = Limiter(
    app=app,
    key_func=rate_limit_key,
    default_limits=["200 per day", "50 per hour"],
)

@app.route("/api/limited")
@auth.require()
@limiter.limit("10 per minute")
def limited_endpoint():
    return {"message": "Rate limited by user"}

@app.route("/public/limited")
@limiter.limit("5 per minute")
def public_limited():
    return {"message": "Rate limited by IP"}
```

### SQLAlchemy Integration

```python
from flask import Flask, g
from flask_sqlalchemy import SQLAlchemy
from jwt_verification import AuthExtension

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
db = SQLAlchemy(app)
auth = AuthExtension(verifier=verifier, authorizer=authorizer)

class User(db.Model):
    id = db.Column(db.String(255), primary_key=True)
    email = db.Column(db.String(255))
    name = db.Column(db.String(255))

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255))
    content = db.Column(db.Text)
    author_id = db.Column(db.String(255), db.ForeignKey('user.id'))
    author = db.relationship('User', backref='posts')

@app.route("/posts", methods=["POST"])
@auth.require(permissions=["write:posts"])
def create_post():
    user_id = g.jwt.get("sub")
    
    # Get or create user from JWT claims
    user = User.query.get(user_id)
    if not user:
        user = User(
            id=user_id,
            email=g.jwt.get("email"),
            name=g.jwt.get("name"),
        )
        db.session.add(user)
    
    # Create post
    post = Post(
        title=request.json['title'],
        content=request.json['content'],
        author=user,
    )
    db.session.add(post)
    db.session.commit()
    
    return {"id": post.id, "title": post.title}

@app.route("/posts/<int:post_id>", methods=["DELETE"])
@auth.require(permissions=["delete:posts"])
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    user_id = g.jwt.get("sub")
    
    # Users can delete own posts, admins can delete any
    if post.author_id != user_id:
        if "admin" not in g.jwt.get("roles", []):
            abort(403, "Can only delete your own posts")
    
    db.session.delete(post)
    db.session.commit()
    return {"message": "Post deleted"}
```

### Celery Integration

```python
from celery import Celery
from flask import Flask, g
from jwt_verification import AuthExtension

app = Flask(__name__)
celery = Celery(app.name, broker=app.config['CELERY_BROKER_URL'])
auth = AuthExtension(verifier=verifier)

@celery.task
def process_data_async(user_id, data):
    """Background task with user context."""
    result = process(data)
    notify_user(user_id, result)
    return result

@app.route("/process", methods=["POST"])
@auth.require(permissions=["write:data"])
def trigger_processing():
    user_id = g.jwt.get("sub")
    data = request.json
    
    # Queue background task with user context
    task = process_data_async.delay(user_id, data)
    
    return {
        "message": "Processing started",
        "task_id": task.id
    }
```

---

## Testing Examples

### Unit Tests

```python
import pytest
from unittest.mock import Mock
from jwt_verification import (
    JWTVerifier,
    JWTVerifyOptions,
    InvalidToken,
    ExpiredToken,
)

@pytest.fixture
def mock_key_provider():
    provider = Mock()
    provider.get_key_for_token.return_value = test_public_key
    return provider

@pytest.fixture
def verifier(mock_key_provider):
    return JWTVerifier(
        key_provider=mock_key_provider,
        options=JWTVerifyOptions(
            issuer="https://test.auth0.com/",
            audience="test-api",
        ),
    )

def test_valid_token(verifier):
    token = create_test_token(
        claims={"sub": "user123"},
        issuer="https://test.auth0.com/",
        audience="test-api",
    )
    
    claims = verifier.verify(token)
    assert claims["sub"] == "user123"

def test_expired_token(verifier):
    token = create_expired_token()
    
    with pytest.raises(ExpiredToken):
        verifier.verify(token)

def test_wrong_issuer(verifier):
    token = create_test_token(
        issuer="https://wrong-issuer.com/",
        audience="test-api",
    )
    
    with pytest.raises(InvalidToken):
        verifier.verify(token)

def test_wrong_audience(verifier):
    token = create_test_token(
        issuer="https://test.auth0.com/",
        audience="wrong-api",
    )
    
    with pytest.raises(InvalidToken):
        verifier.verify(token)
```

### Integration Tests

```python
import pytest
from flask import Flask
from jwt_verification import AuthExtension

@pytest.fixture
def app():
    app = Flask(__name__)
    app.config['TESTING'] = True
    
    auth = AuthExtension(verifier=test_verifier, authorizer=test_authorizer)
    
    @app.route("/public")
    def public():
        return {"message": "public"}
    
    @app.route("/protected")
    @auth.require()
    def protected():
        return {"message": "protected"}
    
    @app.route("/admin")
    @auth.require(roles=["admin"])
    def admin():
        return {"message": "admin"}
    
    return app

@pytest.fixture
def client(app):
    return app.test_client()

def test_public_endpoint(client):
    response = client.get("/public")
    assert response.status_code == 200

def test_protected_without_token(client):
    response = client.get("/protected")
    assert response.status_code == 401

def test_protected_with_valid_token(client):
    token = create_test_token()
    headers = {"Authorization": f"Bearer {token}"}
    
    response = client.get("/protected", headers=headers)
    assert response.status_code == 200
    assert response.json["message"] == "protected"

def test_admin_without_role(client):
    token = create_test_token(roles=[])
    headers = {"Authorization": f"Bearer {token}"}
    
    response = client.get("/admin", headers=headers)
    assert response.status_code == 403

def test_admin_with_role(client):
    token = create_test_token(roles=["admin"])
    headers = {"Authorization": f"Bearer {token}"}
    
    response = client.get("/admin", headers=headers)
    assert response.status_code == 200
```

### Mock Helpers

```python
from datetime import datetime, timedelta
import jwt
from jwt import PyJWK

def create_test_keypair():
    """Generate RSA keypair for testing."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    public_key = private_key.public_key()
    
    return private_key, public_key

def create_test_token(
    claims=None,
    issuer="https://test.auth0.com/",
    audience="test-api",
    roles=None,
    permissions=None,
    expired=False,
):
    """Create a test JWT."""
    private_key, _ = create_test_keypair()
    
    now = datetime.utcnow()
    payload = {
        "iss": issuer,
        "aud": audience,
        "sub": "test-user-123",
        "iat": int(now.timestamp()),
        "exp": int((now - timedelta(hours=1) if expired else now + timedelta(hours=1)).timestamp()),
    }
    
    if claims:
        payload.update(claims)
    if roles:
        payload["roles"] = roles
    if permissions:
        payload["permissions"] = permissions
    
    return jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": "test-kid"})

# Usage in tests
def test_with_mock_token():
    token = create_test_token(
        claims={"email": "test@example.com"},
        roles=["admin"],
        permissions=["read:all", "write:all"],
    )
    
    # Use token in test...
```

---

## Production Patterns

### Application Factory

```python
# app/__init__.py
from flask import Flask
from .auth import init_auth
from .api import api_bp

def create_app(config=None):
    app = Flask(__name__)
    
    if config:
        app.config.from_object(config)
    
    # Initialize auth extension
    init_auth(app)
    
    # Register blueprints
    app.register_blueprint(api_bp, url_prefix="/api")
    
    return app

# app/auth.py
from jwt_verification import (
    AuthExtension,
    Auth0JWKSProvider,
    RedisCache,
    JWTVerifier,
    JWTVerifyOptions,
    RBACAuthorizer,
    ClaimAccess,
    ClaimsMapping,
)
import redis
import os

auth = AuthExtension(verifier=None)  # Placeholder

def init_auth(app):
    # Configure from environment
    auth0_domain = os.environ["AUTH0_DOMAIN"]
    auth0_audience = os.environ["AUTH0_API_IDENTIFIER"]
    redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    
    # Redis cache
    redis_client = redis.from_url(redis_url, decode_responses=False)
    cache = RedisCache(redis_client)
    
    # Key provider
    issuer = f"https://{auth0_domain}/"
    provider = Auth0JWKSProvider(
        issuer=issuer,
        cache=cache,
        ttl_seconds=3600,
    )
    
    # Verifier
    verifier = JWTVerifier(
        key_provider=provider,
        options=JWTVerifyOptions(
            issuer=issuer,
            audience=auth0_audience,
        ),
    )
    
    # Authorizer
    mapping = ClaimsMapping()
    authorizer = RBACAuthorizer(ClaimAccess(mapping))
    
    # Initialize extension
    auth.init_app(app, verifier=verifier, authorizer=authorizer)

# app/api.py
from flask import Blueprint, g
from .auth import auth

api_bp = Blueprint("api", __name__)

@api_bp.route("/profile")
@auth.require()
def profile():
    return {"user_id": g.jwt.get("sub")}

@api_bp.route("/admin/users")
@auth.require(roles=["admin"])
def manage_users():
    return {"users": [...]}
```

### Environment Configuration

```python
# config.py
import os

class Config:
    """Base configuration."""
    SECRET_KEY = os.environ.get("SECRET_KEY")
    
    # Auth0
    AUTH0_DOMAIN = os.environ.get("AUTH0_DOMAIN")
    AUTH0_API_IDENTIFIER = os.environ.get("AUTH0_API_IDENTIFIER")
    
    # Redis
    REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    
    # JWT
    JWT_KEY_CACHE_TTL = 3600
    JWT_NEGATIVE_CACHE_TTL = 60
    JWT_REFRESH_MIN_INTERVAL = 120.0

class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True
    REDIS_URL = "redis://localhost:6379/0"

class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False
    # Additional production settings...

class TestingConfig(Config):
    """Testing configuration."""
    TESTING = True
    # Use in-memory cache for tests
```

### Error Handling

```python
from flask import Flask, jsonify
from jwt_verification import AuthError

app = Flask(__name__)

@app.errorhandler(401)
def handle_unauthorized(error):
    return jsonify({
        "error": "unauthorized",
        "message": error.description or "Authentication required",
    }), 401

@app.errorhandler(403)
def handle_forbidden(error):
    return jsonify({
        "error": "forbidden",
        "message": "Insufficient permissions",
    }), 403

@app.errorhandler(AuthError)
def handle_auth_error(error):
    # Catch-all for any auth errors not handled above
    return jsonify({
        "error": "authentication_error",
        "message": str(error),
    }), 401

@app.errorhandler(500)
def handle_server_error(error):
    # Log but don't reveal details to client
    app.logger.error(f"Server error: {error}")
    return jsonify({
        "error": "server_error",
        "message": "An internal error occurred",
    }), 500
```

### Logging and Monitoring

```python
import logging
from flask import Flask, g, request
from jwt_verification import AuthExtension
from functools import wraps

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
auth = AuthExtension(verifier=verifier, authorizer=authorizer)

@app.before_request
def log_request():
    """Log all requests with auth context."""
    logger.info(
        "Request started",
        extra={
            "method": request.method,
            "path": request.path,
            "remote_addr": request.remote_addr,
            "user_agent": request.headers.get("User-Agent"),
        },
    )

@app.after_request
def log_response(response):
    """Log response with auth context."""
    extra = {
        "status_code": response.status_code,
        "method": request.method,
        "path": request.path,
    }
    
    if hasattr(g, 'jwt'):
        extra["user_id"] = g.jwt.get("sub")
    
    logger.info("Request completed", extra=extra)
    return response

# Custom decorator for audit logging
def audit_log(action):
    """Log security-relevant actions."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user_id = g.jwt.get("sub") if hasattr(g, "jwt") else "anonymous"
            
            logger.warning(
                f"Audit: {action}",
                extra={
                    "user_id": user_id,
                    "action": action,
                    "resource": request.path,
                    "method": request.method,
                },
            )
            
            return f(*args, **kwargs)
        return decorated
    return decorator

@app.route("/admin/delete-user/<user_id>", methods=["DELETE"])
@auth.require(roles=["admin"])
@audit_log("delete_user")
def delete_user(user_id):
    # Sensitive action is logged
    return {"message": "User deleted"}
```

---

**Last Updated:** February 23, 2026
