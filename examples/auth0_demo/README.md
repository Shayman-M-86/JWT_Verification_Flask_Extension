# Auth0 Demo Application

This is a complete example demonstrating how to use the Flask JWT Verification Extension with Auth0 for authentication and authorization.

## What's Included

This demo includes:

- **OAuth Login Flow** - Complete Auth0 login/logout implementation
- **JWT Verification** - Backend API protected with JWT authentication
- **RBAC** - Role-based and permission-based access control
- **Web UI** - Simple HTML templates demonstrating the flow
- **SSL/TLS** - Self-signed certificates for local HTTPS testing

## Architecture

```
┌──────────────┐
│   Browser    │
└──────┬───────┘
       │
       ├─── GET /login ─────────────────┐
       │                                │
       │                        ┌───────▼────────┐
       │                        │ login_provider │
       │                        │  (Flask App)   │
       │◄──── Redirect ─────────┤  Port 5001     │
       │      to Auth0          └───────┬────────┘
       │                                │
┌──────▼───────┐                        │
│    Auth0     │                        │
│   (OAuth)    │                        │
└──────┬───────┘                        │
       │                                │
       │◄───── Get User Info ───────────┘
       │
       ├─── Callback with Code ─────────┐
       │                                │
       │                        ┌───────▼────────┐
       │                        │ login_provider │
       │◄──── Set Cookie ───────┤ Exchange Code  │
       │      Return Token      │  for Token     │
       │                        └────────────────┘
       │
       ├─── GET /api/protected ─────────┐
       │    Authorization: Bearer ...   │
       │                        ┌───────▼────────┐
       │                        │   app.py       │
       │                        │ (Backend API)  │
       │◄──── JSON Response ────┤  Port 5000     │
       │                        │ JWT Verification│
       │                        └────────────────┘
```

## Setup

### 1. Prerequisites

- Python 3.14+
- Auth0 account (free tier is fine)
- OpenSSL (for certificate generation, if needed)

### 2. Auth0 Configuration

#### Create an Application

1. Go to [Auth0 Dashboard](https://manage.auth0.com/)
2. Applications → Create Application
3. Name: "Flask JWT Demo"
4. Type: "Regular Web Application"
5. Click "Create"

#### Configure Application Settings

In your application settings:

- **Allowed Callback URLs**: `https://localhost:5001/callback`
- **Allowed Logout URLs**: `https://localhost:5001/`
- **Allowed Web Origins**: `https://localhost:5001`

Save changes.

#### Create an API

1. Applications → APIs → Create API
2. Name: "Flask Backend API"
3. Identifier: `https://api.example.com` (or your domain)
4. Signing Algorithm: RS256
5. Click "Create"

#### Enable RBAC (Optional)

In your API settings:
- Enable "RBAC"
- Enable "Add Permissions in the Access Token"
- Save changes

#### Create Roles and Permissions (Optional)

1. User Management → Roles → Create Role
   - Name: "admin"
   - Description: "Administrator role"

2. In the "admin" role:
   - Go to Permissions tab
   - Add permissions from your API:
     - `read:admin`
     - `write:posts`
     - `delete:posts`

3. Assign the role to a user:
   - User Management → Users → Select User
   - Roles tab → Assign Roles

### 3. Environment Configuration

Create a `.env` file in the `examples/auth0_demo` directory:

```bash
# Auth0 Configuration
AUTH0_DOMAIN=your-tenant.auth0.com
AUTH0_CLIENT_ID=your_client_id_here
AUTH0_CLIENT_SECRET=your_client_secret_here
AUTH0_API_IDENTIFIER=https://api.example.com

# Flask Configuration
SECRET_KEY=your-random-secret-key-here
FLASK_ENV=development

# Optional: Redis Cache
# REDIS_URL=redis://localhost:6379/0
```

**Replace the placeholder values:**
- `AUTH0_DOMAIN`: Your Auth0 domain (e.g., `dev-abc123.us.auth0.com`)
- `AUTH0_CLIENT_ID`: From your Auth0 Application settings
- `AUTH0_CLIENT_SECRET`: From your Auth0 Application settings
- `AUTH0_API_IDENTIFIER`: The identifier you set for your API
- `SECRET_KEY`: Generate with `python -c "import secrets; print(secrets.token_hex(32))"`

### 4. Install Dependencies

```bash
# From the project root
pip install -e ".[examples]"
```

This installs:
- The jwt_verification extension
- Flask
- Auth0 Python SDK
- python-dotenv
- Other dependencies

### 5. Generate SSL Certificates (if needed)

The demo includes self-signed certificates in the `certs/` directory. If you need to regenerate them:

```bash
cd examples/auth0_demo

# Generate new self-signed certificate
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout certs/key.pem \
  -out certs/cert.pem \
  -days 365 \
  -subj "/CN=localhost"
```

## Running the Demo

### Quick Start

```bash
cd examples/auth0_demo
bash run.sh
```

This script:
1. Loads environment variables from `.env`
2. Starts the backend API on port 5000 (HTTPS)
3. Starts the login provider on port 5001 (HTTPS)

### Manual Start

#### Terminal 1 - Backend API

```bash
cd examples/auth0_demo
python app.py
```

Starts on: https://localhost:5000

#### Terminal 2 - Login Provider

```bash
cd examples/auth0_demo
python login_provider.py
```

Starts on: https://localhost:5001

## Using the Demo

### 1. Open the Application

Navigate to: https://localhost:5001

**Note:** You'll see a browser warning about the self-signed certificate. This is expected for local development. Click "Advanced" and proceed.

### 2. Login

Click the "Login" button. You'll be redirected to Auth0 to authenticate.

### 3. Access Protected Routes

After login, you can test the protected API endpoints:

- **GET /api/protected** - Requires valid JWT
- **GET /api/admin** - Requires `admin` role
- **GET /api/profile** - Returns user profile from JWT

### 4. Test with curl

```bash
# Get a token (manually from browser network tab, or from the /profile page)
TOKEN="your_jwt_token_here"

# Call protected endpoint
curl -k -H "Authorization: Bearer $TOKEN" https://localhost:5000/api/protected

# Call admin endpoint (requires 'admin' role)
curl -k -H "Authorization: Bearer $TOKEN" https://localhost:5000/api/admin

# Call profile endpoint
curl -k -H "Authorization: Bearer $TOKEN" https://localhost:5000/api/profile
```

## Code Overview

### app.py - Backend API

The backend API demonstrates:

```python
from jwt_verification import (
    AuthExtension,
    Auth0JWKSProvider,
    JWTVerifier,
    JWTVerifyOptions,
    RBACAuthorizer,
    ClaimAccess,
    ClaimsMapping,
)

# Setup JWT verification
provider = Auth0JWKSProvider(issuer=f"https://{AUTH0_DOMAIN}/")
verifier = JWTVerifier(
    key_provider=provider,
    options=JWTVerifyOptions(
        issuer=f"https://{AUTH0_DOMAIN}/",
        audience=AUTH0_API_IDENTIFIER,
    ),
)

# Setup RBAC
mapping = ClaimsMapping(permissions_claim="permissions", roles_claim="roles")
authorizer = RBACAuthorizer(ClaimAccess(mapping))

# Create auth extension
auth = AuthExtension(verifier=verifier, authorizer=authorizer)

# Protected route - authentication only
@app.route("/api/protected")
@auth.require()
def protected():
    return {"message": "Access granted", "user": g.jwt["sub"]}

# Admin route - requires 'admin' role
@app.route("/api/admin")
@auth.require(roles=["admin"])
def admin():
    return {"message": "Admin access granted"}
```

### login_provider.py - OAuth Login

The login provider demonstrates:

```python
from authlib.integrations.flask_client import OAuth
from flask import Flask, redirect, session, url_for

# Configure OAuth
oauth = OAuth(app)
oauth.register(
    "auth0",
    client_id=AUTH0_CLIENT_ID,
    client_secret=AUTH0_CLIENT_SECRET,
    api_base_url=f"https://{AUTH0_DOMAIN}",
    access_token_url=f"https://{AUTH0_DOMAIN}/oauth/token",
    authorize_url=f"https://{AUTH0_DOMAIN}/authorize",
    client_kwargs={"scope": "openid profile email"},
)

@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )

@app.route("/callback")
def callback():
    token = oauth.auth0.authorize_access_token()
    session["access_token"] = token["access_token"]
    return redirect("/profile")
```

## Project Structure

```
examples/auth0_demo/
├── app.py                  # Backend API with JWT verification
├── login_provider.py       # OAuth login/logout flow
├── run.sh                  # Startup script
├── .env                    # Environment configuration (create this)
├── certs/                  # SSL certificates
│   ├── cert.pem           # Self-signed certificate
│   └── key.pem            # Private key
├── templates/              # HTML templates
│   ├── home.html          # Landing page
│   ├── profile.html       # User profile (after login)
│   └── 401.html           # Unauthorized page
├── static/                 # CSS and assets
│   └── style.css          # Styling
└── README.md              # This file
```

## Common Issues

### Browser Certificate Warning

**Issue:** Browser shows "Your connection is not private"

**Solution:** This is expected with self-signed certificates. Click "Advanced" and proceed. For production, use proper SSL certificates (e.g., Let's Encrypt).

### Auth0 Callback Error

**Issue:** "Callback URL mismatch" or similar Auth0 error

**Solution:** Ensure the callback URL in Auth0 settings exactly matches: `https://localhost:5001/callback`

### JWKS Fetch Error

**Issue:** "Unable to fetch JWKS" or "Key not found"

**Solution:** 
- Verify `AUTH0_DOMAIN` is correct (no `https://` prefix)
- Check internet connection
- Ensure Auth0 tenant is active

### Role/Permission Not Working

**Issue:** 401 error even though user has the role

**Solution:**
- Enable RBAC in Auth0 API settings
- Enable "Add Permissions in the Access Token"
- Re-login to get a new token with roles/permissions

### Port Already in Use

**Issue:** "Address already in use" error

**Solution:**
```bash
# Find and kill process using port 5000 or 5001
# Windows
netstat -ano | findstr :5000
taskkill /PID <PID> /F

# Linux/Mac
lsof -ti:5000 | xargs kill -9
```

## Security Notes

### For Development

- Self-signed certificates are fine
- `SECRET_KEY` doesn't need to be cryptographically strong
- CORS can be permissive
- Debug mode is okay

### For Production

- Use proper SSL certificates (Let's Encrypt, etc.)
- Generate strong `SECRET_KEY`: `secrets.token_hex(32)`
- Configure CORS properly
- Disable debug mode (`FLASK_ENV=production`)
- Use Redis for caching instead of InMemoryCache
- Enable Auth0 tenant security features
- Set up monitoring and logging
- Use environment-specific configuration

## Next Steps

After running this demo, you can:

1. **Customize the Extension**
   - Implement custom `KeyProvider` for other identity providers
   - Create custom `CacheStore` implementations
   - Add custom claims validation

2. **Integrate into Your App**
   - Copy the JWT configuration from `app.py`
   - Adapt the login flow from `login_provider.py`
   - Use `@auth.require()` on your routes

3. **Explore Documentation**
   - [Extension README](../../docs/README.md) - Architecture and usage
   - [API Reference](../../docs/API_REFERENCE.md) - Complete API docs
   - [Examples](../../docs/EXAMPLES.md) - More code examples
   - [Security Guide](../../docs/SECURITY.md) - Security analysis

## Support

For issues with:
- **The Extension**: See main [README.md](../../README.md)
- **Auth0**: Check [Auth0 Documentation](https://auth0.com/docs)
- **This Demo**: Open an issue describing the problem

## License

This example code is provided under the MIT License, the same as the main extension.

---

**Demo Version:** 1.0.0  
**Extension Version:** 1.0.0  
**Last Updated:** 2024
