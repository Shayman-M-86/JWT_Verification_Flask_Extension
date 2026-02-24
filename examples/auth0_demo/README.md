# Auth0 Demo Application

Complete example demonstrating Flask JWT Verification Extension with Auth0 for authentication and cross-origin API access.

## What's Included

- **OAuth Login Flow** - Auth0 login/logout with secure cookie storage
- **JWT Verification** - Backend API protected with JWT authentication
- **CORS** - Cross-origin requests between login provider and backend
- **Web UI** - Interactive test interface with visual feedback
- **SSL/TLS** - Self-signed certificates for local HTTPS

## Architecture

Two-server setup demonstrating cross-origin authentication:

```text
┌──────────────┐
│   Browser    │
└──────┬───────┘
       │
       ├─── GET /home ──────────────────┐
       │                        ┌───────▼────────────┐
       │                        │ Login Provider     │
       │◄──── HTML/JS ──────────┤  Port 5000         │
       │                        │  OAuth + Cookies   │
       │                        └───────┬────────────┘
       │                                │
       │◄──── Redirect to Auth0 ────────┘
       │
┌──────▼───────┐
│    Auth0     │
└──────┬───────┘
       │
       ├─── Callback ───────────────────┐
       │                        ┌───────▼────────────┐
       │◄──── Set Cookies ──────┤ Login Provider     │
       │                        └────────────────────┘
       │
       ├─── Test Backend (CORS) ────────┐
       │    Bearer Token + Cookies      │
       │                        ┌───────▼────────────┐
       │◄──── JSON Response ────┤ Backend API        │
                                │  Port 5001         │
                                │  JWT Verification  │
                                └────────────────────┘
```

**Components:**

- **Login Provider (5000)** - OAuth flow, session management, web UI
- **Backend API (5001)** - Protected endpoints with JWT verification

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

- **Allowed Callback URLs**: `https://api.localtest.me:5000/login-redirect`
- **Allowed Logout URLs**: `https://api.localtest.me:5000/`, `https://api.localtest.me:5001/home`
- **Allowed Web Origins**: `https://api.localtest.me:5000`, `https://api.localtest.me:5001`

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
uv sync --extra examples
```

This installs:

- The jwt_verification extension
- Flask
- Auth0 Python SDK
- python-dotenv
- Other dependencies

### 5. Generate HTTPS Certificates with mkcert (Optional)

The demo includes development certificates in the certs/ directory.
If you need to regenerate them, you can use mkcert to create locally trusted certificates.

Install mkcert from the official repository: [mkcert](https://github.com/FiloSottile/mkcert)

Then run:

```bash
cd examples/auth0_demo/certs

mkcert -install        # one-time setup
mkcert api.localtest.me
```

This will generate:

```code
api.localtest.me.pem
api.localtest.me-key.pem
```

You can then access the demo at:

```code
https://api.localtest.me:5000
```

## Running the Demo

### Two-Server Setup

This demo requires **two separate Flask servers** running simultaneously:

#### Terminal 1 - Backend API (Port 5001)

```bash
cd examples/auth0_demo
bash run_backend.sh
```

#### Terminal 2 - Login Provider (Port 5000)

```bash
cd examples/auth0_demo
bash run_login_provider.sh
```

Both servers must be running for the demo to work properly.

### Access the Application

Navigate to: <https://api.localtest.me:5000>

**Note:** You'll see a browser warning about the self-signed certificate. This is expected for local development. Click "Advanced" and proceed.

## Features Demonstrated

### 1. OAuth 2.0 Login Flow

- Click "🚀 Login with Auth0" to authenticate
- Redirects to Auth0 for login
- Returns to application with JWT tokens stored as HTTP-only cookies

### 2. Protected Routes

- **`/protected`** - User profile page (requires authentication)
- **`/api/test-access`** - Backend API endpoint (requires JWT)

### 4. CORS Configuration

Both servers are configured for cross-origin communication:

- Backend API accepts requests from Login Provider
- Credentials (cookies) are included in cross-origin requests
- Proper CORS headers for secure token transmission

### 5. Test Backend Access

The **Test Backend Access** button demonstrates:

- Cross-origin request from Login Provider (5000) to Backend (5001)

- Bearer token + cookie authentication
- Visual feedback: ✓ Permission Granted or ✗ Access Denied

## Code Examples

### Backend API (Port 5001)

```python
from flask import Flask, jsonify
from flask_cors import CORS
from jwt_verification import AuthExtension

app = Flask(__name__)

CORS(app, origins=["https://api.localtest.me:5000"], supports_credentials=True)

auth = AuthExtension(verifier=verifier, authorizer=authorizer)
auth.init_app(app)

@app.get("/api/test-access")
@auth.require()
def test_access():
    return jsonify({"status": "success", "message": "Permission Granted ✓"})
```

### Login Provider (Port 5000)

```python
from authlib.integrations.flask_client import OAuth
from flask import Flask, redirect, make_response
from flask_cors import CORS

app = Flask(__name__)
CORS(app, origins=["https://api.localtest.me:5001"], supports_credentials=True)

oauth = OAuth(app)
auth0 = oauth.register("auth0", ...)

@app.get("/login")
def login():
    return auth0.authorize_redirect(redirect_uri=..., audience=...)

@app.get("/login-redirect")
def login_redirect():
    token = auth0.authorize_access_token()
    resp = make_response(redirect("/home"))
    resp.set_cookie("access_token", token["access_token"], httponly=True, secure=True)
    return resp
```

## Troubleshooting

### Certificate Warning

Expected with self-signed certs. Click "Advanced" → proceed.

### Callback URL Mismatch

Verify Auth0 callback URL: `https://api.localtest.me:5000/login-redirect`

### CORS Errors

- Ensure both servers running (5000 and 5001)
- Check CORS origins in both `backend.py` and `login_provider.py`

### Test Button Shows "Access Denied"

- Log in first via OAuth flow
- Check cookies in DevTools (Application → Cookies)
- Verify both servers on correct ports

### Port Already in Use

```bash
# Windows
netstat -ano | findstr :5000
taskkill /PID <PID> /F

# Linux/Mac
lsof -ti:5000 | xargs kill -9
```

### Cookies Not Sent

- Use HTTPS (not HTTP)
- Use `api.localtest.me` (not `localhost`)
- Verify `credentials: 'include'` in fetch

## Project Structure

```text
examples/auth0_demo/
├── backend.py              # Backend API (Port 5001)
├── login_provider.py       # Login Provider (Port 5000)
├── app_config.py           # Shared configuration
├── run_backend.sh          # Start backend script
├── run_login_provider.sh   # Start login provider script
├── .env                    # Environment variables
├── certs/                  # SSL certificates
├── templates/              # HTML (home, profile, 401)
└── static/                 # CSS with animations
```

## Documentation

- [Extension README](../../docs/README.md)
- [API Reference](../../docs/API_REFERENCE.md)
- [Auth0 Docs](https://auth0.com/docs)

## License

MIT License

---

**Last Updated:** 2026
