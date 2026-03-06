#!/usr/bin/env bash
set -euo pipefail

uv sync --frozen --extra examples
# Login Provider Server

# "To run both applications, open TWO separate terminals and run:"
# "Terminal 2 - Login Provider (port 5000):"

# From root run: bash examples/auth0_demo/run_login_provider.sh
export FLASK_APP=examples.auth0_demo.login_provider
export FLASK_ENV=development

CERT_FILE="examples/auth0_demo/certs/api.localtest.me.pem"
KEY_FILE="examples/auth0_demo/certs/api.localtest.me-key.pem"

echo "🚀 Starting Login Provider on port 5000..."
echo "📍 URL: https://localhost:5000"
echo ""

uv run flask run --host 127.0.0.1 --port 5000 
