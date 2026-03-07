#!/usr/bin/env bash
set -euo pipefail

uv sync --frozen --extra examples
# Login Provider Server

# "To run both applications, open TWO separate terminals and run:"
# "Terminal 2 - Login Provider (port 5000):"

# From root run: bash examples/auth0_demo/run_login_provider.sh
export FLASK_APP=examples.auth0_demo.login_provider
export FLASK_ENV=development

echo "🚀 Starting Login Provider on port 5000..."
echo "📍 URL: http://localhost:5000"
echo ""

uv run flask run --host 127.0.0.1 --port 5000 
