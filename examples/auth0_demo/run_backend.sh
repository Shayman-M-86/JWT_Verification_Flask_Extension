#!/usr/bin/env bash
set -euo pipefail

uv sync --frozen --extra examples
# Backend API Server

# "To run both applications, open TWO separate terminals and run:"
# "Terminal 1 - Backend API (port 5001):"

# From root run: bash examples/auth0_demo/run_backend.sh
export FLASK_APP=examples.auth0_demo.backend
export FLASK_ENV=development

CERT_FILE="examples/auth0_demo/certs/api.localtest.me.pem"
KEY_FILE="examples/auth0_demo/certs/api.localtest.me-key.pem"

echo "🚀 Starting Backend API on port 5001..."
echo "📍 URL: https://api.localtest.me:5001"
echo ""

uv run flask run --host 127.0.0.1 --port 5001 --cert "$CERT_FILE" --key "$KEY_FILE"
