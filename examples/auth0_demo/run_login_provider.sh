#!/usr/bin/env bash
set -euo pipefail

uv sync --frozen --extra examples
# Login Provider Server

# "To run both applications, open TWO separate terminals and run:"
# "Terminal 2 - Login Provider (port 5000):"

# From root run: bash examples/auth0_demo/run_login_provider.sh
# export FLASK_APP=examples.auth0_demo.login_provider



uv run flask run --host 0.0.0.0 --port 5000 
