#!/usr/bin/env bash
set -euo pipefail

uv sync --frozen --extra examples
# Backend API Server

# "To run both applications, open TWO separate terminals and run:"
# "Terminal 1 - Backend API (port 5001):"

# From root run: bash examples/auth0_demo/run_backend.sh
# export FLASK_APP=examples.auth0_demo.backend



uv run flask run --host 0.0.0.0 --port 5001 
