export FLASK_APP=src.login_provider
export FLASK_ENV=development
uv run flask run --host 127.0.0.1 --port 5000 --cert certs/api.localtest.me.pem --key certs/api.localtest.me-key.pem