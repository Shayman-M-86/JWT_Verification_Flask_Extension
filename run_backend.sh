export FLASK_APP=src.backendAPI
export FLASK_ENV=development
uv run flask run --host 127.0.0.1 --port 5005 --cert certs/api.localtest.me.pem --key certs/api.localtest.me-key.pem