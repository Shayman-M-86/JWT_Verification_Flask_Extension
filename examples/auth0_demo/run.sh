export FLASK_APP=examples.auth0_demo.login_provider
export FLASK_ENV=development
uv run flask run --host 127.0.0.1 --port 5000 --cert examples/auth0_demo/certs/api.localtest.me.pem --key examples/auth0_demo/certs/api.localtest.me-key.pem