import json
import sys
from pathlib import Path
from urllib.parse import parse_qs

# Ensure project root is in sys.path for Vercel serverless functions
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Import the WSGI Flask app
from app import app


class VercelPathMiddleware:
    """WSGI middleware to restore original request path from Vercel route rewrites."""

    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        # Diagnostic interceptor for /debug
        raw_env_keys = " ".join([str(v) for k, v in environ.items() if isinstance(v, str)])
        if "debug" in raw_env_keys:
            data = {k: str(v) for k, v in environ.items() if isinstance(v, (str, int, bool))}
            body = json.dumps(data, indent=2).encode("utf-8")
            start_response(
                "200 OK",
                [
                    ("Content-Type", "application/json"),
                    ("Content-Length", str(len(body))),
                ],
            )
            return [body]

        # 1. Primary: Check explicit __route__ query param from vercel.json rewrite
        query_string = environ.get("QUERY_STRING", "")
        if query_string:
            qs = parse_qs(query_string)
            if "__route__" in qs and qs["__route__"]:
                route = qs["__route__"][0]
                if not route.startswith("/"):
                    route = "/" + route
                environ["PATH_INFO"] = route

        # 2. Secondary: Check proxy / runtime headers if __route__ not present
        if environ.get("PATH_INFO", "").rstrip("/") in ("/api/index", "/api"):
            fallback = (
                environ.get("RAW_URI")
                or environ.get("REQUEST_URI")
                or environ.get("HTTP_X_MATCHED_PATH")
                or environ.get("HTTP_X_FORWARDED_URI")
                or "/"
            )
            environ["PATH_INFO"] = fallback.split("?")[0] or "/"

        return self.wsgi_app(environ, start_response)


# Wrap Flask app with Vercel path normalizer
app.wsgi_app = VercelPathMiddleware(app.wsgi_app)
