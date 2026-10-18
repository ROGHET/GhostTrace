import sys
from pathlib import Path

# Ensure project root is in sys.path for Vercel serverless functions
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Import the WSGI Flask app
from app import app


class VercelPathMiddleware:
    """WSGI middleware to restore original request path from Vercel headers."""

    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        # Vercel rewrites all routes to /api/index, but passes original request
        # path in x-matched-path or x-forwarded-uri
        matched_path = (
            environ.get("HTTP_X_MATCHED_PATH")
            or environ.get("HTTP_X_FORWARDED_URI")
            or environ.get("HTTP_X_NOW_ROUTE_MATCHES")
        )
        if matched_path:
            environ["PATH_INFO"] = matched_path
        elif environ.get("PATH_INFO", "").rstrip("/") in ("/api/index", "/api"):
            environ["PATH_INFO"] = "/"

        return self.wsgi_app(environ, start_response)


# Wrap Flask app with Vercel path normalizer
app.wsgi_app = VercelPathMiddleware(app.wsgi_app)
