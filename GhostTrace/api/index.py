import sys
from pathlib import Path

# Ensure project root is in sys.path for Vercel serverless functions
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Import the WSGI Flask app
from app import app
