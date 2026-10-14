import os
import sys

# Ensure project root directory is in sys.path so 'backend' can be imported
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

# Ensure database path is in /tmp for Vercel's serverless read-only filesystem
if os.getenv("VERCEL") or os.getenv("AWS_LAMBDA_FUNCTION_NAME"):
    os.environ.setdefault("DATABASE_PATH", "/tmp/threatcheck.db")

from backend.main import app
