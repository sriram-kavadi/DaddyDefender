"""
Threat Check Backend — FastAPI Application

AI-Powered Digital Threat Detection and Digital Trust Platform.
Provides API endpoints for URL and message threat analysis with
heuristic rules, optional threat intelligence integration, and
persistent scan history.

Usage:
    cd backend
    uvicorn main:app --reload --port 8000
"""
import os
import sys
import logging
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Load environment variables from backend/.env explicitly
backend_dir = os.path.dirname(os.path.abspath(__file__))
dotenv_path = os.path.join(backend_dir, ".env")
if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path=dotenv_path)
else:
    load_dotenv()

# Add parent directory to path so we can import backend modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.database import init_db
from backend.routes.analyze import router as analyze_router
from backend.routes.scans import router as scans_router
from backend.routes.health import router as health_router

# ──────────────────────────────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger("threatcheck")


# ──────────────────────────────────────────────────────────────────────
# Rate limiting
# ──────────────────────────────────────────────────────────────────────

rate_limit = os.getenv("RATE_LIMIT", "30/minute")
limiter = Limiter(key_func=get_remote_address, default_limits=[rate_limit])


# ──────────────────────────────────────────────────────────────────────
# App lifecycle
# ──────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize database on startup."""
    try:
        logger.info("Initializing database...")
        await init_db()
        logger.info("Database initialized.")
    except Exception as e:
        logger.error(f"Non-fatal database startup error: {e}")
    logger.info("Threat Check backend is ready.")
    yield
    logger.info("Shutting down Threat Check backend.")


# ──────────────────────────────────────────────────────────────────────
# FastAPI application
# ──────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Threat Check API",
    description=(
        "AI-Powered Digital Threat Detection and Digital Trust Platform. "
        "Analyzes URLs and messages for phishing, scam, and social engineering indicators."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

# Rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS
cors_origins = os.getenv("CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:5500,http://localhost:5500,http://localhost:8080,http://127.0.0.1:8000,http://localhost:8000")
origins = [o.strip() for o in cors_origins.split(",") if o.strip()]
# Also allow file:// for local development
origins.append("null")

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)


# ──────────────────────────────────────────────────────────────────────
# Error handlers
# ──────────────────────────────────────────────────────────────────────

@app.exception_handler(422)
async def validation_error_handler(request: Request, exc):
    """Return clean validation errors without exposing internals."""
    return JSONResponse(
        status_code=422,
        content={
            "error": "validation_error",
            "detail": "The submitted data is invalid. Please check your input.",
            "status_code": 422,
        },
    )


@app.exception_handler(500)
async def internal_error_handler(request: Request, exc):
    """Return clean internal errors without exposing stack traces."""
    logger.error(f"Internal error: {exc}")
    return JSONResponse(
        status_code=500,
        content={
            "error": "internal_error",
            "detail": "An unexpected error occurred. Please try again.",
            "status_code": 500,
        },
    )


# ──────────────────────────────────────────────────────────────────────
# Request size limit middleware
# ──────────────────────────────────────────────────────────────────────

MAX_BODY_SIZE = int(os.getenv("MAX_INPUT_LENGTH", "10000")) * 2  # generous buffer for JSON wrapper

@app.middleware("http")
async def limit_request_size(request: Request, call_next):
    """Reject requests that exceed the maximum body size."""
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > MAX_BODY_SIZE:
        return JSONResponse(
            status_code=413,
            content={
                "error": "payload_too_large",
                "detail": "Request body exceeds the maximum allowed size.",
                "status_code": 413,
            },
        )
    return await call_next(request)


# ──────────────────────────────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────────────────────────────

app.include_router(analyze_router)
app.include_router(scans_router)
app.include_router(health_router)


@app.get("/", include_in_schema=False)
async def root():
    """Root endpoint redirect to API docs."""
    return {
        "name": "Threat Check API",
        "version": "1.0.0",
        "docs": "/api/docs",
        "health": "/api/health",
    }


if __name__ == "__main__":
    import uvicorn
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    debug = os.getenv("DEBUG", "false").lower() in ("true", "1")
    uvicorn.run("backend.main:app", host=host, port=port, reload=debug)
