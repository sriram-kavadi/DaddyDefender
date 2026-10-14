"""
Database setup and connection management for Threat Check.
Uses aiosqlite for async SQLite operations.
"""
import aiosqlite
import os
import json
from datetime import datetime, timezone

DATABASE_PATH = os.getenv("DATABASE_PATH", "threatcheck.db")


async def get_db_path() -> str:
    """Return the resolved database path."""
    if os.getenv("VERCEL") or os.getenv("AWS_LAMBDA_FUNCTION_NAME"):
        default_path = "/tmp/threatcheck.db"
    else:
        default_path = "threatcheck.db"

    path = os.getenv("DATABASE_PATH", default_path)
    if os.path.isabs(path):
        return path
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), path)


async def init_db():
    """Initialize the database schema. Safe to call multiple times."""
    db_path = await get_db_path()
    async with aiosqlite.connect(db_path) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                scan_type TEXT NOT NULL,
                input_preview TEXT NOT NULL,
                input_length INTEGER NOT NULL,
                classification TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                findings TEXT NOT NULL,
                links TEXT,
                recommendations TEXT NOT NULL,
                provider_results TEXT,
                explanation TEXT,
                limitations TEXT,
                status TEXT NOT NULL DEFAULT 'completed',
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """)
        await db.execute("""
            CREATE INDEX IF NOT EXISTS idx_scans_created
            ON scans(created_at DESC)
        """)
        await db.execute("""
            CREATE INDEX IF NOT EXISTS idx_scans_type
            ON scans(scan_type)
        """)
        await db.commit()


async def get_connection():
    """Get a database connection."""
    db_path = await get_db_path()
    db = await aiosqlite.connect(db_path)
    db.row_factory = aiosqlite.Row
    return db


async def save_scan(scan_data: dict) -> None:
    """Persist a scan result to the database."""
    db = await get_connection()
    try:
        await db.execute(
            """INSERT INTO scans
               (id, scan_type, input_preview, input_length, classification,
                risk_score, risk_level, findings, links, recommendations,
                provider_results, explanation, limitations, status, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_data["id"],
                scan_data["scan_type"],
                scan_data.get("input_preview", ""),
                scan_data.get("input_length", 0),
                scan_data.get("classification", "unknown"),
                scan_data["risk_score"],
                scan_data["risk_level"],
                json.dumps(scan_data.get("findings", [])),
                json.dumps(scan_data.get("links", [])),
                json.dumps(scan_data.get("recommendations", [])),
                json.dumps(scan_data.get("provider_results", {})),
                scan_data.get("explanation", ""),
                scan_data.get("limitations", ""),
                scan_data.get("status", "completed"),
                scan_data.get("created_at", datetime.now(timezone.utc).isoformat()),
            ),
        )
        await db.commit()
    finally:
        await db.close()


async def get_scan(scan_id: str) -> dict | None:
    """Retrieve a scan result by ID."""
    db = await get_connection()
    try:
        cursor = await db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        row = await cursor.fetchone()
        if not row:
            return None
        return _row_to_dict(row)
    finally:
        await db.close()


async def get_recent_scans(limit: int = 20, offset: int = 0) -> list[dict]:
    """Retrieve recent scans, newest first."""
    db = await get_connection()
    try:
        cursor = await db.execute(
            "SELECT * FROM scans ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
        rows = await cursor.fetchall()
        return [_row_to_dict(row) for row in rows]
    finally:
        await db.close()


async def get_scan_stats() -> dict:
    """Get aggregate statistics from persisted scans."""
    db = await get_connection()
    try:
        cursor = await db.execute("SELECT COUNT(*) as total FROM scans")
        total = (await cursor.fetchone())[0]

        cursor = await db.execute(
            "SELECT risk_level, COUNT(*) as count FROM scans GROUP BY risk_level"
        )
        levels = {row[0]: row[1] for row in await cursor.fetchall()}

        cursor = await db.execute(
            "SELECT scan_type, COUNT(*) as count FROM scans GROUP BY scan_type"
        )
        types = {row[0]: row[1] for row in await cursor.fetchall()}

        cursor = await db.execute("SELECT AVG(risk_score) as avg_score FROM scans")
        avg_row = await cursor.fetchone()
        avg_score = round(avg_row[0], 1) if avg_row[0] is not None else 0

        return {
            "total_scans": total,
            "by_level": levels,
            "by_type": types,
            "average_score": avg_score,
        }
    finally:
        await db.close()


async def delete_scan(scan_id: str) -> bool:
    """Delete a scan by ID. Returns True if a row was deleted."""
    db = await get_connection()
    try:
        cursor = await db.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def cleanup_old_scans(days: int = 30) -> int:
    """Delete scans older than the given number of days. Returns count deleted."""
    db = await get_connection()
    try:
        cursor = await db.execute(
            "DELETE FROM scans WHERE created_at < datetime('now', ?)",
            (f"-{days} days",),
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


def _row_to_dict(row) -> dict:
    """Convert a database row to a dictionary, parsing JSON fields."""
    d = dict(row)
    for field in ("findings", "links", "recommendations", "provider_results"):
        if field in d and isinstance(d[field], str):
            try:
                d[field] = json.loads(d[field])
            except (json.JSONDecodeError, TypeError):
                pass
    return d
