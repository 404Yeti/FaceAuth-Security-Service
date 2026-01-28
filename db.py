import sqlite3
import json
import time
from typing import Any, Optional

DB_PATH = "faceauth.db"

def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def _ensure_users_role_column(conn: sqlite3.Connection) -> None:
    cur = conn.cursor()
    cur.execute("PRAGMA table_info(users)")
    cols = [r["name"] for r in cur.fetchall()]
    if "role" not in cols:
        cur.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
        conn.commit()

def init_db() -> None:
    conn = connect()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        embedding_json TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        created_at INTEGER NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts INTEGER NOT NULL,
        event_type TEXT NOT NULL,
        username TEXT,
        ip TEXT,
        meta_json TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS auth_state (
        key TEXT PRIMARY KEY,
        value_json TEXT NOT NULL
    )
    """)

    _ensure_users_role_column(conn)
    conn.close()

def upsert_user(username: str, embedding: list[float], role: str = "user") -> None:
    conn = connect()
    cur = conn.cursor()
    cur.execute("""
    INSERT INTO users (username, embedding_json, role, created_at)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(username) DO UPDATE SET
      embedding_json = excluded.embedding_json,
      role = COALESCE(users.role, excluded.role)
    """, (username, json.dumps(embedding), role, int(time.time())))
    conn.commit()
    conn.close()

def get_user(username: str) -> Optional[dict[str, Any]]:
    conn = connect()
    cur = conn.cursor()
    cur.execute("SELECT username, embedding_json, role FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    return {
        "username": row["username"],
        "role": row["role"],
        "embedding": json.loads(row["embedding_json"]),
    }

def set_user_role(username: str, role: str) -> bool:
    conn = connect()
    cur = conn.cursor()
    cur.execute("UPDATE users SET role = ? WHERE username = ?", (role, username))
    conn.commit()
    updated = cur.rowcount > 0
    conn.close()
    return updated

def list_users() -> list[dict[str, Any]]:
    conn = connect()
    cur = conn.cursor()
    cur.execute("SELECT username, embedding_json, role FROM users")
    rows = cur.fetchall()
    conn.close()
    out = []
    for r in rows:
        out.append({
            "username": r["username"],
            "role": r["role"],
            "embedding": json.loads(r["embedding_json"]),
        })
    return out

def log_event(event_type: str, username: Optional[str], ip: Optional[str], meta: dict[str, Any]) -> None:
    conn = connect()
    cur = conn.cursor()
    cur.execute("""
    INSERT INTO events (ts, event_type, username, ip, meta_json)
    VALUES (?, ?, ?, ?, ?)
    """, (int(time.time()), event_type, username, ip, json.dumps(meta)))
    conn.commit()
    conn.close()

def list_events(limit: int = 50) -> list[dict[str, Any]]:
    conn = connect()
    cur = conn.cursor()
    cur.execute("""
    SELECT ts, event_type, username, ip, meta_json
    FROM events
    ORDER BY ts DESC
    LIMIT ?
    """, (limit,))
    rows = cur.fetchall()
    conn.close()
    out = []
    for r in rows:
        out.append({
            "ts": r["ts"],
            "event_type": r["event_type"],
            "username": r["username"],
            "ip": r["ip"],
            "meta": json.loads(r["meta_json"]) if r["meta_json"] else {},
        })
    return out

def get_state(key: str, default: dict[str, Any]) -> dict[str, Any]:
    conn = connect()
    cur = conn.cursor()
    cur.execute("SELECT value_json FROM auth_state WHERE key = ?", (key,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return default
    return json.loads(row["value_json"])

def set_state(key: str, value: dict[str, Any]) -> None:
    conn = connect()
    cur = conn.cursor()
    cur.execute("""
    INSERT INTO auth_state (key, value_json)
    VALUES (?, ?)
    ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json
    """, (key, json.dumps(value)))
    conn.commit()
    conn.close()
