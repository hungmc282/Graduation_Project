"""Small SQLite store for drafts and immutable report snapshots."""
import json
import sqlite3
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from uuid import uuid4

from sv4_app_llm.config import DATABASE_PATH


@contextmanager
def connection(path=DATABASE_PATH):
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(path, timeout=10)) as db, db:
        db.row_factory = sqlite3.Row
        db.execute('''CREATE TABLE IF NOT EXISTS records (
            id TEXT PRIMARY KEY, kind TEXT NOT NULL, created_at TEXT NOT NULL,
            title TEXT NOT NULL, payload TEXT NOT NULL)''')
        yield db


def save_record(kind, title, payload, path=DATABASE_PATH):
    record_id = str(uuid4())
    created_at = datetime.now(timezone.utc).isoformat()
    encoded = json.dumps(payload, ensure_ascii=False, allow_nan=False)
    with connection(path) as db:
        db.execute("INSERT INTO records VALUES (?, ?, ?, ?, ?)",
                   (record_id, kind, created_at, title, encoded))
    return record_id


def list_records(kind, path=DATABASE_PATH):
    with connection(path) as db:
        rows = db.execute(
            "SELECT id, created_at, title FROM records WHERE kind=? "
            "ORDER BY created_at DESC", (kind,)).fetchall()
    return [dict(row) for row in rows]


def get_record(record_id, path=DATABASE_PATH):
    with connection(path) as db:
        row = db.execute("SELECT * FROM records WHERE id=?", (record_id,)).fetchone()
    if row is None:
        raise ValueError("Không tìm thấy bản ghi.")
    record = dict(row)
    record["payload"] = json.loads(record["payload"])
    return record


def update_record(record_id, kind, title, payload, path=DATABASE_PATH):
    """Update a user-owned profile only; analysis/evidence snapshots stay append-only."""
    if kind not in ("website", "enterprise_asset"):
        raise ValueError("Chỉ cho phép cập nhật hồ sơ tài sản.")
    encoded = json.dumps(payload, ensure_ascii=False, allow_nan=False)
    with connection(path) as db:
        cursor = db.execute("UPDATE records SET title=?, payload=? WHERE id=? AND kind=?",
                            (title, encoded, record_id, kind))
        if cursor.rowcount != 1:
            raise ValueError("Không tìm thấy hồ sơ website.")
