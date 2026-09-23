from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "pencentral.db"
_lock = threading.Lock()
_con: sqlite3.Connection | None = None


def connect() -> sqlite3.Connection:
    global _con
    if _con is not None:
        return _con
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    _con = sqlite3.connect(str(DB_PATH), check_same_thread=False, timeout=30, isolation_level=None)
    _con.row_factory = sqlite3.Row
    try:
        _con.execute("PRAGMA journal_mode=MEMORY")
    except sqlite3.Error:
        pass
    _con.execute("PRAGMA synchronous=OFF")
    _con.execute("PRAGMA foreign_keys=ON")
    _con.execute("PRAGMA busy_timeout=30000")
    return _con


def init() -> None:
    with _lock:
        con = connect()
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                stages TEXT NOT NULL,
                wordlist TEXT,
                authorized INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'queued',
                current_stage TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                finished_at TEXT,
                error TEXT
            );
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                level TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                detail TEXT,
                severity TEXT DEFAULT 'info',
                reviewed INTEGER NOT NULL DEFAULT 0,
                note TEXT DEFAULT '',
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
            CREATE INDEX IF NOT EXISTS idx_logs_scan ON logs(scan_id);
            """
        )
        cols = {r[1] for r in con.execute("PRAGMA table_info(findings)")}
        for name in ("url", "ip", "screenshot"):
            if name not in cols:
                con.execute(f"ALTER TABLE findings ADD COLUMN {name} TEXT DEFAULT ''")
        con.commit()


def create_scan(target: str, stages: list[str], wordlist: str | None) -> int:
    with _lock:
        con = connect()
        cur = con.execute(
            "INSERT INTO scans(target, stages, wordlist, authorized, status) VALUES (?,?,?,?,?)",
            (target, ",".join(stages), wordlist, 1, "queued"),
        )
        con.commit()
        sid = int(cur.lastrowid)
        pass
        return sid


def delete_scan(scan_id: int) -> bool:
    with _lock:
        con = connect()
        row = con.execute("SELECT id FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not row:
            return False
        con.execute("DELETE FROM findings WHERE scan_id=?", (scan_id,))
        con.execute("DELETE FROM logs WHERE scan_id=?", (scan_id,))
        con.execute("DELETE FROM scans WHERE id=?", (scan_id,))
        con.commit()
        return True


def update_scan(scan_id: int, **fields) -> None:
    if not fields:
        return
    cols = ", ".join(f"{k}=?" for k in fields)
    vals = list(fields.values()) + [scan_id]
    with _lock:
        con = connect()
        con.execute(f"UPDATE scans SET {cols} WHERE id=?", vals)
        con.commit()
        pass


def add_log(scan_id: int, level: str, message: str) -> None:
    with _lock:
        con = connect()
        con.execute(
            "INSERT INTO logs(scan_id, level, message) VALUES (?,?,?)",
            (scan_id, level, message),
        )
        con.commit()
        pass


def add_finding(
    scan_id: int,
    category: str,
    title: str,
    detail: str = "",
    severity: str = "info",
    url: str = "",
    ip: str = "",
    screenshot: str = "",
) -> int:
    with _lock:
        con = connect()
        cur = con.execute(
            """INSERT INTO findings(scan_id, category, title, detail, severity, url, ip, screenshot)
               VALUES (?,?,?,?,?,?,?,?)""",
            (scan_id, category, title, detail, severity, url or "", ip or "", screenshot or ""),
        )
        con.commit()
        fid = int(cur.lastrowid)
        pass
        return fid


def update_finding(finding_id: int, **fields) -> None:
    if not fields:
        return
    cols = ", ".join(f"{k}=?" for k in fields)
    vals = list(fields.values()) + [finding_id]
    with _lock:
        con = connect()
        con.execute(f"UPDATE findings SET {cols} WHERE id=?", vals)
        con.commit()
        pass


def get_finding(finding_id: int) -> dict | None:
    con = connect()
    row = con.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
    return dict(row) if row else None


def set_reviewed(finding_id: int, reviewed: bool, note: str | None = None) -> None:
    with _lock:
        con = connect()
        if note is None:
            con.execute(
                "UPDATE findings SET reviewed=? WHERE id=?",
                (1 if reviewed else 0, finding_id),
            )
        else:
            con.execute(
                "UPDATE findings SET reviewed=?, note=? WHERE id=?",
                (1 if reviewed else 0, note, finding_id),
            )
        con.commit()
        pass


def set_note(finding_id: int, note: str) -> None:
    with _lock:
        con = connect()
        con.execute("UPDATE findings SET note=? WHERE id=?", (note, finding_id))
        con.commit()
        pass


def list_scans() -> list[dict]:
    con = connect()
    rows = con.execute(
        """
        SELECT s.*,
               (SELECT COUNT(*) FROM findings f WHERE f.scan_id=s.id) AS findings,
               (SELECT COUNT(*) FROM findings f WHERE f.scan_id=s.id AND f.reviewed=1) AS reviewed
        FROM scans s
        ORDER BY s.id DESC
        """
    ).fetchall()
    return [dict(r) for r in rows]


def get_scan(scan_id: int) -> dict | None:
    con = connect()
    row = con.execute(
        """
        SELECT s.*,
               (SELECT COUNT(*) FROM findings f WHERE f.scan_id=s.id) AS findings,
               (SELECT COUNT(*) FROM findings f WHERE f.scan_id=s.id AND f.reviewed=1) AS reviewed
        FROM scans s WHERE s.id=?
        """,
        (scan_id,),
    ).fetchone()
    return dict(row) if row else None


def get_findings(scan_id: int, category: str | None = None) -> list[dict]:
    con = connect()
    if category:
        rows = con.execute(
            "SELECT * FROM findings WHERE scan_id=? AND category=? ORDER BY id",
            (scan_id, category),
        ).fetchall()
    else:
        rows = con.execute(
            "SELECT * FROM findings WHERE scan_id=? ORDER BY id",
            (scan_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_logs(scan_id: int, after_id: int = 0) -> list[dict]:
    con = connect()
    rows = con.execute(
        "SELECT * FROM logs WHERE scan_id=? AND id>? ORDER BY id",
        (scan_id, after_id),
    ).fetchall()
    return [dict(r) for r in rows]


def counts_by_category(scan_id: int) -> dict[str, int]:
    con = connect()
    rows = con.execute(
        "SELECT category, COUNT(*) AS n FROM findings WHERE scan_id=? GROUP BY category",
        (scan_id,),
    ).fetchall()
    return {r["category"]: r["n"] for r in rows}
