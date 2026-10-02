import json
import sqlite3
from pathlib import Path
from datetime import datetime

DEFAULT_DB = Path("/var/lib/linux-hardener/hardener.db")


class Database:
    def __init__(self, path: str | None = None):
        self.path = Path(path or DEFAULT_DB)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.execute("CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY, hostname TEXT, score INTEGER, created_at TEXT, report_json TEXT)")
        self.conn.commit()

    def save_scan(self, report):
        self.conn.execute("INSERT INTO scans(hostname, score, created_at, report_json) VALUES(?,?,?,?)",
                          (report.hostname, report.score, datetime.utcnow().isoformat(), json.dumps(report.to_dict())))
        self.conn.commit()

    def recent(self, limit=20):
        rows = self.conn.execute("SELECT id, hostname, score, created_at FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [{"id": r[0], "hostname": r[1], "score": r[2], "created_at": r[3]} for r in rows]

    def latest(self, hostname: str):
        row = self.conn.execute("SELECT report_json FROM scans WHERE hostname=? ORDER BY id DESC LIMIT 1", (hostname,)).fetchone()
        return json.loads(row[0]) if row else None
