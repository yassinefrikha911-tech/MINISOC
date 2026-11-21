import sqlite3
from pathlib import Path

DB_PATH = Path("minisoc.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS imports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file TEXT NOT NULL,
    source TEXT NOT NULL CHECK (source IN ('ssh', 'http')),
    imported_at TEXT NOT NULL,
    year_used INTEGER,
    file_hash TEXT,
    accepted INTEGER NOT NULL DEFAULT 0,
    rejected INTEGER NOT NULL DEFAULT 0,
    result TEXT
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    import_id INTEGER REFERENCES imports(id),
    timestamp TEXT NOT NULL,
    source TEXT NOT NULL CHECK (source IN ('ssh', 'http')),
    file TEXT NOT NULL,
    ip TEXT,
    type TEXT NOT NULL,
    severity TEXT NOT NULL
        CHECK (severity IN ('info', 'low', 'medium', 'high', 'unknown')),
    status_code INTEGER,
    summary TEXT NOT NULL,
    raw TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule TEXT NOT NULL,
    title TEXT NOT NULL,
    priority TEXT NOT NULL CHECK (priority IN ('low', 'medium', 'high')),
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    window_minutes INTEGER,
    ip TEXT,
    source TEXT,
    event_count INTEGER NOT NULL,
    threshold INTEGER NOT NULL,
    details TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alert_events (
    alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    event_id INTEGER NOT NULL REFERENCES events(id),
    PRIMARY KEY (alert_id, event_id)
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip);
CREATE INDEX IF NOT EXISTS idx_events_source ON events(source);
CREATE INDEX IF NOT EXISTS idx_alerts_priority ON alerts(priority);
CREATE INDEX IF NOT EXISTS idx_alerts_first_seen ON alerts(first_seen);
"""


def connect(path=DB_PATH):
    """Open the database. Rows can be read by column name."""
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")  # make SQLite enforce the links
    return con


def init_db(path=DB_PATH):
    """Create the tables if they don't exist. Safe to run many times."""
    con = connect(path)
    con.executescript(SCHEMA)
    con.commit()
    con.close()