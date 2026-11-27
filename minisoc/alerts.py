from .db import connect, DB_PATH
from .rules import load_events, run_rules

RANK = {"low": 1, "medium": 2, "high": 3}


def save_alerts(con, alerts):
    """Store alerts and their evidence links. Never duplicates, never deletes.

    An alert is the same as a stored one if rule, IP, first_seen and last_seen match.
    A stored alert can only be upgraded (low, medium, high), and this is reported.
    """
    report = {"new": 0, "unchanged": 0, "upgraded": 0}
    with con:  # one transaction: everything is saved, or nothing
        for a in alerts:
            # "IS ?" also matches an empty IP (NULL), where "= ?" never would
            row = con.execute(
                "SELECT id, priority FROM alerts WHERE rule = ? AND ip IS ? "
                "AND first_seen = ? AND last_seen = ?",
                (a["rule"], a["ip"], a["first_seen"], a["last_seen"]),
            ).fetchone()

            if row is None:
                cur = con.execute(
                    "INSERT INTO alerts (rule, title, priority, first_seen, last_seen, "
                    "window_minutes, ip, source, event_count, threshold, details, created_at) "
                    "VALUES (:rule, :title, :priority, :first_seen, :last_seen, "
                    ":window_minutes, :ip, :source, :event_count, :threshold, :details, "
                    ":created_at)",
                    a,
                )
                alert_id = cur.lastrowid
                report["new"] += 1
            else:
                alert_id = row["id"]
                if RANK[a["priority"]] > RANK[row["priority"]]:
                    con.execute(
                        "UPDATE alerts SET priority = ?, details = ? WHERE id = ?",
                        (a["priority"], a["details"], alert_id),
                    )
                    report["upgraded"] += 1
                else:
                    report["unchanged"] += 1

            # Evidence links; IGNORE skips a pair that already exists
            con.executemany(
                "INSERT OR IGNORE INTO alert_events (alert_id, event_id) VALUES (?, ?)",
                [(alert_id, event_id) for event_id in a["event_ids"]],
            )
    return report


def detect_and_save(db_path=DB_PATH):
    """Run every rule on the stored events and save the resulting alerts."""
    con = connect(db_path)
    try:
        events = load_events(con)
        alerts = run_rules(events)
        report = save_alerts(con, alerts)
        report["events"] = len(events)
        report["found"] = len(alerts)
        return report
    finally:
        con.close()


def list_alerts(con):
    """All stored alerts, oldest first."""
    rows = con.execute("SELECT * FROM alerts ORDER BY first_seen, id").fetchall()
    return [dict(row) for row in rows]


def get_evidence(con, alert_id):
    """The events that prove one alert (a JOIN through alert_events)."""
    rows = con.execute(
        "SELECT e.id, e.timestamp, e.source, e.ip, e.type, e.severity, "
        "e.status_code, e.summary, e.raw "
        "FROM alert_events ae JOIN events e ON e.id = ae.event_id "
        "WHERE ae.alert_id = ? ORDER BY e.timestamp, e.id",
        (alert_id,),
    ).fetchall()
    return [dict(row) for row in rows]