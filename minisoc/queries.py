import csv
import io
from datetime import datetime, timedelta, timezone

EVENT_COLUMNS = ["timestamp", "source", "ip", "type", "severity", "status_code", "summary"]
EVENT_HEADERS = ["timestamp_utc", "source", "ip", "type", "severity", "status_code", "summary"]
ALERT_COLUMNS = ["id", "rule", "title", "priority", "first_seen", "last_seen",
                 "window_minutes", "ip", "source", "event_count", "threshold",
                 "details", "evidence_ids"]
ALERT_HEADERS = ["id", "rule", "title", "priority", "first_seen_utc", "last_seen_utc",
                 "window_minutes", "ip", "source", "event_count", "threshold",
                 "details", "evidence_event_ids"]

# A cell starting with one of these can be read as a formula by a spreadsheet
RISKY = ("=", "+", "-", "@", "\t", "\r", "\n")


def _day_start(day):
    return datetime(day.year, day.month, day.day, tzinfo=timezone.utc).isoformat()


def period_bounds(start, end):
    """Two dates (both days included) become [first, after): ISO text in UTC."""
    return _day_start(start), _day_start(end + timedelta(days=1))


def _in_clause(values):
    """'(?, ?, ?)' with one placeholder per value. Values are never put in the SQL."""
    return "(" + ", ".join("?" for _ in values) + ")"


def filter_events(con, start, end, ip=None, sources=("ssh", "http")):
    """Events inside the period, for the chosen sources and (optionally) one IP."""
    if not sources:
        return []
    first, after = period_bounds(start, end)
    sql = (
        "SELECT id, timestamp, source, ip, type, severity, status_code, summary, raw "
        "FROM events WHERE timestamp >= ? AND timestamp < ? AND source IN "
        + _in_clause(sources)
    )
    params = [first, after, *sources]
    if ip:
        sql += " AND ip = ?"
        params.append(ip)
    sql += " ORDER BY timestamp, id"
    return [dict(row) for row in con.execute(sql, params).fetchall()]


def filter_alerts(con, start, end, ip=None, sources=("ssh", "http"),
                  priorities=("low", "medium", "high")):
    """Alerts whose observed period overlaps the chosen period."""
    if not sources or not priorities:
        return []
    first, after = period_bounds(start, end)
    sql = (
        "SELECT a.*, (SELECT GROUP_CONCAT(event_id) FROM alert_events "
        "WHERE alert_id = a.id) AS evidence_ids "
        "FROM alerts a WHERE a.first_seen < ? AND a.last_seen >= ? "
        "AND a.source IN " + _in_clause(sources)
        + " AND a.priority IN " + _in_clause(priorities)
    )
    params = [after, first, *sources, *priorities]
    if ip:
        sql += " AND a.ip = ?"
        params.append(ip)
    sql += " ORDER BY a.first_seen, a.id"
    return [dict(row) for row in con.execute(sql, params).fetchall()]


def event_date_range(con):
    """First and last day with events (today and today if there are none)."""
    row = con.execute("SELECT MIN(timestamp), MAX(timestamp) FROM events").fetchone()
    if row[0] is None:
        today = datetime.now(timezone.utc).date()
        return today, today
    return datetime.fromisoformat(row[0]).date(), datetime.fromisoformat(row[1]).date()


def totals(con):
    return {
        "events": con.execute("SELECT COUNT(*) FROM events").fetchone()[0],
        "alerts": con.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
    }


def safe_cell(value):
    """Empty values become empty cells. Risky text gets a quote in front."""
    if value is None:
        return ""
    if isinstance(value, str) and value.startswith(RISKY):
        return "'" + value
    return value


def to_csv(rows, columns, headers):
    """CSV text for the given rows. The csv module handles commas and quotes."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(headers)
    for row in rows:
        writer.writerow([safe_cell(row[column]) for column in columns])
    return buffer.getvalue()