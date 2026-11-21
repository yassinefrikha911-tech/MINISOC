import hashlib
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from .db import connect, DB_PATH
from .parsers import ParseError, parse_http_line, parse_ssh_line

SOURCES = ("ssh", "http")


def _parse(source, line, filename, year):
    """Pick the right parser for the source."""
    if source == "ssh":
        return parse_ssh_line(line, filename, year=year)
    return parse_http_line(line, filename)


def import_file(path, source, year=None, db_path=DB_PATH):
    """Import one log file and return a report dictionary.

    A bad line is counted and explained, but never stops the import.
    An identical file that was already imported is refused, not overwritten.
    """
    if source not in SOURCES:
        raise ValueError(f"source must be one of {SOURCES}")

    path = Path(path)
    data = path.read_bytes()
    file_hash = hashlib.sha256(data).hexdigest()
    lines = data.decode("utf-8", errors="replace").splitlines()

    con = connect(db_path)
    try:
        # Duplicate policy: same content + same source, already imported
        previous = con.execute(
            "SELECT id, imported_at FROM imports "
            "WHERE file_hash = ? AND source = ? AND accepted > 0",
            (file_hash, source),
        ).fetchone()
        if previous:
            return {
                "file": path.name, "source": source, "status": "duplicate",
                "accepted": 0, "rejected": 0, "errors": [], "import_id": None,
                "duplicate_of": previous["id"], "previous_date": previous["imported_at"],
            }

        # Parse every line: good ones become events, bad ones are explained
        events, errors = [], []
        for number, line in enumerate(lines, start=1):
            if not line.strip():
                continue
            try:
                events.append(_parse(source, line, path.name, year))
            except ParseError as error:
                errors.append((number, str(error), line.strip()[:80]))

        accepted, rejected = len(events), len(errors)
        if accepted == 0:
            status = "failed"
        elif rejected:
            status = "partial"
        else:
            status = "ok"

        summary = status
        if errors:
            reasons = Counter(reason for _, reason, _ in errors)
            summary += ": " + "; ".join(f"{n} x {r}" for r, n in reasons.most_common())

        if source == "ssh":
            year_used = year if year is not None else datetime.now(timezone.utc).year
        else:
            year_used = None

        # One transaction: everything is saved, or nothing is
        with con:
            cur = con.execute(
                "INSERT INTO imports (file, source, imported_at, year_used, "
                "file_hash, accepted, rejected, result) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (path.name, source, datetime.now(timezone.utc).isoformat(),
                 year_used, file_hash, accepted, rejected, summary),
            )
            import_id = cur.lastrowid
            con.executemany(
                "INSERT INTO events (import_id, timestamp, source, file, ip, type, "
                "severity, status_code, summary, raw) VALUES (:import_id, :timestamp, "
                ":source, :file, :ip, :type, :severity, :status_code, :summary, :raw)",
                [dict(event, import_id=import_id) for event in events],
            )

        return {
            "file": path.name, "source": source, "status": status,
            "accepted": accepted, "rejected": rejected, "errors": errors,
            "import_id": import_id, "duplicate_of": None,
        }
    finally:
        con.close()


def format_report(report):
    """Turn a report dictionary into readable text."""
    lines = [f"Import of {report['file']} ({report['source']})"]
    if report["status"] == "duplicate":
        lines.append(
            f"  Skipped: identical file already imported (import #{report['duplicate_of']} "
            f"on {report['previous_date']}). Nothing was changed."
        )
        return "\n".join(lines)
    lines.append(
        f"  Result: {report['status']} - {report['accepted']} accepted, "
        f"{report['rejected']} rejected"
    )
    for number, reason, snippet in report["errors"][:10]:
        lines.append(f"  line {number}: {reason}  ->  {snippet}")
    if len(report["errors"]) > 10:
        lines.append(f"  ... and {len(report['errors']) - 10} more rejected lines")
    return "\n".join(lines)