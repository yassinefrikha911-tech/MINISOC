from collections import defaultdict
from datetime import datetime, timedelta, timezone

# Pedagogical values, calibrated on the demo logs (see docs/rules.md)
R1_TYPES = ("ssh_auth_failure", "ssh_invalid_user")


def load_events(con):
    """Read all events from the database as a list of dictionaries."""
    rows = con.execute(
        "SELECT id, timestamp, source, ip, type, severity, status_code "
        "FROM events ORDER BY timestamp, id"
    ).fetchall()
    return [dict(row) for row in rows]


def _time(event):
    return datetime.fromisoformat(event["timestamp"])


def find_bursts(times, window, threshold):
    """Find groups of events that fit `threshold` times inside `window`.

    times: sorted list of datetimes. Returns a list of (first, last) positions.
    """
    hot = set()
    start = 0
    for end in range(len(times)):
        # Slide the window: drop events that are too old
        while times[end] - times[start] > window:
            start += 1
        if end - start + 1 >= threshold:
            hot.update(range(start, end + 1))

    # Merge neighbouring hot events into bursts; a gap longer than the window splits them
    bursts = []
    for k in sorted(hot):
        if bursts and k == bursts[-1][1] + 1 and times[k] - times[k - 1] <= window:
            bursts[-1][1] = k
        else:
            bursts.append([k, k])
    return [(a, b) for a, b in bursts]


def build_alert(rule, title, events, ip, source, window_minutes, threshold, details):
    """Turn a group of events into an alert dictionary with its evidence."""
    count = len(events)
    return {
        "rule": rule,
        "title": title,
        "priority": "high" if count >= 2 * threshold else "medium",
        "first_seen": events[0]["timestamp"],
        "last_seen": events[-1]["timestamp"],
        "window_minutes": window_minutes,
        "ip": ip,
        "source": source,
        "event_count": count,
        "threshold": threshold,
        "details": details,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "event_ids": [e["id"] for e in events],
    }


def rule_r1(events, window_minutes=5, threshold=5):
    """R1: at least `threshold` SSH failures from one IP within `window_minutes`."""
    by_ip = defaultdict(list)
    for e in events:
        if e["source"] == "ssh" and e["type"] in R1_TYPES and e["ip"]:
            by_ip[e["ip"]].append(e)

    window = timedelta(minutes=window_minutes)
    alerts = []
    for ip, group in by_ip.items():
        group.sort(key=lambda e: (_time(e), e["id"]))
        times = [_time(e) for e in group]
        for first, last in find_bursts(times, window, threshold):
            burst = group[first:last + 1]
            details = (
                f"{len(burst)} failed SSH logins from {ip} within "
                f"{window_minutes} minutes (threshold {threshold})"
            )
            alerts.append(build_alert(
                "R1", "Repeated SSH failures", burst, ip, "ssh",
                window_minutes, threshold, details,
            ))
    return alerts