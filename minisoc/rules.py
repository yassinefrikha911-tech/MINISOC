from collections import Counter, defaultdict
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


def _per_ip_rule(events, keep, rule, title, source, window_minutes, threshold, describe):
    """Shared engine: group matching events by IP, then look for bursts."""
    by_ip = defaultdict(list)
    for e in events:
        if e["source"] == source and e["ip"] and keep(e):
            by_ip[e["ip"]].append(e)

    window = timedelta(minutes=window_minutes)
    alerts = []
    for ip, group in by_ip.items():
        group.sort(key=lambda e: (_time(e), e["id"]))
        times = [_time(e) for e in group]
        for first, last in find_bursts(times, window, threshold):
            burst = group[first:last + 1]
            alerts.append(build_alert(
                rule, title, burst, ip, source,
                window_minutes, threshold, describe(burst, ip),
            ))
    return alerts


def rule_r1(events, window_minutes=5, threshold=5):
    """R1: at least `threshold` SSH failures from one IP within `window_minutes`."""
    def describe(burst, ip):
        return (f"{len(burst)} failed SSH logins from {ip} within "
                f"{window_minutes} minutes (threshold {threshold}).")

    return _per_ip_rule(
        events, lambda e: e["type"] in R1_TYPES,
        "R1", "Repeated SSH failures", "ssh", window_minutes, threshold, describe,
    )


def rule_r2(events, window_minutes=2, threshold=5):
    """R2: at least `threshold` HTTP 4xx/5xx responses to one IP within `window_minutes`."""
    def describe(burst, ip):
        codes = Counter(e["status_code"] for e in burst)
        listed = ", ".join(f"{code} x{n}" for code, n in sorted(codes.items()))
        return (f"{len(burst)} HTTP error responses (4xx/5xx) for requests from {ip} "
                f"within {window_minutes} minutes (threshold {threshold}). Codes: {listed}.")

    return _per_ip_rule(
        events,
        lambda e: e["status_code"] is not None and 400 <= e["status_code"] <= 599,
        "R2", "Repeated HTTP errors", "http", window_minutes, threshold, describe,
    )


def escalate(alerts):
    """The same IP triggering two different rules makes both alerts high."""
    rules_by_ip = defaultdict(set)
    for a in alerts:
        if a["ip"]:
            rules_by_ip[a["ip"]].add(a["rule"])
    for a in alerts:
        if a["ip"] and len(rules_by_ip[a["ip"]]) >= 2:
            a["priority"] = "high"
            a["details"] += " Also flagged by another rule for the same IP."
    return alerts


def rule_r3(events, threshold=30):
    """R3: at least `threshold` HTTP requests in one calendar minute (all IPs)."""
    per_minute = defaultdict(list)
    for e in events:
        if e["source"] == "http":
            per_minute[_time(e).replace(second=0, microsecond=0)].append(e)

    # Fixed window: each calendar minute is counted on its own
    hot = sorted(m for m, group in per_minute.items() if len(group) >= threshold)

    # Consecutive hot minutes belong to the same spike
    spikes = []
    for minute in hot:
        if spikes and minute - spikes[-1][-1] == timedelta(minutes=1):
            spikes[-1].append(minute)
        else:
            spikes.append([minute])

    alerts = []
    for minutes in spikes:
        group = sorted(
            (e for m in minutes for e in per_minute[m]),
            key=lambda e: (_time(e), e["id"]),
        )
        peak_minute = max(minutes, key=lambda m: len(per_minute[m]))
        peak = len(per_minute[peak_minute])

        top = ""
        ips = Counter(e["ip"] for e in group if e["ip"])
        if ips:
            top_ip, top_n = ips.most_common(1)[0]
            top = f" Top source: {top_ip} ({top_n} requests)."

        details = (
            f"Peak of {peak} HTTP requests in one minute "
            f"({peak_minute.strftime('%H:%M')} UTC), threshold {threshold} per minute. "
            f"Spike lasted {len(minutes)} minute(s).{top}"
        )
        alert = build_alert(
            "R3", "Request volume spike", group, None, "http", 1, threshold, details
        )
        # Priority from the busiest minute, not from the total of the merged minutes
        alert["priority"] = "high" if peak >= 2 * threshold else "medium"
        alerts.append(alert)
    return alerts


def run_rules(events):
    """Run every rule, then rank the alerts."""
    return escalate(rule_r1(events) + rule_r2(events) + rule_r3(events))