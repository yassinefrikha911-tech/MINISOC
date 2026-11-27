from datetime import datetime, timedelta, timezone

from minisoc.db import connect
from minisoc.rules import load_events, rule_r3, run_rules

BASE = datetime(2026, 11, 18, 14, 0, tzinfo=timezone.utc)


def fake_http(count, start, step=1.0, first_id=1, source="http"):
    """`count` requests, `step` seconds apart, starting `start` seconds after 14:00:00."""
    return [{"id": first_id + n,
             "timestamp": (BASE + timedelta(seconds=start + (n + 1) * step)).isoformat(),
             "source": source, "ip": "198.51.100.10",
             "type": "http_request", "status_code": 200}
            for n in range(count)]


def check(name, got, expected):
    print("OK   " if got == expected else "WRONG", name, "- expected", expected, "got", got)


print("--- R3 edge cases")
check("29 requests in one minute", len(rule_r3(fake_http(29, 0))), 0)
check("30 requests in one minute", len(rule_r3(fake_http(30, 0))), 1)
check("40 SSH events in one minute (ignored)", len(rule_r3(fake_http(40, 0, source="ssh"))), 0)
split = fake_http(15, 44) + fake_http(15, 59, first_id=100)
check("30 requests split over a minute boundary (known limit)", len(rule_r3(split)), 0)
two = rule_r3(fake_http(35, 0, 1.5) + fake_http(35, 60, 1.5, first_id=100))
check("two hot minutes in a row: one alert", len(two), 1)
check("merged alert counts all its events", two[0]["event_count"], 70)
apart = fake_http(35, 0, 1.5) + fake_http(35, 600, 1.5, first_id=100)
check("two spikes 10 minutes apart", len(rule_r3(apart)), 2)
check("60 requests in one minute: priority", rule_r3(fake_http(60, 0, 0.9))[0]["priority"], "high")
check("35 requests in one minute: priority", rule_r3(fake_http(35, 0, 1.5))[0]["priority"], "medium")

print("--- All rules on the database")
con = connect()
events = load_events(con)
con.close()
print("Events loaded:", len(events))
for a in run_rules(events):
    print(a["rule"], a["priority"], a["ip"], "count", a["event_count"],
          "threshold", a["threshold"], a["first_seen"], "->", a["last_seen"])
    print("  ", a["details"])