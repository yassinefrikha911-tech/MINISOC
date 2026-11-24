from datetime import datetime, timedelta, timezone

from minisoc.db import connect
from minisoc.rules import load_events, rule_r1

print("--- R1 on the database")
con = connect()
events = load_events(con)
con.close()
print("Events loaded:", len(events))
for alert in rule_r1(events):
    print(alert["rule"], alert["priority"], alert["ip"], "count", alert["event_count"],
          "threshold", alert["threshold"], alert["first_seen"], "->", alert["last_seen"])
    print("  evidence event ids:", alert["event_ids"])


def fake(ip, minutes):
    """Make SSH failure events at the given minutes after 10:00."""
    base = datetime(2026, 11, 17, 10, 0, tzinfo=timezone.utc)
    return [
        {"id": n, "timestamp": (base + timedelta(minutes=m)).isoformat(),
         "source": "ssh", "ip": ip, "type": "ssh_auth_failure"}
        for n, m in enumerate(minutes, start=1)
    ]


print("--- R1 edge cases")
CASES = [
    ("4 failures in 1 minute", [0, .2, .4, .6], 0),
    ("5 failures in 1 minute", [0, .2, .4, .6, .8], 1),
    ("5 failures, 2.5 minutes apart", [0, 2.5, 5, 7.5, 10], 0),
    ("two bursts 1 hour apart", [0, .2, .4, .6, .8, 60, 60.2, 60.4, 60.6, 60.8], 2),
    ("10 failures in 2 minutes", [i * .2 for i in range(10)], 1),
]
for name, minutes, expected in CASES:
    got = len(rule_r1(fake("203.0.113.9", minutes)))
    print("OK   " if got == expected else "WRONG", name, "- expected", expected, "got", got)

big = rule_r1(fake("203.0.113.9", [i * .2 for i in range(10)]))
print("Priority with 10 failures:", big[0]["priority"])