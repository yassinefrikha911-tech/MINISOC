from datetime import datetime, timedelta, timezone

from minisoc.db import connect
from minisoc.rules import load_events, rule_r1, rule_r2, run_rules

con = connect()
events = load_events(con)
con.close()
print("Events loaded:", len(events))

print("--- All rules on the database")
for a in run_rules(events):
    print(a["rule"], a["priority"], a["ip"], "count", a["event_count"],
          "threshold", a["threshold"], a["first_seen"], "->", a["last_seen"])
    print("  ", a["details"])
    print("   evidence ids:", a["event_ids"])

BASE = datetime(2026, 11, 17, 10, 0, tzinfo=timezone.utc)
IP = "203.0.113.9"


def stamp(m):
    return (BASE + timedelta(minutes=m)).isoformat()


def fake_ssh(ip, minutes):
    return [{"id": n, "timestamp": stamp(m), "source": "ssh", "ip": ip,
             "type": "ssh_auth_failure", "status_code": None}
            for n, m in enumerate(minutes, start=1)]


def fake_http(ip, minutes, status=404):
    return [{"id": 100 + n, "timestamp": stamp(m), "source": "http", "ip": ip,
             "type": "http_request", "status_code": status}
            for n, m in enumerate(minutes, start=1)]


def check(name, got, expected):
    print("OK   " if got == expected else "WRONG", name, "- expected", expected, "got", got)


print("--- R1 edge cases")
check("4 failures in 1 minute", len(rule_r1(fake_ssh(IP, [0, .2, .4, .6]))), 0)
check("5 failures in 1 minute", len(rule_r1(fake_ssh(IP, [0, .2, .4, .6, .8]))), 1)
check("5 failures, 2.5 minutes apart", len(rule_r1(fake_ssh(IP, [0, 2.5, 5, 7.5, 10]))), 0)
check("two bursts 1 hour apart",
      len(rule_r1(fake_ssh(IP, [0, .2, .4, .6, .8, 60, 60.2, 60.4, 60.6, 60.8]))), 2)

print("--- R2 edge cases")
check("4 errors in 10 seconds", len(rule_r2(fake_http(IP, [0, .1, .2, .3]))), 0)
check("5 errors in 10 seconds", len(rule_r2(fake_http(IP, [0, .1, .2, .3, .4]))), 1)
check("5 errors, one per minute", len(rule_r2(fake_http(IP, [0, 1, 2, 3, 4]))), 0)
check("10 responses with status 200",
      len(rule_r2(fake_http(IP, [i * .1 for i in range(10)], 200))), 0)

print("--- Priority")
burst = [0, .2, .4, .6, .8]
same = run_rules(fake_ssh(IP, burst) + fake_http(IP, burst))
check("same IP, two rules", sorted(a["priority"] for a in same), ["high", "high"])
diff = run_rules(fake_ssh(IP, burst) + fake_http("203.0.113.10", burst))
check("two IPs, one rule each", sorted(a["priority"] for a in diff), ["medium", "medium"])
big = rule_r1(fake_ssh(IP, [i * .2 for i in range(10)]))
check("10 failures from one IP", big[0]["priority"], "high")