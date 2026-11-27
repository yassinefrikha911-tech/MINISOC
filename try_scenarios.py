import os

from minisoc.alerts import detect_and_save, get_evidence, list_alerts
from minisoc.db import connect, init_db
from minisoc.importer import import_file

DB = "test_scenarios.db"


def check(name, got, expected):
    print("OK   " if got == expected else "WRONG", name, "- expected", expected, "got", got)


def run(*files):
    """Fresh database, import the files, run the rules. Returns accepted counts and alerts."""
    if os.path.exists(DB):
        os.remove(DB)
    init_db(DB)
    accepted = []
    for path, source in files:
        year = 2026 if source == "ssh" else None
        accepted.append(import_file(path, source, year=year, db_path=DB)["accepted"])
    detect_and_save(DB)
    con = connect(DB)
    alerts = list_alerts(con)
    evidence = {a["id"]: len(get_evidence(con, a["id"])) for a in alerts}
    con.close()
    return accepted, alerts, evidence


R1 = ("data/scenario_r1_ssh.log", "ssh")
R2 = ("data/scenario_r2_http.log", "http")
R3 = ("data/demo_r3_http.log", "http")

print("--- Scenario R1 (SSH)")
accepted, alerts, evidence = run(R1)
check("lines accepted", accepted, [13])
check("number of alerts", len(alerts), 1)
a = alerts[0]
check("rule", a["rule"], "R1")
check("IP", a["ip"], "192.0.2.10")
check("event count", a["event_count"], 6)
check("priority", a["priority"], "medium")
check("evidence events", evidence[a["id"]], 6)
check("first seen", a["first_seen"], "2026-11-19T09:15:02+00:00")
check("last seen", a["last_seen"], "2026-11-19T09:15:52+00:00")
check("IP under the threshold: no alert", any(x["ip"] == "192.0.2.20" for x in alerts), False)

print("--- Scenario R2 (HTTP)")
accepted, alerts, evidence = run(R2)
check("lines accepted", accepted, [15])
check("number of alerts", len(alerts), 1)
a = alerts[0]
check("rule", a["rule"], "R2")
check("IP", a["ip"], "192.0.2.30")
check("event count", a["event_count"], 6)
check("priority", a["priority"], "medium")
check("codes in the details", "403 x1, 404 x4, 500 x1" in a["details"], True)
check("IP under the threshold: no alert", any(x["ip"] == "192.0.2.40" for x in alerts), False)

print("--- Scenario R3 (HTTP)")
accepted, alerts, evidence = run(R3)
check("lines accepted", accepted, [94])
check("number of alerts", len(alerts), 1)
a = alerts[0]
check("rule", a["rule"], "R3")
check("IP (global rule)", a["ip"], None)
check("event count", a["event_count"], 45)
check("priority", a["priority"], "medium")

print("--- The three scenarios together")
accepted, alerts, evidence = run(R1, R2, R3)
check("number of alerts", len(alerts), 3)
check("rules", sorted(a["rule"] for a in alerts), ["R1", "R2", "R3"])
check("priorities (no escalation)", sorted(a["priority"] for a in alerts), ["medium"] * 3)

os.remove(DB)