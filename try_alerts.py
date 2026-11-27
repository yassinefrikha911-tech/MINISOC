import os

from minisoc.alerts import detect_and_save, get_evidence, list_alerts
from minisoc.db import connect, init_db
from minisoc.importer import import_file

DB = "test_alerts.db"


def fresh():
    if os.path.exists(DB):
        os.remove(DB)
    init_db(DB)


def check(name, got, expected):
    print("OK   " if got == expected else "WRONG", name, "- expected", expected, "got", got)


def stored():
    con = connect(DB)
    rows = list_alerts(con)
    evidence = {r["rule"]: len(get_evidence(con, r["id"])) for r in rows}
    con.close()
    return rows, evidence


print("--- Demo v1: first run")
fresh()
import_file("data/demo_v1_ssh.log", "ssh", year=2026, db_path=DB)
import_file("data/demo_v1_http.log", "http", db_path=DB)
r = detect_and_save(DB)
check("alerts found", r["found"], 2)
check("new alerts", r["new"], 2)

print("--- Same rules run again")
r = detect_and_save(DB)
check("new alerts", r["new"], 0)
check("unchanged alerts", r["unchanged"], 2)
rows, evidence = stored()
check("alerts in the database", len(rows), 2)
check("evidence links R1 and R2", (evidence["R1"], evidence["R2"]), (8, 8))

print("--- Persistence: reopen the file")
check("alerts after reopening", len(stored()[0]), 2)

print("--- Priority upgrade")
fresh()
import_file("data/demo_v1_ssh.log", "ssh", year=2026, db_path=DB)
r = detect_and_save(DB)
check("SSH only: found, new", (r["found"], r["new"]), (1, 1))
check("priority with one rule", stored()[0][0]["priority"], "medium")
import_file("data/demo_v1_http.log", "http", db_path=DB)
r = detect_and_save(DB)
check("after HTTP import: new, upgraded", (r["new"], r["upgraded"]), (1, 1))
check("priorities now", sorted(a["priority"] for a in stored()[0]), ["high", "high"])

os.remove(DB)