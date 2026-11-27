import csv
import io
import os
from datetime import date

from minisoc.alerts import detect_and_save
from minisoc.db import connect, init_db
from minisoc.importer import import_file
from minisoc.queries import (ALERT_COLUMNS, EVENT_COLUMNS, EVENT_HEADERS,
                             filter_alerts, filter_events, to_csv)

DB = "test_queries.db"
if os.path.exists(DB):
    os.remove(DB)
init_db(DB)
import_file("data/demo_v1_ssh.log", "ssh", year=2026, db_path=DB)
import_file("data/demo_v1_http.log", "http", db_path=DB)
import_file("data/demo_r3_http.log", "http", db_path=DB)
detect_and_save(DB)
con = connect(DB)

D16, D17, D18 = date(2026, 11, 16), date(2026, 11, 17), date(2026, 11, 18)


def check(name, got, expected):
    print("OK   " if got == expected else "WRONG", name, "- expected", expected, "got", got)


print("--- Event filters")
check("both days", len(filter_events(con, D17, D18)), 123)
check("17 Nov only", len(filter_events(con, D17, D17)), 29)
check("18 Nov only", len(filter_events(con, D18, D18)), 94)
check("16 Nov (no data)", len(filter_events(con, D16, D16)), 0)
check("one IP", len(filter_events(con, D17, D18, ip="203.0.113.50")), 16)
check("SSH only", len(filter_events(con, D17, D18, sources=["ssh"])), 14)
check("one IP and HTTP only",
      len(filter_events(con, D17, D18, ip="203.0.113.50", sources=["http"])), 8)
check("18 Nov and SSH only", len(filter_events(con, D18, D18, sources=["ssh"])), 0)
check("no source selected", len(filter_events(con, D17, D18, sources=[])), 0)

print("--- Alert filters")
check("all alerts", len(filter_alerts(con, D17, D18)), 3)
check("priority high", len(filter_alerts(con, D17, D18, priorities=["high"])), 2)
check("priority medium", len(filter_alerts(con, D17, D18, priorities=["medium"])), 1)
check("one IP", len(filter_alerts(con, D17, D18, ip="203.0.113.50")), 2)
check("SSH only", len(filter_alerts(con, D17, D18, sources=["ssh"])), 1)
check("17 Nov only", len(filter_alerts(con, D17, D17)), 2)
check("18 Nov only", len(filter_alerts(con, D18, D18)), 1)
check("no priority selected", len(filter_alerts(con, D17, D18, priorities=[])), 0)

print("--- CSV")
rows = filter_events(con, D17, D17)
parsed = list(csv.reader(io.StringIO(to_csv(rows, EVENT_COLUMNS, EVENT_HEADERS))))
check("rows = filtered events + header", len(parsed), 30)
check("first header", parsed[0][0], "timestamp_utc")
fake = [{"timestamp": "t", "source": "ssh", "ip": None, "type": "x", "severity": "low",
         "status_code": None, "summary": s} for s in ("=1+2", "-5", "@x", 'plain, with "quotes"')]
cells = [r[6] for r in list(csv.reader(io.StringIO(to_csv(fake, EVENT_COLUMNS, EVENT_HEADERS))))[1:]]
check("risky cells get a quote in front", cells[:3], ["'=1+2", "'-5", "'@x"])
check("commas and quotes survive", cells[3], 'plain, with "quotes"')
r1 = filter_alerts(con, D17, D18, sources=["ssh"])[0]
check("alert R1 has 8 evidence ids", len(r1["evidence_ids"].split(",")), 8)

con.close()
os.remove(DB)