import sys

from minisoc.alerts import get_evidence, list_alerts
from minisoc.db import connect

con = connect()
alerts = list_alerts(con)

if len(sys.argv) > 1:
    # python show_alerts.py 1  ->  one alert with its evidence
    wanted = int(sys.argv[1])
    for a in alerts:
        if a["id"] == wanted:
            print(f"Alert {a['id']}: {a['rule']} - {a['title']} (priority {a['priority']})")
            print(" ", a["details"])
            print(f"  Window {a['window_minutes']} min, threshold {a['threshold']}, "
                  f"count {a['event_count']}, {a['first_seen']} -> {a['last_seen']}")
            print("  Evidence:")
            for e in get_evidence(con, wanted):
                print("   ", e["id"], e["timestamp"], e["source"], e["ip"],
                      e["status_code"], e["summary"])
            break
    else:
        print("No alert with id", wanted)
else:
    print("Alerts in the database:", len(alerts))
    for a in alerts:
        print(f"  {a['id']} {a['rule']} {a['priority']} {a['ip'] or '-'} "
              f"{a['event_count']}/{a['threshold']} {a['first_seen']} -> {a['last_seen']}")
con.close()