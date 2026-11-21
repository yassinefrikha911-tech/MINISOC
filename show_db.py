from minisoc.db import connect

con = connect()

print("Imports:")
for r in con.execute("SELECT id, file, source, accepted, rejected, result FROM imports ORDER BY id"):
    print(" ", r["id"], r["file"], r["source"], "accepted", r["accepted"],
          "rejected", r["rejected"], "|", r["result"])

print("Events (SSH and HTTP together, in time order):")
for r in con.execute(
    "SELECT timestamp, source, ip, type, severity, status_code FROM events ORDER BY timestamp, id"
):
    print(" ", r["timestamp"], r["source"], r["ip"], r["type"], r["severity"], r["status_code"])

print("Total events:", con.execute("SELECT COUNT(*) FROM events").fetchone()[0])
con.close()