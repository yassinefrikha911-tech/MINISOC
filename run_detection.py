from minisoc.alerts import detect_and_save
from minisoc.db import init_db

init_db()
r = detect_and_save()
print("Events analysed:", r["events"])
print(f"Alerts found: {r['found']}   new: {r['new']}   "
      f"unchanged: {r['unchanged']}   upgraded: {r['upgraded']}")