from minisoc.db import connect, init_db, DB_PATH

init_db()

con = connect()
print("Database file:", DB_PATH.resolve())
# Table names come from SQLite itself, not from outside, so this is safe
for row in con.execute(
    "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
):
    count = con.execute(f"SELECT COUNT(*) FROM {row['name']}").fetchone()[0]
    print(" table", row["name"], "-", count, "rows")
con.close()