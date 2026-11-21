import sys

from minisoc.db import init_db
from minisoc.importer import import_file, format_report

init_db()

if len(sys.argv) >= 3:
    # Usage: python run_import.py ssh data/file.log [year]
    year = int(sys.argv[3]) if len(sys.argv) > 3 else None
    jobs = [(sys.argv[1], sys.argv[2], year)]
else:
    # No arguments: import the two sample files
    jobs = [("ssh", "data/ssh_sample.log", 2026), ("http", "data/http_sample.log", None)]

for source, path, year in jobs:
    try:
        print(format_report(import_file(path, source, year=year)))
    except (FileNotFoundError, ValueError) as error:
        print("Error:", error)
    print()