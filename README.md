# MiniSOC

Defensive log monitoring lab project. It imports SSH and HTTP logs, normalizes them into events, stores them in SQLite, and (from Week 3) applies correlation rules and shows alerts in a dashboard.

Lab use only: synthetic data, no intrusive agent, no remote access, no automatic response.

## Status
- Week 1 (planning): done. See `docs/`.
- Week 2 (ingestion and SQLite): done. Parsers, importer with import report, database.
- Week 3 (rules and dashboard): to do.

## Prerequisites
- Python 3.11 or higher
- Git

## Installation (Windows PowerShell)
```
git clone https://github.com/yassinefrikha911-tech/MINISOC.git
cd MINISOC
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```
On Linux: use `python3 -m venv .venv`, then `source .venv/bin/activate`.

## Run the demo
```
python init_db.py
python run_import.py ssh data/demo_v1_ssh.log 2026
python run_import.py http data/demo_v1_http.log
python show_db.py
```
Expected: 14 and 15 accepted lines, then 29 events listed (SSH and HTTP together, in time order).

## How importing works
- `python run_import.py <ssh|http> <file> [year]`
- SSH lines have no year: give it as the last argument, otherwise the current year is used (or last year if that date would be in the future). The year used is saved with the import.
- A bad line is rejected with a reason and never stops the import. The report shows accepted and rejected counts.
- Importing an identical file again is refused with a message. Nothing is overwritten.

## Project layout
- `minisoc/parsers.py`: SSH and HTTP parsers
- `minisoc/db.py`: SQLite schema
- `minisoc/importer.py`: import and report
- `data/`: sample and demo logs (synthetic)
- `docs/`: schema, decisions, sources, notes, mockup, demo description

## Limits
Synthetic data only. Dates are stored in UTC. SSH logs spanning New Year are not handled. Severity and priority rules are written in `docs/schema.md`. An alert is a lead for investigation, not proof of an attack.

## Author
Yessin Frikha