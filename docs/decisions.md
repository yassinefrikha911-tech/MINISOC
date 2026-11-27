# Decisions

Date: 18 November 2026

| # | Decision | Choice | Why |
|---|---|---|---|
| 1 | Web or desktop | Local web app (browser) | It runs on my own computer and I open it in my browser at an address like http://127.0.0.1:5000. Tables, filters, and dashboards are easier to build in HTML than in a desktop window. |
| 2 | Language | Python | Because I already know the basics. |
| 2 | Framework | Streamlit | It builds a dashboard in pure Python: tables, filters, file upload and CSV download are built-in widgets, so no HTML or routing is needed. It fits the time limit for a beginner. |
| 2 | Database | SQLite | Because it's a single file, built into Python, and persistent. |
| 2 | SSH year | Given at import, otherwise guessed | SSH lines have no year. The analyst can give one, which keeps demos reproducible. Otherwise the parser uses the current year, or last year if the date would be in the future. |
| 3 | Export | CSV, UTF-8, comma-separated | Because Excel opens accented characters correctly with the utf-8-sig variant. |
| 3 | CSV columns | timestamp_utc, source, ip, type, severity, status_code, summary | These are the main normalized fields an analyst needs. |
| 3 | CSV safety | Prefix risky text cells (= + - @) with a single quote | Usernames and URLs in logs come from outsiders and could contain formulas. |
| 3 | CSV file | UTF-8 with BOM, period in the file name, risky text cells prefixed with a quote | Excel reads accents correctly and the export matches the period shown. |
| 4 | Duplicate imports | Identical file (same SHA-256 and source) is refused with a message | Nothing is overwritten or deleted silently. A modified file counts as a new import, so events present in both versions are stored twice (documented limit). |
| 5 | Re-running the rules | An alert already stored (same rule, IP, first and last time) is not duplicated. Its priority can only go up, and the report says so. Nothing is deleted. | The history is never overwritten silently. Limit: if new events extend a burst, the longer burst is stored as a new alert next to the old one. |
| 6 | Dashboard layout | Streamlit: sidebar filters, three tabs (Alerts, Events, Import), evidence opened with a selector | Simple to build in the time limit. The evidence page of the mockup becomes a section under the alerts table. |
| 6 | Filter rules | Period overlaps for alerts, exact IP, source, priority (alerts only). All counts and CSV exports use the same filters. | An IP filter hides R3 alerts because they have no IP (documented limit). |
## Decided in Week 1
- Event schema, date handling, severity criteria, and missing-data behaviour: see `schema.md`.