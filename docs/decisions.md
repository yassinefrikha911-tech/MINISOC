# Decisions

Date: 18 November 2026

| # | Decision | Choice | Why |
|---|---|---|---|
| 1 | Web or desktop | Local web app (browser) | It runs on my own computer and I open it in my browser at an address like http://127.0.0.1:5000. Tables, filters, and dashboards are easier to build in HTML than in a desktop window. |
| 2 | Language | Python | Because I already know the basics. |
| 2 | Framework | Flask | Because it's a small Python framework that serves web pages. |
| 2 | Database | SQLite | Because it's a single file, built into Python, and persistent. |
| 3 | Export | CSV, UTF-8, comma-separated | Because Excel opens accented characters correctly with the utf-8-sig variant. |
| 3 | CSV columns | timestamp_utc, source, ip, type, severity, status_code, summary | These are the main normalized fields an analyst needs. |
| 3 | CSV safety | Prefix risky text cells (= + - @) with a single quote | Usernames and URLs in logs come from outsiders and could contain formulas. |

## Decided in Week 1
- Event schema, date handling, severity criteria, and missing-data behaviour: see `schema.md`.