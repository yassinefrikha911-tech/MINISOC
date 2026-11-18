# Decisions 

Date: 18 November 2026

| # | Decision | Choice | Why |
|---|---|---|---|


| 1 | Web or desktop | Local web app (browser) |It runs on my own computer, and you open it in your browser at an address like http://127.0.0.1:5000. Tables, filters, and dashboards are easier to build in HTML than in a desktop window. |


| 2 | Language | Python |because i already know the basics  |


| 2 | Framework | Flask |because it 's a small Python framework that serves web pages |
| 2 | Database | SQLite |for the database because i already read about it  |
| 3 | Export | CSV, UTF-8, comma-separated |  because Excel opens accented characters correctly with the utf-8-sig variant.|
| 3 | CSV columns | timestamp_utc, source, ip, type, severity, status_code, summary | |
| 3 | CSV safety | Prefix risky text cells (= + - @) with a single quote | |

## Still to decide 
- Exact event schema, date handling, and severity criteria
- Behaviour when a field is missing