# Sources consulted

| Topic | Link | Date consulted | What I learned |
|---|---|---|---|


| HTTP log format | https://httpd.apache.org/docs/2.4/logs.html | 18/11/2026|Each part in a log entry represents somthing like : the IP address of the client,the availability of the requested piece of information ,the userid of the person requesting , The time that the request was received and its format , the request itself,the status code such as a successful request ( beginning with 2xx  or a  redirected page beginning with 3xx or a failed one beginning with  or 4xx or 5xx ),the size of the object returned to the client ,which page was the visitor on before they came here and finally what software is the visitor using|


| Date parsing | https://docs.python.org/3/library/datetime.html | 18/11/2026 | python can read date and time using the pre built in tool kit "import datetime ad dt" using "strptime" to parse (turn text into datetime) , (strftime)to do the reverse and "isoformat()"  for the standard ISO 8601 text. The problem is that  parsing a day of the month without a year raises an error in modern python and SSH lines have no year so to solev that we will add one ourselves before parsing . Python also raises an error when comparing or subtracting one aware and one naive datetime (a naive date time doesnt represent  a timezone on the contrary to the aware one )  thus we make every timestamp aware in UTC|


| Common schema | https://www.elastic.co/guide/en/ecs/current/index.html | 18/11/2026 |ECS defines a shared set of field names and data types for event data such as logs SO The final goal is that events from different sources look alike and that is normalization |


| SQLite | https://docs.python.org/3/library/sqlite3.html | 18/11/2026 | SQLite is a small database that lives in one file on your computer, with no server to install. Python includes it, so you only need "import sqlite3". WE SHOULD BE AWARE of SQL injections which is a vulnerability and to protect against it we put ? placeholders in the query and pass the values separately.(never build sql queries by pasting python values into a string)|


| CSV injection | https://owasp.org/www-community/attacks/CSV_Injection | 18/11/2026 |A CSV injection is an attack that happens when an application puts untrusted input into a CSV file and to prevent it The idea is simple: put a ' in front of any risky cell before it goes into the CSV.Why it works. A spreadsheet looks at the first character of a cell. If it’s =, it thinks “this is a formula, calculate it.” If the first character is a ', it thinks “this is plain text, just display it.” |