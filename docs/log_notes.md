# Log notes

## SSH log

Example line:
`Nov 16 10:15:32 server sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 52144 ssh2`

- `Nov 16 10:15:32`: date and time. There is no year, so I will assume 2026 and UTC.
- `server`: name of the machine.
- `sshd[1234]`: program that wrote the line, and its process number.
- `Failed password for invalid user admin`: the event, a failed login.
- `203.0.113.5`: IP address of the computer that tried to log in.
- `port 52144`: technical detail, ignored.

Event types in my sample: `Failed password` (failure) and `Accepted password` (success).

## HTTP log

Example line:
`203.0.113.5 - - [16/Nov/2026:10:15:32 +0000] "GET /login HTTP/1.1" 404 512 "-" "Mozilla/5.0"`

- `203.0.113.5`: IP address of the visitor.
- `- -`: unused fields.
- `[16/Nov/2026:10:15:32 +0000]`: date and time. `+0000` means UTC.
- `"GET /login HTTP/1.1"`: the request, meaning the visitor asked for the page /login.
- `404`: status code. 2xx = OK, 4xx = visitor error, 5xx = server error.
- `512`: size of the response.
- `"Mozilla/5.0"`: the browser used.

## Common points

Both logs contain a time, an IP address, and an event. Normalization means converting both into one shared format.