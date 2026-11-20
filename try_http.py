from minisoc.parsers import parse_http_line, ParseError

with open("data/http_sample.log", encoding="utf-8") as f:
    lines = f.read().splitlines()

# Extra lines: 2 good and 3 deliberately bad
lines.append('198.51.100.7 - - [16/Nov/2026:11:15:32 +0100] "GET /a HTTP/1.1" 200 10 "-" "x"')
lines.append('198.51.100.7 - - [16/Nov/2026:10:17:00 +0000] "GET /b HTTP/1.1" 503 10 "-" "x"')
lines.append("this is not a log line")
lines.append('203.0.113.5 - - [32/Nov/2026:10:15:32 +0000] "GET / HTTP/1.1" 200 10 "-" "x"')
lines.append('999.1.1.1 - - [16/Nov/2026:10:15:32 +0000] "GET / HTTP/1.1" 200 10 "-" "x"')

for number, line in enumerate(lines, start=1):
    try:
        event = parse_http_line(line, "http_sample.log")
        print(number, "OK", event["timestamp"], event["ip"], event["status_code"], event["severity"])
    except ParseError as error:
        print(number, "REJECTED:", error)