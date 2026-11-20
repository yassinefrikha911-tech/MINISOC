from datetime import datetime, timezone

from minisoc.parsers import parse_ssh_line, ParseError

with open("data/ssh_sample.log", encoding="utf-8") as f:
    lines = f.read().splitlines()

# Extra lines: 1 good and 3 deliberately bad
lines.append("Nov 16 10:21:02 server sshd[1305]: Invalid user test from 203.0.113.5 port 52200")
lines.append("this is not a log line")
lines.append("Nov 99 10:15:32 server sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2")
lines.append("Nov 16 10:15:32 server sshd[1]: Failed password for root from 999.1.1.1 port 22 ssh2")


def run(title, **options):
    print("---", title)
    for number, line in enumerate(lines, start=1):
        try:
            event = parse_ssh_line(line, "ssh_sample.log", **options)
            print(number, "OK", event["timestamp"], event["ip"], event["type"])
        except ParseError as error:
            print(number, "REJECTED:", error)


run("1. Year guessed (today's date)")
run("2. Year given: 2025", year=2025)
run("3. Guessed, pretending today is 10 Jan 2027", now=datetime(2027, 1, 10, tzinfo=timezone.utc))