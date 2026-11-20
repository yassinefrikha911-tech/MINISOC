# Log parsers: SSH and HTTP
import ipaddress
import re
from datetime import datetime, timedelta, timezone


class ParseError(ValueError):
    """Raised when a line cannot be turned into an event."""


# Shape of a whole SSH line: date, time, host, sshd[pid]: message
SSH_LINE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+(?P<message>.*)$"
)

# The three kinds of message we support
FAILED = re.compile(
    r"^Failed password for (?P<invalid>invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\S+) port \d+"
)
ACCEPTED = re.compile(r"^Accepted \S+ for (?P<user>\S+) from (?P<ip>\S+) port \d+")
INVALID = re.compile(r"^Invalid user (?P<user>\S+) from (?P<ip>\S+)")


def parse_ssh_line(line, filename, year=None, now=None):
    """Turn one SSH log line into an event dictionary, or raise ParseError.

    year: the year of the log. If None, it is guessed (see below).
    now:  the current date, only given in tests. Default: the real date.
    """
    line = line.strip()

    match = SSH_LINE.match(line)
    if not match:
        raise ParseError("line not recognized as a supported SSH line")

    # Year: given by the analyst, otherwise guessed from the current date
    now = now or datetime.now(timezone.utc)
    guessing = year is None
    if guessing:
        year = now.year

    # Date: the line has no year, so we add one and assume UTC
    text = f"{year} {match['month']} {match['day']} {match['time']}"
    try:
        moment = datetime.strptime(text, "%Y %b %d %H:%M:%S")
    except ValueError:
        raise ParseError("unreadable timestamp")
    moment = moment.replace(tzinfo=timezone.utc)

    # A guessed date more than one day in the future belongs to last year
    if guessing and moment > now + timedelta(days=1):
        try:
            moment = moment.replace(year=year - 1)
        except ValueError:
            raise ParseError("unreadable timestamp")
    timestamp = moment.isoformat()

    # Message: decide the type and severity (rules from schema.md)
    message = match["message"]
    if m := FAILED.match(message):
        kind, severity = "ssh_auth_failure", "low"
        who = ("invalid user " if m["invalid"] else "") + m["user"]
        summary = f"Failed password for {who}"
    elif m := ACCEPTED.match(message):
        kind, severity = "ssh_auth_success", "info"
        summary = f"Accepted login for {m['user']}"
    elif m := INVALID.match(message):
        kind, severity = "ssh_invalid_user", "low"
        summary = f"Invalid user {m['user']}"
    else:
        raise ParseError("SSH message type not supported")

    # IP: must be a valid address
    try:
        ip = str(ipaddress.ip_address(m["ip"]))
    except ValueError:
        raise ParseError("invalid IP address")

    return {
        "timestamp": timestamp,
        "source": "ssh",
        "file": filename,
        "ip": ip,
        "type": kind,
        "severity": severity,
        "status_code": None,
        "summary": summary,
        "raw": line,
    }

# Shape of a whole HTTP line (Apache/Nginx Combined Log Format)
HTTP_LINE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
)


def parse_http_line(line, filename):
    """Turn one HTTP access-log line into an event dictionary, or raise ParseError."""
    line = line.strip()

    match = HTTP_LINE.match(line)
    if not match:
        raise ParseError("line not recognized as a supported HTTP line")

    # Date: the line has an offset (+0100, +0000...), convert it to UTC
    try:
        moment = datetime.strptime(match["time"], "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        raise ParseError("unreadable timestamp")
    timestamp = moment.astimezone(timezone.utc).isoformat()

    # IP: must be a valid address
    try:
        ip = str(ipaddress.ip_address(match["ip"]))
    except ValueError:
        raise ParseError("invalid IP address")

    # Severity from the status code (rules from schema.md)
    status = int(match["status"])
    if 200 <= status < 400:
        severity = "info"
    elif 400 <= status < 500:
        severity = "low"
    elif 500 <= status < 600:
        severity = "medium"
    else:
        severity = "unknown"

    return {
        "timestamp": timestamp,
        "source": "http",
        "file": filename,
        "ip": ip,
        "type": "http_request",
        "severity": severity,
        "status_code": status,
        "summary": f"{match['method']} {match['path']} returned {status}",
        "raw": line,
    }