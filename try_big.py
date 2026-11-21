from collections import Counter
from minisoc.parsers import parse_http_line, ParseError

accepted = 0
reasons = Counter()
with open("data/apache_logs.log", encoding="utf-8", errors="replace") as f:
    for line in f:
        try:
            parse_http_line(line, "apache_logs.log")
            accepted += 1
        except ParseError as error:
            reasons[str(error)] += 1

print("accepted:", accepted)
print("rejected:", sum(reasons.values()))
for reason, count in reasons.most_common():
    print(" ", count, reason)