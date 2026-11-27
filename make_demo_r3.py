"""Create data/demo_r3_http.log: a request spike and a busy-but-normal minute."""
from datetime import datetime, timedelta

BASE = datetime(2026, 11, 18, 14, 0, 0)
IPS = [f"198.51.100.{n}" for n in range(10, 15)]
PAGES = ["/index.html", "/about.html", "/products.html", "/contact.html"]

# (minute after 14:00, number of requests)
# Quiet minutes: 3 requests. Minute 5: busy but under the threshold (25).
# Minute 8: the spike (45), mostly from one IP.
MINUTES = [(0, 3), (1, 3), (2, 3), (3, 3), (4, 3), (5, 25), (6, 3), (7, 3), (8, 45), (9, 3)]

lines = []
k = 0
for minute, count in MINUTES:
    for i in range(count):
        when = BASE + timedelta(minutes=minute, seconds=i * 60 // count)
        ip = IPS[0] if (minute == 8 and i % 3 != 2) else IPS[k % len(IPS)]
        page = PAGES[k % len(PAGES)]
        stamp = when.strftime("%d/%b/%Y:%H:%M:%S +0000")
        lines.append(f'{ip} - - [{stamp}] "GET {page} HTTP/1.1" 200 1024 "-" "Mozilla/5.0"')
        k += 1

with open("data/demo_r3_http.log", "w", encoding="utf-8") as f:
    f.write("\n".join(lines) + "\n")
print(len(lines), "lines written")