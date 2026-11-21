# Demo set v1

Synthetic logs for the lab. IPs come from reserved example ranges. SSH is imported with year 2026.

| File | Lines | Content |
|---|---|---|
| data/demo_v1_ssh.log | 14 | normal logins (alice, bob), 2 isolated failures, 1 burst from 203.0.113.50 (7 failures + 1 invalid user in 21 seconds) |
| data/demo_v1_http.log | 15 | normal page views, 1 isolated 404, 1 burst of 8 error responses (403/404/500) from 203.0.113.50 in 14 seconds |

## Expected import results
- SSH: 14 accepted, 0 rejected. HTTP: 15 accepted, 0 rejected. Total: 29 events.

## Planned for the rules (Week 3, thresholds to calibrate)
- R1: the SSH burst should trigger; the isolated failures (alice, bob) should not.
- R2: the HTTP error burst should trigger; the single 404 should not.
- R3: no volume spike yet. It is added in the Week 4 scenarios.