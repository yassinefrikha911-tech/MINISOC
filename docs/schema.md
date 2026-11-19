# Event schema (v1)

## Event fields
| Field | Type | Notes |
|---|---|---|
| id | integer | auto-generated |
| timestamp | text | UTC, ISO 8601 (2026-11-16T10:15:32+00:00) |
| source | text | `ssh` or `http` |
| file | text | name of the imported file |
| ip | text, nullable | empty if the line has no IP |
| type | text | controlled list below |
| severity | text | `info`, `low`, `medium`, `high`, `unknown` |
| status_code | integer, nullable | HTTP only |
| summary | text | short human-readable description |
| raw | text | original log line, kept for evidence |

## Allowed types
- ssh_auth_failure, ssh_auth_success, ssh_invalid_user, http_request

## Date rules
- Stored in UTC. The interface shows the timezone.
- SSH lines have no year: assume 2026 and UTC. Documented limit.
- HTTP lines include an offset: convert it to UTC.

## Severity rules (event level, written criteria)
- ssh_auth_success: info
- ssh_auth_failure, ssh_invalid_user: low
- http_request 2xx or 3xx: info
- http_request 4xx: low
- http_request 5xx: medium
- anything else: unknown

## Alert priority (alert level)
- low: isolated signal
- medium: a rule threshold is reached
- high: several criteria, or a clearly exceeded threshold

## Missing or invalid data
- No IP: keep the event, ip = empty.
- Timestamp unreadable: reject the line, count it as rejected with the reason.
- Invalid IP format: reject the line with the reason.
- A rejected line never stops the rest of the import.