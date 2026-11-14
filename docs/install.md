# Installing and running Cornicen

← [README](../README.md)

## Compose install

Requires Docker Compose. Copy the examples into private local files:

```sh
mkdir -p config secrets
chmod 700 config secrets
cp compose.example.yml compose.yml
cp examples/cornicen.example.toml config/cornicen.toml
cp examples/watchlist.example.toml config/watchlist.toml
```

Edit the config: replace the fictional ntfy URL and topic with your channel,
using an HTTP(S) `ntfy_url` without userinfo, a query string or a fragment (path prefixes are allowed),
set your repository owner for the default User-Agent, and choose your digest time
and IANA time zone. Edit the watch list for your inventory. Create
`secrets/ntfy_token` with your ntfy token using your editor, and keep it outside
version control. The file must be owned by container UID 10001 and have mode 0600.
For a local Compose bind-mounted secret, set that ownership and mode on the host;
Compose file secrets may not honour `uid`, `gid` or `mode` overrides. For a server
without authentication, remove the Compose `environment` and `secrets` entries.
Secrets may also come from `CORNICEN_NTFY_TOKEN`; never put a token in TOML.
The default rejects any group/world permissions on token files. If your secret
manager requires a shared file, explicitly set `allow_shared_token_file = true`
in config and restrict access to the intended group; this opts out of the mode
check. Keep private config and secrets directories mode 0700 where possible.

```sh
docker compose up --build -d
docker compose exec cornicen python -m cornicen status
docker compose exec cornicen python -m cornicen notify test
```

The image runs as user `cornicen` (UID 10001). Compose gives it a read-only root,
a writable SQLite volume at `/data`, temporary `/tmp`, read-only configuration,
no capabilities, no privilege escalation, and no ports. The watch list is
`/config/watchlist.toml`. The Dockerfile pins `python:3.13-slim` to an immutable
multi-platform index digest verified on 2026-11-03. To bump it, inspect the
official image with `docker buildx imagetools inspect python:3.13-slim`, verify
the index digest against the intended official release, and replace the
Dockerfile's `@sha256:` value. Update the verification date and the expected
digest in `tests/test_fix_b.py`, run `make gate`, then build and smoke-test the
image on the deployment architecture. The gate requires a 64-hex digest;
it does not contact the registry or verify image provenance.

Normal alerts are grouped into one daily digest, most severe first. KEV-listed
items and affected items at or above the EPSS threshold are urgent. The first
bootstrap sends a historical summary; later changes produce alerts.

EPSS crossing settings in the main TOML config:

```toml
epss_threshold = 0.10
epss_rearm_ratio = 0.8
epss_crossing = true
```

A delivered affected pair sends one urgent alert when EPSS reaches the threshold.
It re-arms only after falling strictly below threshold times re-arm ratio
(8% with these defaults). The ratio must be a number strictly between 0 and 1;
`epss_crossing` must be a boolean. Unknown, inactive and accepted pairs, and
pairs already urgent for KEV or SSVC active exploitation, do not send crossings.
Existing high scores initialize silently on upgrade. State survives restarts;
a cleared and re-opened pair starts armed. Disabling crossings also removes
pending crossing reasons; scores still update state while disabled.
Only complete EPSS ingests without errors update crossing state. Partial evidence
cannot fire, re-arm or seed it, including after restart. Changing the threshold
or re-arm ratio silently re-baselines each pair against its last complete score:
at or above the new threshold becomes fired, below the new re-arm line becomes
armed, and in between keeps its state. The next genuine crossing can alert.

CVE List polls hourly, KEV every six hours, and the outbox every minute.
EPSS polls hourly until today's UTC score date is stored, then waits until the
next UTC day. Each poll refetches the validated bulk file.
An older KEV `dateReleased` is a failed fetch: the accepted catalog and cursor
stay unchanged, and KEV health stays or becomes unhealthy, including after restart.
SIGTERM completes the current cycle and exits successfully. One JSON line per
cycle reports source health and counts; it contains no inventory or record text.
Delivery retries after 1, 2, 4, 8, 16, 32, then 60 minutes, capped at one hour.
Container health fails for unhealthy sources or delivery overdue by more than
`overdue_minutes` (60 by default). A quiet outbox is healthy.

For a local dry run set `notifier = "file"`; notifications append as JSONL to
`notification_path` (default `/data/notifications.jsonl`). This file contains alert
data and belongs in private storage. No ntfy requests are made in file mode.

## What the first run costs

The first cycle downloads the full CVE List snapshot (a zip of about 650 MB),
the KEV catalog and the day's EPSS file, then builds the local database. The
snapshot is staged in the `/data` volume, not in `/tmp`, and is deleted once it
has been read. Leave at least 1 GB free in the data volume.

Measured with v0.1.15 on 2026-11-14, on an Apple-silicon desktop with a fast
connection:

| | First cycle | Running |
|---|---|---|
| Time | about 75 seconds | polls on the schedule above |
| CPU | about 1 minute | near idle between cycles |
| Peak memory | about 210 MB | about 150 MB, on a homelab server |
| Data volume | about 750 MB at peak, about 410 MB after | about 490 MB after ten days, on a homelab server |

Slower connections, disks and CPUs take longer. The database grows as new CVEs
are published. `status` shows each source as healthy once it has been fetched.

## GitHub token (optional)

GitHub allows 60 unauthenticated API requests per hour per public IP, shared
with other devices and applications. An optional token raises the primary limit
to 5,000 per hour. On github.com, create a **fine-grained** personal access token,
choose **Public repositories (read-only)**, add **no** permissions, and set an expiry.
Save it with your editor to `secrets/github_token`, outside version control.
Make it readable by container UID 10001 with mode 600, as for the ntfy secret.

Uncomment the GitHub secret entries in `compose.example.yml` (or your copy): the
service mounts `github_token` as a Compose secret and sets
`CORNICEN_GITHUB_TOKEN_FILE: /run/secrets/github_token`. There is no direct token
environment variable, and tokens cannot go in TOML. Restart after adding or
replacing the file. An unreadable, empty, shared or invalid file falls back to
unauthenticated access; `status` shows the problem without its path or contents.

When GitHub rejects an expired or invalid token with HTTP 401, Cornicen logs one
warning, retries once without credentials, and uses unauthenticated access for
the rest of the process. Replace the token file and restart. `cornicen status`
shows authentication state and the last observed rate limit, reset time and
observation time; `status --json` includes the same state in `github`.

With an active token, release listings and direct past-day tag lookups use a
persistent ETag cache. Authorized 304 responses do not consume the primary limit.
Hourly listings mostly still return 200 because new releases shift the pages;
ETags help mainly with restarts, retries within an hour and repeated past-day
lookups. The larger authenticated allowance is the main benefit.
A token does not widen what the listing reads: it stops at the same 1,000 releases as anonymous access.

## Dead-man ping (optional)

Off by default. Configure an outside monitor to expect a ping, then set
`CORNICEN_DEADMAN_URL` or mount a secret file and set
`CORNICEN_DEADMAN_URL_FILE` to its container path. The direct environment value
takes precedence. Use HTTP or HTTPS; other schemes are rejected. Treat the whole
URL as a secret and never put it in TOML. File ownership and mode follow the ntfy
secret rules above; an unreadable or invalid file is a configuration error.
Restart after changing the URL.

The one TOML setting is `deadman_interval_minutes = 5`, a positive integer.
Cornicen sends a GET after printing the heartbeat of a completed cycle, at most
once per interval, using a monotonic clock. A restart sends on the first
completed cycle. Failed requests also consume the interval. Requests use a
10-second socket timeout, no body, no added query, and User-Agent `Cornicen` without a
version. Redirects to another host and HTTPS downgrades are rejected.
The GET runs on a daemon worker so the minute loop and SIGTERM shutdown never
wait for it. At most one request runs at a time. On the next tick, a request
still running after 30 seconds is recorded as failed; another cannot start until
that worker exits. A late success does not erase this failure.

Unhealthy sources do not block pings: routine CVE List and EPSS outages must not
page through this monitor. A due notification that remains unsent after a failed
attempt blocks pings, including during retry backoff. A failed cycle sends no
ping. Choose the monitor's grace period to allow for full cycle and download
times as well as the ping interval.

`status` shows a `deadman` health component after the scheduler collects the first result. Failures use
fixed details and notify only on health transitions, like other components.
The heartbeat's `deadman` value is `off` when disabled, `skipped` while delivery
is failing, otherwise the latest request result (`ok` or `failed`). Before the
first request it is `ok` (no failure observed). Because the request follows the
heartbeat, its result appears on the next heartbeat. It changes no source health or container health: the outside monitor is optional.
Disabling the URL hides stored deadman health in status and heartbeats without
sending a recovery notification. Delivery suppression uses completion time,
after cycle processing and notification flushes.

## File permissions

SQLite, its WAL/shared-memory sidecars, and the notification JSONL use mode 0600.
Existing files are tightened on startup. Use a private data directory (0700) for
local installs and keep backups equally private. The database, watch list, and
notification log contain inventory; do not commit them. Mount secrets and config
read-only, and ensure the container's UID 10001 can read its token as described above.

## Signed webhook channel

ntfy remains the default. Each deployment chooses one channel: `ntfy`, `file`
or `webhook`. For a webhook set these shareable TOML settings:

```toml
notifier = "webhook"
webhook_format = "json"
```

Set `CORNICEN_WEBHOOK_URL` and `CORNICEN_WEBHOOK_SECRET`, or mount files outside
the repository and set `CORNICEN_WEBHOOK_URL_FILE` and
`CORNICEN_WEBHOOK_SECRET_FILE`. Direct environment values take precedence.
Both values are required, secret, and forbidden in TOML. Files follow the
owner-only permission checks and explicit shared-file opt-out described above.
Use a strong random signing secret shared with the receiver. Restart after changes.
The URL must use HTTPS with a host, without userinfo or a fragment; paths and
query strings are allowed. For example, `https://hook.example.invalid/x1`.

Every notification is a JSON POST. No redirects are followed. The socket timeout
is 60 seconds. Any 2xx acknowledges delivery; every other response or exception
keeps the durable outbox pending with its normal retry schedule. Retries get a
fresh timestamp and signature. Delivery is at least once; receivers should
expect duplicates.

`webhook_format` selects the following body (priority is an integer, 3 normal
or 5 urgent; CVE IDs include all digest members):

| Format | Fields | Text budget |
|---|---|---|
| `json` (default) | `title`, `priority`, `body`, `cve_ids` array | body 8,000 UTF-8 bytes |
| `discord` | `content` (title and body), `allowed_mentions: {"parse": []}` | 2,000 UTF-16 units |
| `slack` | `text` (title and body) | 4,000 UTF-8 bytes |
| `matrix` | `msgtype: "m.text"`, `body` (title and body) | body 8,000 UTF-8 bytes plus title |
| `gotify` | `title`, `message`, `priority` | message 8,000 UTF-8 bytes |
| `homeassistant` | flat `title`, `priority`, `body`, `cve_ids` array | body 8,000 UTF-8 bytes |

Slack escapes `&`, `<` and `>` to literal text. Discord escapes Markdown and
disables mentions. Matrix uses only a plain `body` with `m.mentions: {}`;
bridges must preserve that empty object. Gotify explicitly requests
`extras: {"client::display": {"contentType": "text/plain"}}`.
The webhook sends the same rendered notification text ntfy would send, signed
exactly as serialized. Neither channel filters CVE text: a CNA title that quotes
a string identical to one of your credentials is delivered as written. Cornicen
never copies a configured credential into a notification itself.

Each delivery has a 60-second total deadline, including name resolution,
connection, writes and response headers. A slow receiver leaves its alert pending
for retry. Queued requests each receive their own deadline, so a flush of N
requests may take up to N times 60 seconds. Resolver calls that cannot be cancelled
run in daemon workers; at most four workers can remain outstanding, after which
new attempts fail promptly until a slot becomes available.

Titles have a local 256-byte UTF-8 budget. Truncated text ends in the fixed
marker `\n[truncated]`, included in the budget. Slack uses its recommended
4,000-character budget conservatively in bytes, below its 40,000-character
truncation threshold. Matrix's 65,536-byte event limit includes event metadata;
the smaller local body budget leaves room for JSON escaping and event metadata.
Gotify and Home Assistant do not specify a universal message-field limit; their
budgets are local safeguards. Receiver and proxy request limits may be lower.
The plain JSON CVE array stays complete even when text is truncated.
See the service references for [Discord](https://discord.com/developers/docs/resources/webhook#execute-webhook),
[Slack](https://docs.slack.dev/reference/methods/chat.postMessage#truncating-content),
[Matrix](https://spec.matrix.org/latest/client-server-api/#size-limits),
[Gotify](https://gotify.net/api-docs), and
[Home Assistant](https://www.home-assistant.io/docs/automation/trigger/#webhook-trigger).
These formats adapt bodies; they do not provision service authentication or API
routes. Configure the full incoming URL, or a receiver bridge that accepts the
shape and forwards it. Matrix commonly needs a bridge for its authenticated
room-send API. Home Assistant reads the flat object as `trigger.json`.

All formats carry `X-Cornicen-Timestamp` (Unix seconds) and
`X-Cornicen-Signature` (`sha256=` followed by lowercase HMAC-SHA256 hex).
Verify the exact raw request bytes before parsing JSON, using the shared secret
encoded as UTF-8. This standard-library receiver recipe uses a five-minute
window and a constant-time comparison; reject a request when it returns false:

```python
import hashlib
import hmac
import re
import time


def verify_webhook(secret, raw_body, timestamp, signature, *, now=None):
    """Read secret bytes and raw HTTP values; write nothing; return validity.

    No process exit codes: the caller chooses its HTTP rejection response.
    """
    if not isinstance(timestamp, str) or not re.fullmatch(r"[0-9]{1,20}", timestamp):
        return False
    if not isinstance(signature, str) or not re.fullmatch(r"sha256=[0-9a-f]{64}", signature):
        return False
    now = time.time() if now is None else now
    if abs(now - int(timestamp)) > 300:
        return False
    expected = "sha256=" + hmac.new(
        secret, timestamp.encode("ascii") + b"." + raw_body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)
```

Keep receiver clocks synchronized. The window limits replay age; it does not
prevent duplicate delivery within that window. Native service endpoints may
ignore the signature; a receiver you control must verify it to authenticate
Cornicen.

## Email through ntfy

Cornicen has no email notifier or mail credentials. Use your ntfy server's own
`X-Email` forwarding. Configure `smtp-sender-*` and `smtp-sender-verify` on the
server as described in ntfy's [config → E-mail notifications](https://docs.ntfy.sh/config/#e-mail-notifications).
Cornicen does not add an `X-Email` header; arrange forwarding on your ntfy server
or a server-side integration.
