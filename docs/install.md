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

CVE List polls hourly, KEV every six hours, EPSS daily, and the outbox every minute.
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

## File permissions

SQLite, its WAL/shared-memory sidecars, and the notification JSONL use mode 0600.
Existing files are tightened on startup. Use a private data directory (0700) for
local installs and keep backups equally private. The database, watch list, and
notification log contain inventory; do not commit them. Mount secrets and config
read-only, and ensure the container's UID 10001 can read its token as described above.
