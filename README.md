# Cornicen

Cornicen is a self-hosted CVE alerting tool for homelabs and small networks. One container watches public vulnerability data, matches it locally against a private list of the products and versions you run, and pushes an alert when something you run is affected. It stays silent when nothing is, and it says so loudly when it has gone blind.

## How it's built to behave

These are the design goals for this v0.1 tool:

1. **Catch what hits your gear.** The matching and event rules aim to enqueue exactly one notification within one poll cycle of *successfully ingesting* each new match, KEV addition or correction on a watched item. Urgent events go at once; normal ones go in the next digest.
2. **Make delivery durable and at-least-once.** The outbox is designed to preserve notifications across crashes and outages and retry until accepted. A lost acknowledgement can cause a duplicate; retries are intended to prevent loss.
3. **Stay quiet otherwise.** Matching and deduplication are designed to suppress notifications for products you don't run, versions a record authoritatively excludes, and edits that don't change applicability or a defined event.
4. **Report blindness.** Health checks are designed to report sources that cannot be fetched, return incomplete data, or stop advancing as unhealthy, rather than as "no new CVEs."
5. **Show what is known and unknown.** Alerts are designed to state their evidence and show unknowns explicitly ("not in KEV" means not listed, not "not exploited").
6. **Be usable by strangers.** The project aims to need no account or key for any v1 source and provides a fictional example watch list and one documented install.

### What it cannot promise

Cornicen only knows what the CVE List, KEV and EPSS publish. CNA data is
inconsistent, and matching can miss vulnerabilities or over-report them. Treat
it as an early-warning aid, not an audit.

For the ingestion, matching and delivery design, see [docs/spec.md](docs/spec.md).

## Install with Compose

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

## Write and tune a watch list

Each `[[watch]]` needs a stable `id`, display `name`, vendor-scoped `match`
identities, `version`, and comparison `scheme`. Changing a name keeps its identity;
changing a version re-matches stored records. Use `semver`, numeric `dotted`,
`debian`, CPython `python`, or equality-only `opaque`. Comparator ranges such as
`">=1.0.0, <2.0.0"` are supported. Declare `eol = true` for unsupported versions.

`product_only` is an explicit loose match across vendors and caps applicability at
unknown. Prefer scoped identities. Normalisation trims and collapses whitespace
and ignores case while keeping punctuation. Placeholder products never match;
a placeholder vendor can match a real product only through `product_only`.
For CPython use `python`, which orders three numeric components and optional
`aN`, `bN` or `rcN` pre-releases. Other PEP 440 forms remain unknown.
Synology DSM build/update strings can use `debian`;
wildcards, `unspecified` bounds and prose remain unknown.
When a version is outside every affected range a CNA entry lists and all
comparisons are decidable, `defaultStatus: affected` yields **unknown**, with
evidence “outside every range the CNA listed; the CNA's default says affected”.
This rule applies equally before, between and after the listed ranges.
Explicit status rows and covering ranges take precedence. An entry with no
affected ranges retains its existing default behavior. Range watches evaluate
all allowed versions: any affected cell yields **affected**, and every cell must
be excluded to return **not affected**. Starts of `0`, `0.0`, `0.0.0` or `*` in
explicit ranges mean unbounded below and never enter version ranking or lookup.
Across matching entries, an affected result wins. An unknown result wins over
an exclusion inferred only from another entry's history.
History inference requires an omitted/unknown default, decidable rows and
transitions, no covering row, and affected history starting at zero or `*`
(or an upper-bounded comparator unbounded below). Explicit unaffected rows and
unaffected defaults retain their precedence. Undecidable comparisons stay unknown.
The versioned built-in alias map accounts for spelling variants; extend it with
a local `aliases_path` containing `version` and `[[alias]]` groups of `identities`.

Validate before starting (no database is needed), then inspect the stored CVEs
after bootstrap before trusting your identities:

```sh
docker compose run --rm cornicen python -m cornicen watch check
```

```sh
docker compose exec cornicen python -m cornicen watch check --days 90
docker compose exec cornicen python -m cornicen report
```

`watch check` validates the whole file, reports collisions including aliases,
and prints matched and near-miss CVEs per watch. Matches are affected or unknown
with exploitation evidence. Near misses include excluded or unknown versions
and shared vendor or product names. The window uses the CVE publication time,
falling back to local ingestion time. It performs no fetches; an empty database
cannot establish coverage and reports "no records ingested yet". Use near misses
to discover a CNA's vendor and product spelling, then add that scoped identity
to `match` or a local alias group. For example, F5 publishes nginx as
`F5:NGINX Open Source`; the built-in aliases connect it to `nginx:nginx` and
`f5:nginx`, while keeping `F5:NGINX Plus` separate. The example inventory uses
real CNA identities for nginx, OpenWrt, nginx-ui and Jellyfin. Review near
misses after tuning to check coverage.
Collisions are reported without rejecting an otherwise valid list by default.

The running scheduler reloads on file modification. Startup also compares the
file with the last applied watch list stored in SQLite and re-matches changes
before sending any queued notifications. A rejected reload keeps the
previous list and marks `watchlist` unhealthy until a valid reload. Mounting a
directory read-only at `/config` instead of individual files can help editors
that replace files atomically make changes visible in an existing container.

`report` prints a one-line count summary, then JSON-lines items under these headings:

- **Baseline: affected** — affected pairs recorded during baseline.
- **Baseline: exploited (unknown version)** — baseline pairs with unknown applicability and known exploitation.
- **Open matches** — affected or exploited unknown-version pairs outside baseline.
- **Not affected (recorded, no alert)** — pairs recorded as not affected, including baseline pairs.
- **Dead letters** — records that exhausted retries.

Pair items include their alias map version. Groups do not overlap; unknown pairs
without known exploitation are omitted.
`status` reports source health, a sanitised last source error, and reconciliation. `healthcheck` exits 0 when
healthy and 1 otherwise, including when the database is unavailable.
Run locally on Python 3.11+ with `PYTHONPATH=src python3 -m cornicen --config
/path/to/cornicen.toml status`. Runtime dependencies are standard library only.

### Local CLI diagnostics

Use the same `--config PATH` option as `status`. These commands perform no
fetches or deliveries and never migrate databases. Database commands open the
source read-only; backups write only a new destination. Version comparison works
without configuration or a database.

```sh
cornicen db backup --output /backups/cornicen.db
cornicen report --watch proxy --group open --format jsonl
cornicen version compare 3.14.0rc1 3.14.0 --scheme python
cornicen explain CVE-2026-4321 --watch proxy
cornicen outbox list
cornicen outbox list --failed
cornicen status --json
cornicen watch check --file /config/draft.toml --strict --days 90
```

- `db backup --output PATH`: copy the existing database through SQLite's backup
  API, including committed WAL data, into a private mode-0600 staging file beside
  PATH. Check the copy with `PRAGMA quick_check`, then publish without overwriting
  any destination (including the source). Failure exits 1 and removes only this
  invocation's staging file. The backup contains SQLite state only; back up the
  watch list, configuration and alias files separately. Backups contain private
  inventory and should stay local.
- `report [--watch WATCH_ID ...] [--group GROUP ...] [--format {text,jsonl}]`:
  intersect the selected watches and groups. Repeat either filter to select
  multiple values. Groups are `baseline-affected`, `baseline-exploited`, `open`,
  `not-affected` and `dead-letters`, in that order. Watch filters exclude dead
  letters because those rows have no watch ID. Text (the default) keeps the
  existing headings and reports filtered counts. JSONL emits only row objects,
  adding `schema_version: 1` and `group` to the existing fields, ordered within
  each group by watch/CVE (or source/CVE for dead letters). Empty JSONL is empty
  output. Exports contain private inventory and should stay local.
- `version compare LEFT RIGHT --scheme {semver,dotted,debian,python,opaque}`:
  print exactly `less`, `equal`, `greater` or `unknown`. Decidable results exit 0;
  unknown exits 1; argument errors exit 2. This command loads no configuration
  and opens no database. Opaque equality normalizes case and whitespace like
  applicability evaluation. This compares literal versions, not CNA range
  coverage, support status or whether an upgrade fixes a CVE.

Alerts append `CVE title` (one line, at most 160 characters) and `CNA CVSS score`.
The score is the highest numeric retained CNA base score used for digest ordering;
ADP scores are excluded. Missing title/score values, including old queued bodies,
show `unknown`; a valid score of 0.0 remains visible. Existing fields retain their
order, and EOL remains the leading warning. Urgency and digest ordering do not change.

- `explain CVE_ID --watch WATCH_ID` shows the current watch version/scheme,
  applicability, exploitation, evidence, confidence and alias-map version.
  Stored pair state is labeled separately because an edited watch file may
  differ from the scheduler's last applied state. Identity misses exit 0;
  unknown watches and unavailable retained records exit 1. Missing data is
  unknown, never a safe result.
- `outbox list [--failed]` prints pending rows as JSON lines followed by
  `Pending rows: N`. Rows include ID, watch/CVE or operational component,
  urgency, reasons, enqueue/due times, attempts, retry time and `eligible_at`
  (`max(due_at, next_attempt_at or due_at)`), ordered by eligibility then ID.
  `--failed` selects attempts greater than zero. Dirty rows say `awaiting
  revalidation`; displayed scheduling may change after revalidation. Health
  and baseline rows remain visible. An empty queue exits 0; unavailable DBs exit 1.
- `status --json` emits one object with exactly `schema_version` (1),
  `available`, `container_healthy`, `sources`, `baseline_complete` and
  `reconcile_at`. Each source has `state`, sanitized `detail`, `cursor` and
  `content_time`. Flags are booleans; absent cursor/time/reconciliation values
  are null. An unavailable database emits false availability/health, empty
  sources, false baseline completion and null reconciliation, then exits 1.
  Available status exits 0 even when unhealthy; use `container_healthy` for
  monitoring. Plain `status` and `healthcheck` keep their existing behavior.
- `watch check [--file PATH] [--strict]` validates the candidate file only for
  this invocation. It works without a database. Explicit `--file` or `--strict`
  preflight prints detailed local validation errors; plain `watch check` keeps
  its sanitized validation errors. `--strict` exits 1 for identity collisions or alias-map
  warnings; default warnings exit 0. Invalid files exit 1 in either mode.
  Neither mode rewrites the active file or persists validation problems.

Stored CVEs use the [projection documented in the spec](docs/spec.md#66-stored-cve-projection):
metadata, affected products/versions, title, CNA short name and CNA/ADP CVSS.
Descriptions, references and other unused material are discarded. Startup
migrates existing records in resumable batches of 128; freed SQLite pages are
reused without automatically shrinking the existing file. Matching, diagnostics
and notifications use the retained fields.

## File permissions

SQLite, its WAL/shared-memory sidecars, and the notification JSONL use mode 0600.
Existing files are tightened on startup. Use a private data directory (0700) for
local installs and keep backups equally private. The database, watch list, and
notification log contain inventory; do not commit them. Mount secrets and config
read-only, and ensure the container's UID 10001 can read its token as described above.

## What it cannot see

- **Plex:** no machine-readable advisory feed found (its security web pages could not be inspected). Covered by CVE records; a latest-version check is planned for v1.1.
- **Apple:** no official machine-readable feed. A community feed exists; not planned.
- **Raspberry Pi OS:** Debian data (v1.1) covers its Debian base only, not Raspberry Pi-specific packages or firmware.
- **Anything without a CVE record or vendor advisory** (a blog post, a GitHub issue).

Cornicen never probes your systems or scans container images. It knows only the
products and versions you declare, and depends on the completeness of CNA data.

Vendor advisory adapters, NVD enrichment, release checks, and additional delivery
channels are future work. Unknown version evidence is shown as unknown.

## Privacy

- **Matching is local.** Cornicen downloads whole public datasets (CVE List, KEV, EPSS bulk). It sends no product name, version or CVE ID to any data source in v1.
- **Notifications carry your data to the channel you configure.** An alert names the product and version it matched. If your ntfy server is someone else's, they see that. Self-host ntfy for end-to-end privacy.
- **No telemetry, analytics or update check.** The README lists every host contacted by default.
- **v1.1 caveat:** repository-specific checks (latest-release, GitHub advisories) and per-CVE lookups reveal what you watch to those hosts. Each will be opt-in and say so.
- Runs as non-root, read-only root filesystem, writable volume only for SQLite, watch list mounted read-only. No inbound port. Secrets (ntfy token) from environment or file, never the shareable TOML.
- User-Agent configurable, default `Cornicen/<version> (+<repo URL>)`.

Default source traffic goes to `github.com`, `api.github.com`,
`objects.githubusercontent.com`, and `release-assets.githubusercontent.com` for CVE List releases; `www.cisa.gov` for KEV;
and `epss.empiricalsecurity.com` for EPSS. Notifications go to your ntfy server
(the config loader defaults to `ntfy.sh`; the example requires you to set a
server). Every public-source request, redirect, pagination link and asset URL
must use HTTPS on port 443 and stay within that source's hosts listed above.
Userinfo and IP literals are rejected. DNS answers are checked at connection
time; loopback, private, link-local, unique-local, multicast and other non-public
addresses are rejected. Connections use the checked address directly while TLS
verifies the original hostname. Public sources ignore environment HTTP proxies.
The configured ntfy destination is separate from these source allowlists.
Notification redirects are rejected, so Authorization is never forwarded.
There are no other scheduled service calls.

Compressed download budgets are 2 GiB / 45 minutes for a CVE List snapshot,
200 MiB / 5 minutes for a CVE List delta, 20 MiB / 5 minutes for KEV, and
64 MiB / 5 minutes for EPSS. These are `DOWNLOAD_BUDGETS` in
`src/cornicen/config.py`; positive integer overrides use TOML tables such as:

```toml
[download_budgets.cvelist_snapshot]
max_bytes = 2147483648
deadline_seconds = 2700
```

Other budget table names are `cvelist_delta`, `kev`, and `epss`. The total
deadline spans redirects and body transfer, alongside 60-second socket timeouts.
Exceeding a budget fails the fetch and removes its partial download. EPSS also
limits expanded input to 256 MiB and 2,000,000 rows, with CVE identifiers at most
32 characters matching `CVE-\d{4}-\d{4,19}` (ASCII digits). Rejected feeds preserve
the accepted scores.

## Private acceptance list

Keep your real watch list and known historical CVEs outside the repository.
After ingesting the public datasets, create a private TOML acceptance file:

```toml
[[expect]]
watch_id = "proxy"
cve = "CVE-2026-1234"
```

Use one `[[expect]]` entry per known (watch, CVE) pair. The watch ID must be in
your current watch list. Mount the private file read-only into the container,
then run:

```sh
docker compose exec cornicen python -m cornicen replay --list /config/acceptance.toml
```

Replay evaluates stored records against the current watches and aliases without
fetching or delivering notifications. It prints `matched` or `not matched` for
each expected CVE and exits 1 if any expectation fails. Missing retained records
can cause failures; inspect them before trusting a deployment. Run it again after
watch changes. The public regression gate is `make gate`; its replay fixtures
check exact notification sequences without network access.

The gate includes seeded fuzz properties with 2,000 cases per property/scheme by
default. Run a longer local check with:

```sh
CORNICEN_FUZZ_CASES=100000 PYTHONPATH=src python3 -m unittest tests.test_fuzz
```

Failures print the base seed, property seed, and case index. Set
`CORNICEN_FUZZ_SEED` to replay a base seed; `.build/fuzz.out.md` records the
results and minimal failing inputs.

## License and prior art

MIT; see [LICENSE](LICENSE).

The silent first-run baseline, vendor-scoped version-bounded watches, a crash-safe outbox, and alerting on *what changed* rather than every record update are ideas seen in other open-source CVE watchers. Cornicen's code is written from this spec.
