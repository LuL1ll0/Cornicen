# Command reference

← [README](../README.md)

## Local diagnostics

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
  each group by watch/CVE (or source/CVE for dead letters). Empty JSONL is empty output.
  The EOL coverage notice goes to stderr in JSONL mode.
  Coverage follows `--watch` filters regardless of group filters or recorded matches.
  Exports contain private inventory and should stay local.
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
- `status --json` emits one object with `schema_version` (1),
  `available`, `container_healthy`, `sources`, `baseline_complete` and
  `reconcile_at`. Each source has `state`, sanitized `detail`, `cursor` and
  `content_time`. Flags are booleans; absent cursor/time/reconciliation values
  are null. An unavailable database emits false availability/health, empty
  sources, false baseline completion and null reconciliation, then exits 1.
  Available status exits 0 even when unhealthy; use `container_healthy` for
  monitoring. EOL coverage metadata is described below. Health assessments and
  exit codes do not change.
- `watch check [--file PATH] [--strict]` validates the candidate file only for
  this invocation. It works without a database. Explicit `--file` or `--strict`
  preflight prints detailed local validation errors; plain `watch check` keeps
  its sanitized validation errors. `--strict` exits 1 for identity collisions or alias-map
  warnings; default warnings exit 0. Invalid files exit 1 in either mode.
  Neither mode rewrites the active file or persists validation problems.

`status`, text `report`, and `watch check` print this line for each `eol = true`
watch, prefixed with its watch ID:

```text
WATCH_ID: coverage limited: the vendor issues no advisories for unsupported versions; absence of alerts is not evidence of safety
```

`status --json` adds `"eol_coverage_limited": ["WATCH_ID", ...]` to its object;
the field is omitted when there are no EOL watches.
`report --format jsonl` writes the human notice lines to stderr. Report coverage
respects `--watch`, applies regardless of `--group`, and includes watches with
no recorded matches. Notices use the current watch file; status and report omit
coverage when that file cannot be loaded, preserving their existing availability.
`watch check --file` reports the candidate file's EOL watches.
This notice creates no events or notifications and changes no health state or exit code.

Stored CVEs use the [projection documented in the spec](spec.md#66-stored-cve-projection):
metadata, affected products/versions, title, CNA short name and CNA/ADP CVSS.
Descriptions, references and other unused material are discarded. Startup
migrates existing records in resumable batches of 128; freed SQLite pages are
reused without automatically shrinking the existing file. Matching, diagnostics
and notifications use the retained fields.

## Accept entry diagnostics

`accept_warn_days` in `cornicen.toml` is a positive integer, default 180. It
controls the `watch check` warning for far-future `until` dates.

After `reconcile:`, text `status` prints each entry as:

```text
accepted: proxy/CVE-2026-0001 until 2027-03-01 — active; held 1; Module not built
accepted: 1 active, 0 lapsed, 0 unknown watch
```

A version-change entry shows `until version change`; an entry with both conditions
shows `until <date> or version change`. States are `active`,
`lapsed-date`, `lapsed-version` and `unknown-watch`. JSON status adds an `accepted`
array of `{watch_id, cve, reason, until, version, state, held}`; dates are
`YYYY-MM-DD` strings or null. Existing fields and `schema_version: 1` remain.
A loaded watch list with no accept entries emits `accepted: []`.
An unreadable watch file prints `accepted: not checked (watch list unreadable)`
in text and omits the JSON key. Exit codes do not change.

`report` keeps its groups and rows. When the watch list loads, each pair row
adds `accepted`: null or `{reason, until, version, state}`. Its text summary
excludes active, non-exploited accepted pairs from affected/open counts and
counts them as `Accepted (not alerting): N`. Exploited pairs remain counted and
show their acceptance. With no accept entries, pair rows still have `accepted: null`;
dead-letter rows never have this field. If the watch list cannot load, pair rows
omit it. The text summary keeps its legacy shape when there are no accept entries.
JSONL stdout contains only rows, with schema version 1.
An unreadable watch file prints `accepted: not applied (watch list unreadable)`
on stderr in both formats, preserving the legacy text report on stdout.

Reasons in status and watch-check text replace control characters with spaces,
collapse whitespace and are capped at 160 characters.

`watch check` lists each entry's state and reason, followed by `accept warning:`
lines for unknown watches, lapsed entries, long dates and matches nothing.
Stored-record applicability uses the candidate watches when `--file` is given;
matching is marked not checked without a database. `--strict` also exits 1 for
accept warnings. Malformed accept entries reject the entire file with a labelled
`watch validation error: accept entry N (<cve>/<watch>): <problem>`.
`outbox list` includes the held row's `accepted` body metadata for auditing.

Deploy 0.1.6 before installing a watch file containing `[[accept]]`; v0.1.5
rejects that table. See [accept entry format and limits](watch-lists.md#accept-entries).

## Minute heartbeat

Each successful minute cycle logs one JSON line. Existing keys `time`, `sources`,
`ingested`, `events`, `sent` and `pending` retain their shapes.

`health_details` values are filtered to Cornicen's vocabulary, integers and ISO
times; withheld text appears as `[redacted]`. Keys that fail the same boundary
are dropped. The always-present integer `health_details_withheld` counts dropped
keys (normally 0). Loaded watch inventory is also withheld, including vocabulary
fragments of at least four characters. Record IDs after `Dead-letter records:`,
`Missing stored record:` and `Declared record missing or invalid:` are withheld
through the end of the text. Punctuation-only tokens and leading or trailing
punctuation runs peeled from a core are kept only when exactly one character
long, independently of inventory. The exact marker always passes through.

Failed-cycle lines filter `error`, `message`, `health_error` and `health_message`;
withheld exception type names become `Exception`. The `run` startup failure line
uses the same filter, with loaded watches when available. Before watch loading
succeeds it uses no inventory. Argument errors for `run` print only a fixed usage
line to stderr and exit 2. Operator commands retain their detailed output.
Two additional objects expose aggregate monitoring values:

- `report`: `affected`, `exploited_unknown`, `open`, `dead_letters` and `accepted`
  are integer counts matching the unfiltered text report Summary. Active accepts
  exclude non-exploited pairs from affected/open totals and count them as accepted;
  no accept entries means `accepted: 0`. Counts are recomputed every cycle from
  pairs and dead letters using the engine's loaded inventory. A counting failure
  makes all five values null.
- `github`: `auth` is `token`, `none`, `token-rejected`, `token-unusable` or
  `unknown`. `limit` and `remaining` are integers; `reset` and `observed_at` are
  integer UTC epoch seconds. These four values are null without valid stored
  rate-limit metadata. Values come from the last stored GitHub response, with no
  additional request. A status failure emits `auth: "unknown"` and four nulls.

The new objects contain no watch IDs, products, CVE IDs or diagnostic free text.
