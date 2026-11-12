# Cornicen — design spec

**Version 1.0 · 2026-11-03 · approved.** Written to be public: it becomes the build brief and the seed of the repo's docs. It names no real deployment, host, network or watch list.

Cornicen is a self-hosted CVE alerting tool for homelabs and small networks. One container watches public vulnerability data, matches it locally against a private list of the products and versions you run, and pushes an alert when something you run is affected. It stays silent when nothing is, and it says so loudly when it has gone blind.

---

## 1. Design goals

Judged in this order. Each is testable (§11).

1. **It catches what hits your gear.** For every defined event (§7) on a watched item, Cornicen enqueues exactly one notification within one poll cycle of *successfully ingesting* the record that causes it. Urgent events are sent at once; normal ones go in the next digest.
2. **Delivery is durable and at-least-once.** An enqueued notification survives crashes and outages and is retried until accepted. A lost acknowledgement can cause a rare duplicate; it never causes a loss.
3. **It stays quiet otherwise.** No notification for a product you don't run, a version a record authoritatively excludes, or a record edit that doesn't change applicability or a defined event.
4. **It never mistakes blindness for safety.** A source that cannot be fetched, returns incomplete data, or stops advancing is reported as unhealthy (§9), never as "no new CVEs."
5. **It says what it knows and what it doesn't.** Every alert states its evidence, and every unknown is shown as unknown — never as a negative ("not in KEV" means not listed, not "not exploited").
6. **It's usable by strangers.** No account or key for any v1 source; a fictional example watch list; one documented install.

An accepted pair (§4) is an explicit operator decision, recorded and shown in
local diagnostics. Guarantees 1 and 3 honor this decision; exploitation always
breaks through.

## 2. Non-goals

- Not a scanner: never probes or reads a running system; knows only the watch list.
- Not a dashboard: alerts are the product; status is a CLI command.
- Not an image scanner (use Trivy or Grype beside it).
- Not vulnerability management: no tickets, owners or SLAs.

## 3. Scope

### v1 — the core

| Source | Used for |
|---|---|
| **CVE List V5** (`CVEProject/cvelistV5`) | Primary match source: every published CVE, with the CNA's `affected` vendor / product / version data. In sampled recent records this data was present while NVD still had no CPE tags 2–13 days after publication. |
| **CISA KEV** (`known_exploited_vulnerabilities.json`) | Exploited-in-the-wild flag, CISA due date, ransomware use. |
| **FIRST EPSS bulk CSV** (daily) | Exploit-probability score and percentile shown on alerts and used for urgency at send time. Bulk download only, so no CVE ID ever leaves the host. |

Plus: the watch list (§4), matching with explicit applicability (§5), events and dedupe (§7), declared end-of-life, **ntfy** as the one notification channel, durable ingestion with gap recovery (§6), source health (§9).

### v1.1 — after the core is solid

- **Vendor advisory adapters**, each added only with archive/index catch-up or explicit gap reporting (§6.4): Synology RSS, Debian and Ubuntu via OSV, Microsoft and Cisco via CSAF, GitHub repository advisories.
- **EPSS threshold-crossing events**, with hysteresis.
- **NVD enrichment** (CVSS where the CNA gave none; CPE as supporting evidence only).
- **Latest-release checks** ("you are behind"), generic webhook, SMTP.

### Not covered (stated in the README)

- **Plex:** no machine-readable advisory feed found (its security web pages could not be inspected). Covered by CVE records; a latest-version check is planned for v1.1.
- **Apple:** no official machine-readable feed. A community feed exists; not planned.
- **Raspberry Pi OS:** Debian data (v1.1) covers its Debian base only, not Raspberry Pi-specific packages or firmware.
- **Anything without a CVE record or vendor advisory** (a blog post, a GitHub issue).

## 4. Watch list

A TOML file, mounted read-only. **It is the user's private inventory and never leaves the host.** The repo ships only a fictional example.

```toml
[[watch]]
id       = "proxy"                  # required, stable; renaming `name` never re-alerts
name     = "Reverse proxy"
match    = ["f5:nginx", "nginx:nginx"]   # vendor:product identities
version  = "1.25.3"
scheme   = "semver"                 # how to compare versions (below)

[[watch]]
id       = "router"
name     = "Edge router"
match    = ["openwrt:openwrt"]
version  = "21.02.7"
scheme   = "dotted"
eol      = true                     # declared: vendor no longer supports this version

[[watch]]
id       = "nas"
name     = "File server"
match    = ["examplecorp:examplenas_os"]
product_only = ["examplenas os"]    # optional loose names; lower confidence
version  = "7.2.2-72806"
scheme   = "opaque"                 # equality only
```

### Accept entries

`[[accept]]` records a CVE/watch pair, a required trimmed reason (1–200
characters), and `until` (inclusive local date), or `until_version_change = true`
with its required recorded `version`. Both conditions may be used; the first
lapse wins. CVE IDs normalize uppercase; duplicate case-folded pairs and malformed
entries reject the file. Accept entries are separate from watches and their
applied hash, so editing them never triggers matching. See the complete
[format, validation and warnings](watch-lists.md#accept-entries).

At delivery refresh, active entries hold only new-match/acceptance-lapsed rows
without KEV or exploitation. Held rows remain pending with `accepted` metadata,
normal urgency and a due time rolled to the next digest; EPSS alone never breaks
through. Corrections, health and baseline notifications are unaffected. Date or
version lapse, or entry removal, releases a held row with `acceptance_lapsed`
metadata. A separate transactional pass queues a normal lapse event for each
lapsed entry with an active pair, including baseline or previously notified
pairs. It writes only events/outbox and dedupes once per episode. Extending and
lapsing an entry again in the same episode does not notify twice. Holds never
alter ingest state, cursors, retries, episodes or health policies.

Status, report and watch check show decisions using the shared state predicate.
Unknown watches are ignored; lapsed, long and unmatched entries warn locally.
Reload validates watches and accepts together and retains both on rejection.
Deploy 0.1.6 before copying accept entries: 0.1.5 rejects the new table.

### Identity

- **Normalisation:** lowercase, trim, collapse internal whitespace. Punctuation is kept (`foo-bar` ≠ `foobar`).
- `match` entries are **vendor-scoped exact** identities, compared after normalisation against CNA `vendor`/`product` and KEV `vendorProject`/`product`.
- `product_only` entries match a product string from any vendor, at reduced confidence, and must be opted into per watch.
- Cornicen ships a **versioned alias map** of known spelling variants (e.g. a vendor's CNA spelling vs its CPE spelling). The map version is recorded with every match. Users can extend it locally.
- `cornicen watch check` validates the file, reports collisions (two watches claiming one identity), and shows, per watch, what the last 90 days of CVE records would have matched — and near misses — so users can tune identities before trusting them.

### Versions

Each watch declares a comparison `scheme`:

| Scheme | Meaning |
|---|---|
| `semver` | SemVer 2.0 precedence, including pre-releases |
| `dotted` | numeric dot-separated segments; any non-numeric segment makes the comparison unknown. Missing trailing segments count as zero for ordering (`21.02.7 < 23.05`), but an equality that holds only through that padding (`1.2` vs `1.2.0`) is unknown |
| `debian` | Debian package version ordering (epoch, upstream, revision) |
| `python` | CPython release ordering for three numeric components with optional `aN`, `bN` or `rcN`: alpha < beta < release candidate < final. Numeric components and pre-release serials compare numerically; leading zeros, case and one leading `v` are normalised. This is a conservative subset of PEP 440: missing components, dev/post/local/epoch forms and other spellings remain unknown |
| `opaque` | equality only, compared after normalising case and whitespace. A listed version that equals yours decides. An unlisted version can only lean toward exposure: it is **affected** when the CNA's `defaultStatus` is `affected`, otherwise **unknown** — never "not affected", because a spelling difference must not read as safe. Orderings, ranges and `changes[]` are unknown |

A watch `version` may be a single version or a range: comma-separated comparators from `=`, `>=`, `>`, `<=`, `<` (`">=7.0, <7.2.3"`). A range watch is **affected** if any version it allows is affected, **not affected** only if every version it allows is excluded, otherwise unknown. A comparison the scheme cannot decide yields **unknown**, never "any version."

### Reload

The file is re-read on change. A reload is validated whole and applied atomically, or rejected with the previous list kept and a health warning raised. After a valid reload, every changed watch is **re-matched against stored records**: a change that newly makes a watch affected produces new-match events; a change that clears it produces nothing.

Changes to effective alias groups, including local edits, re-check stored CVEs at the next start, including during bootstrap. The first start after upgrading also re-checks retained CVEs when no alias fingerprint is stored. Version-only edits do nothing. Resulting alerts follow the ordinary event path: new matches enter the digest, while KEV-listed or high-EPSS matches are urgent.

## 5. Applicability

For each (record, watch) pair Cornicen computes one state: **affected**, **not affected**, or **unknown**, with evidence.

### CVE List V5 `affected` semantics

Implemented to the CVE 5 schema, with boundary fixtures for each rule:

- `version` + `status` with no range: equality, except comparator strings below.
- With neither `lessThan` nor `lessThanOrEqual`, a `version` that parses as a comma-separated conjunction of explicit `=`, `>`, `>=`, `<`, `<=` comparators is evaluated as that constraint. Whitespace around comparators and commas is allowed (e.g. `< 10.11.10`, `>=2.0.0, <2.3.8`). All bounds use the watch's scheme; an absent `versionType` inherits it. Undecidable comparisons yield **unknown**, including git-hash bounds such as `< 920c8a1` under semver/dotted and ordering under opaque. Non-constraint strings and entries with explicit range fields retain equality/range semantics.
- `version` + `lessThan` / `lessThanOrEqual`: half-open or closed range from `version`.
- `changes[]`: status transitions inside a range (e.g. affected `[1.0, 2.0)` with `{at: "1.5", status: "unaffected"}` → 1.6 is not affected).
- `defaultStatus`: the status of versions not otherwise listed. If it is absent and every version row is an affected comparator string, versions decidably outside their union are **not affected**. An omitted or explicitly `unknown` default also permits **not affected** when every row is decidable, none covers the watched version, and at least one affected range describes the history from the beginning: a range starting at `0`, `0.0`, `0.0.0` or `*`, or an upper-bounded comparator constraint unbounded below (optionally `>=` zero). Evidence says "outside every affected range the CNA listed". This also applies to uncovered cells of a range watch; all allowed versions must be excluded to return **not affected**. All boundaries and status transitions must be decidable for this exclusion, including changes outside the watch; opaque ordering stays unknown. Entries without such a history retain **unknown**, apart from the comparator-only rule. Explicit `affected` and `unaffected` defaults take precedence over history exclusion; affected defaults follow the uniform rule below. The explicit-unknown case covers Plex CVE-2026-96652 as published in the 2026-11-03 corpus.
- **Uniform affected-default rule:** when a version is outside every affected range a CNA entry lists (all comparisons decidable) and the entry's `defaultStatus` is `affected`, the entry yields **unknown**, with evidence "outside every range the CNA listed; the CNA's default says affected". This applies before, between and after ranges, regardless of version spelling. Explicit status rows, status transitions and covering ranges retain precedence. An entry listing no affected ranges retains its existing default behavior. Affected comparator ranges follow the same rule. Range watches evaluate each endpoint and uncovered cell: any affected cell yields **affected**; all allowed versions must be excluded to return **not affected**, otherwise the result is **unknown**. Explicit range starts `0`, `0.0`, `0.0.0` and `*` are unbounded sentinels, never version values in ranking or lookup. In the unchanged DSM fixture, fictional `7.2.2-72806-9` and `7.4.3-90500` yield **unknown**, while `7.2.2-72806-6` remains **affected**. Its explicit unknown range `0 <= v < 7.2.1` keeps fictional `6.2.3-25426` **unknown**.
- `versionType` is recorded. Absent, `custom`, `semver` and `python` labels are hints: the watch's scheme compares the actual strings, and anything it cannot order remains **unknown**. CNAs use these labels for loosely dotted and vendor-specific versions as well as strict versions. Any other named type that differs from the watch's scheme (`rpm`, `git`, `maven`, `original_commit_for_fix`, …) makes the result **unknown**.
- DSM watches can use `debian`: `7.2.2 < 7.2.2-72806 < 7.2.2-72806-7 < 7.2.2-72806-11 < 7.3 < 7.4-90075 < 7.4.1-90081`. For point watches only, a numeric wildcard start with a non-wildcard upper bound textually in the same line (`5.4.*` below `5.4.12`) becomes that line's first release (`5.4.0`), while a version in the line below that release stays **unknown**. Every other wildcard bound, `unspecified` and prose (`before 6.1.4-15217`) remain **unknown**; the comparator does not infer omitted lower bounds or parse prose. CPython watches can use `python`: measurement of the 2026-11-03 corpus found pre-release bounds prevented semver/dotted from deciding 75 of 80 matched records for release 3.14.11 (76 were unknown in total). The supported grammar orders `3.14.0a1 < 3.14.0a2 < 3.14.0b1 < 3.14.0rc1 < 3.14.0`; other PEP 440 forms remain **unknown**. Semver/dotted continue to treat CPython pre-release strings as unknown. Range watches account for adjacent supported Python versions and never invent an affected version between `3.14.0a1` and `3.14.0a2`.
- `status: unaffected` and `unknown` entries are honoured, not skipped.
- When several `affected` entries match one watch: any affected result → **affected**; otherwise an explicit unaffected row or explicit `defaultStatus: unaffected` retains precedence over unknown. Exclusions inferred only from history are weaker: any unknown matching entry wins over it, including an entry with an undecidable row and another affected range covering the watched version. If all matching entries exclude the version, return **not affected**. Other existing exclusions retain their precedence.

### Resolving evidence

1. An authoritative version result from the CNA record (affected or not affected) decides.
2. A KEV listing without version data never overrides a CNA "not affected." With no CNA version data, a KEV identity match yields **unknown, exploited** — which is alerted (§7) because exploitation makes "check now" worth a ping.
   This rule applies even before the CNA record is retained.
3. `product_only` matches cap at unknown, including a real product name paired with a placeholder vendor (`n/a`, empty, `unknown`, etc.). Placeholder vendors never establish a scoped exact identity; placeholder products never match, even through `product_only` or KEV. The loose match requires explicit opt-in for that product name.
4. Rejected records are **not affected** from the moment the rejection is ingested.

## 6. Ingestion

### 6.1 Bootstrap

First run downloads the latest **full snapshot** of CVE List V5, then the cumulative daily deltas since that snapshot, then KEV and EPSS. The CVE snapshot identity, **snapshot cutoff** and completed phase are committed atomically with its records. Restart resumes deltas from that cutoff, including its day, without choosing a new baseline. Records first encountered after the snapshot phase completes are new even while KEV or EPSS bootstrap is pending. Bootstrap reads only page one of the release listing. An optional GitHub token file enables authenticated API requests and persistent ETag conditional requests for release listings and direct tag lookups.

### 6.2 Cursors and catch-up

- Each source keeps a durable cursor (CVE List: last fully processed release; KEV: `catalogVersion`; EPSS: score date).
- CVE List deltas are **cumulative since midnight UTC**. Catch-up processes one release per missed day, in date order, plus the latest release today. For past days it fetches the direct GitHub `/releases/tags/` endpoint for `cve_YYYY-MM-DD_at_end_of_day`, ordered after `2300Z`, with asset `YYYY-MM-DD_delta_CVEs_at_end_of_day.zip`; on HTTP 404 it falls back to the latest listed hourly `cve_YYYY-MM-DD_HH00Z` release. End-of-day releases need not carry a snapshot. Listing stops after passing the cursor day; HTTP 422 “Only the first 1000 results are available” ends the listing. A missed day older than the available releases requires full-snapshot reconciliation. If a day is missing, Cornicen reconciles from the latest available full snapshot and says so in health output. Unknown tags are skipped with a warning; a listing with no supported releases fails, including during bootstrap. Without a completed CVE List fetch, bootstrap becomes unhealthy after a two-hour grace period. Poll deadlines and loop elapsed time use a monotonic clock; UTC remains authoritative for metadata and digests. Persisted content times and cursor timestamps are checked for future skew; timestamps more than two hours in the future are unhealthy and cannot advance coverage.
- The cursor and committed CVE release identity advance only with the release's records and resulting events in one transaction. Already committed or older releases are ignored before applying records; incomplete releases remain retryable.
- A KEV catalog whose `dateReleased` precedes the stored content time is a failed fetch, including after restart. It leaves the accepted catalog and cursor untouched and keeps or makes KEV unhealthy.

### 6.3 Completeness

A fetch is **complete**, **partial** or **failed**. Partial covers: a truncated or undecodable body, a non-empty `error[]` in a CVE delta, a referenced record that could not be fetched, a schema mismatch. Partial and failed records go to a durable retry queue; the cursor does not pass them. An empty 200 is accepted only where the source can legitimately be empty (an empty delta); otherwise it is a failure.

### 6.4 Bounded feeds (v1.1 adapters)

A feed that exposes only its newest N items cannot prove nothing was missed. Every v1.1 adapter must either catch up through an archive or index (CSAF `changes.csv`, OSV export, full pagination) or report an **unrecoverable gap** as a health warning when the oldest item it sees is newer than its cursor.

### 6.5 EPSS

- Bulk CSV: verify decompression completes, the header matches, the score date is new or unchanged, and the row count has not collapsed (>20% drop is a failure).
- A CVE with no score is **unknown**, shown as "EPSS: not yet scored."

### 6.6 Stored CVE projection

The `records.json` blob is zlib-compressed JSON containing only:

- `cveMetadata`, unchanged (identity, rejection state, publication/update dates).
- `containers.cna.affected`, unchanged, including all version boundaries,
  statuses, defaults, `versionType` and `changes` used for applicability/evidence.
- `containers.cna.title` and `containers.cna.providerMetadata.shortName`.
- `containers.cna.metrics` and `containers.adp[].metrics`, retaining only
  metric keys starting with `cvss` and their complete values. Optional field
  presence and array order are preserved.

Descriptions, references, credits, problem types, legacy copies, other provider
metadata, non-CVSS metrics and other top-level/container fields are discarded.
Ingestion still validates the full incoming record. Invalid records/revisions
retain their original payload for validation and durable retries.

Applicability and reload/retry evaluation read metadata and affected data;
notification severity reads CNA CVSS `baseScore` (ADP scores do not alter v1
severity). `watch check` also reads `datePublished` for its window and
vendor/product for near misses. Replay uses the same resolver. Render reads the
engine's notification body; report reads pairs/dead letters, not CVE prose.
Title, CNA short name and ADP CVSS remain part of the stored contract.

At `run` startup, `Store.migrate()` projects existing text and compressed
records in transactions of at most 128 rows, decoding one record at a time.
Each batch commits its ID cursor; interrupted migration resumes from that cursor.
A version marker avoids rescanning on subsequent starts. Record IDs, ingestion
times, pairs, events, outbox and retry/dead-letter state are preserved.
Freed SQLite pages are reusable; migration does not vacuum the database, so an
existing file may retain its previous physical size.

## 7. Events and notifications

### 7.1 Events (v1)

| Event | Fires when |
|---|---|
| **new match** | a pair becomes affected, or unknown-and-exploited, for the first time |
| **KEV added** | a matched pair's CVE appears in KEV |
| **acceptance lapsed** | an accept entry lapses by date or version for an active pair; once per episode, due in the next digest |
| **correction** | a pair previously notified becomes not affected or rejected |

EPSS changes, CVSS changes, description edits and reference additions update the stored record silently in v1.

### 7.2 Identity and dedupe

- **Event key** = (watch `id`, canonical record ID, event type, episode). Canonical record ID is the CVE ID. A pair's **episode** starts at 1 and increments each time it goes from affected back to not affected (a correction), so a pair that later becomes affected again alerts again; nothing else re-arms it. Keys are stored permanently, independent of record retention, so a replay never re-sends.
- A **processing cycle** is one scheduler tick: run every due ingest in fixed order (CVE List, then KEV, then EPSS), compute events, then release the outbox. Nothing is sent mid-cycle, urgent items included. Events for the same pair in one cycle are **coalesced** into one notification listing every reason ("new match · KEV added"), and a new reason for a pair whose notification is still unsent is merged into it.
- The event row and its outbox row are written in the same transaction; the outbox row's ID is sent as the idempotency key (ntfy message ID / header) so receivers that support it can drop duplicates.
- Before a digest is sent, each queued item is **revalidated**; items that became not affected are dropped or converted to a correction.

### 7.3 Baseline

Classification is by **where a record came from**, not when it was processed: every record in the bootstrap's CVE List snapshot is baseline, whenever bootstrap gets to it; every record arriving in a delta release after that snapshot is new. Likewise, every entry in the first KEV catalog fetched is baseline for KEV-added events. Baseline pairs are recorded, not notified. Baseline completes only when every v1 source has completed once; a crashed bootstrap resumes from completed-source markers and never re-classifies records already ingested. On completion, one summary notification is sent ("baseline: 14 historical matches, 2 exploited — run `cornicen report`").

### 7.4 Urgency

- **Urgent** (sent at once, high priority): KEV-listed; or affected with EPSS ≥ the configured threshold at the time of sending (default 10%).
- **Normal:** everything else, in a combined digest (default daily, configurable). All due normal watch rows form one notification titled "Cornicen digest: N items", with one block per item, ordered by CNA CVSS severity then EPSS probability, highest first. Each constituent row is marked sent only after the combined send succeeds; failures leave every row pending. Urgent and health notifications, and the baseline summary, stay individual.
- **Promotion:** after each EPSS or KEV ingest, unsent normal items are re-evaluated; any that now meet the urgent rule are sent at the end of that cycle. Already-delivered items are not re-sent for a score change.
- **EOL:** any notification on an `eol = true` watch leads with "unsupported by the vendor — fixes unlikely; isolate or replace."
  `status`, `report`, and `watch check` also list each EOL watch ID with "coverage limited: the vendor issues no advisories for unsupported versions; absence of alerts is not evidence of safety" (structured as `eol_coverage_limited` IDs in status JSON; report JSONL sends the human notice to stderr), without creating events or notifications or changing health or exit codes. `watch check --file` reports the candidate file's EOL watches.

### 7.5 Notification text

```
🚨 Cornicen: CVE-2026-1234 — Edge router (openwrt 21.02.7)
Why: new match · KEV added
KEV: listed 2026-11-03, CISA due 2026-11-24 · EPSS 37% (97th pct, 2026-11-03)
Match: CNA affected openwrt < 23.05.4 — affected (version range)
EOL: unsupported by the vendor — fixes unlikely; isolate or replace
https://www.cve.org/CVERecord?id=CVE-2026-1234
```

Fields with no data say so ("EPSS: not yet scored", "Fix: not stated by the CNA").

## 8. Privacy

Stated in the README exactly like this:

- **Matching is local.** Cornicen downloads whole public datasets (CVE List, KEV, EPSS bulk). It sends no product name, version or CVE ID to any data source in v1.
- **Notifications carry your data to the channel you configure.** An alert names the product and version it matched. If your ntfy server is someone else's, they see that. Self-host ntfy for end-to-end privacy.
- **No telemetry, analytics or update check.** The README lists every host contacted by default.
- **v1.1 caveat:** repository-specific checks (latest-release, GitHub advisories) and per-CVE lookups reveal what you watch to those hosts. Each will be opt-in and say so.
- Runs as non-root, read-only root filesystem, writable volume only for SQLite, watch list mounted read-only. No inbound port. Secrets never go in the shareable TOML: the ntfy token comes from the environment or a file, and the optional GitHub token from a file only.
- User-Agent configurable, default `Cornicen/<version> (+<repo URL>)`.
- `ntfy_url` must be HTTP(S) with a host and no userinfo, query string or fragment. Path prefixes are allowed; invalid values are rejected at configuration loading with an error naming the key.

## 9. Health

- Cornicen keeps **one state per source**. Its detail names **fetch health** (did requests succeed), **completeness** (§6.3), and **content-age findings** against a per-source expectation. Failed or partial ingestion retains a sanitised last error (control characters removed, at most 200 characters) in health detail and `cornicen status`:

A successful unchanged CVE release listing clears fetch failure without advancing coverage. Pending record retries and content-age problems still keep the source unhealthy.

| Source | Expected to change | Stale when |
|---|---|---|
| CVE List V5 | every hour | no new release for 3 h |
| KEV | irregularly (days can pass) | fetch health only; content age is shown, not alarmed |
| EPSS | daily | score date older than 2 days |

- A health transition (healthy → unhealthy and back) is a persisted event, sent as an **urgent** notification on the way down and a normal one on the way back up.
- Because a broken channel cannot deliver its own warning, health is also exposed as the **container health check** (unhealthy if any source is unhealthy, or any outbox item is still undelivered a configurable period after its due time; a quiet install with nothing to send stays healthy) and by `cornicen status`.

## 10. Runtime

- One container, one process, internal scheduler, SQLite in a volume.
- Polls: CVE List hourly, KEV every 6 h, EPSS daily, outbox continuously.
- Budget: ≤256 MB steady state; bootstrap streams the snapshot rather than holding it in memory.
- Retention: record history prunable by setting; event keys and baseline markers never pruned.
- Python (§13).

### Local CLI commands

All commands accept the global `--config PATH`. Existing commands are `run`,
`status`, `healthcheck`, `report`, `watch check [--days N]`,
`replay --list PATH` and `notify test`.

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

- `explain CVE_ID --watch WATCH_ID`: resolve the locally retained CVE and KEV
  against the current watch file. Print version/scheme, applicability,
  exploitation, evidence, confidence and alias-map version. Label stored pair
  state separately from current-file evaluation. An identity miss exits 0;
  unknown watch IDs and unavailable retained records exit 1. Missing retained
  data is explicitly unavailable, never not affected.
- `outbox list [--failed]`: print pending rows only, ordered by effective
  eligibility then row ID. Include ID, watch/CVE or operational component,
  urgency, reasons, enqueue/due times, attempts, retry time and `eligible_at =
  max(due_at, next_attempt_at or due_at)`. `--failed` selects attempts greater
  than zero. Dirty rows say `awaiting revalidation`; health and baseline rows
  remain visible without a watch ID. Output is JSON lines followed by
  `Pending rows: N`; an empty queue exits 0, unavailable databases exit 1.
  Persisted scheduling may change during revalidation.
- `status --json`: emit one object with `schema_version` (integer 1),
  `available` (boolean), `container_healthy` (boolean), `sources` (object),
  `baseline_complete` (boolean) and `reconcile_at` (string or null), plus
  `eol_coverage_limited` (array of watch IDs) when EOL watches exist.
  Each source has exactly `state`, sanitized `detail`, `cursor` and
  `content_time`; the latter two are strings or null. Reuse source assessment
  and container health policies. An unavailable/unreadable database emits
  false availability/health/baseline, empty sources and null reconciliation,
  then exits 1. Available status exits 0 even when unhealthy. Coverage notices
  use the current watch file and are omitted by status/report if it cannot be
  loaded; health assessment and exit codes retain their behavior.
- `watch check [--days N] [--file PATH] [--strict]`: optionally validate a
  candidate instead of the configured file for this invocation. Strict mode
  exits 1 for identity collisions or existing alias-map warnings; default
  warnings exit 0. Validation errors exit 1 in either mode. Explicit `--file`
  or `--strict` preflight shows detailed problems locally; plain `watch check`
  retains sanitized errors. Validation works without a database, never rewrites watch
  files, and never persists or notifies validation problems.

These diagnostics make no network or notification calls. They open existing
databases read-only without migrations and leave state unchanged. No new
configuration keys are required.

## 11. Testing and acceptance

- **The gate is a command** — `make gate` — that runs the full suite. It is written first, run once against the empty scaffold, and must fail there for the right reasons before any feature work starts.
- **Replay fixtures:** each scenario is a timestamped input file (`tests/replay/<name>.input.jsonl`, trimmed real records) plus an exact expected output (`<name>.expected.jsonl`: events and notifications in order). Writing these files is the **first build task**; they are reviewed before any feature work, and from then on they are the contract. Required scenarios:
  - affected range with `changes[]` exclusion; `lessThanOrEqual` endpoint; `defaultStatus: affected`;
  - authoritative not-affected beats a versionless KEV listing;
  - same CVE arriving via CVE List and KEV in one cycle → one coalesced notification;
  - record revised after baseline to include the watched version → one new match;
  - record rejected after notification → one correction; queued digest item dropped;
  - affected → corrected → affected again → second new match (episode 2), nothing more on replay;
  - normal item promoted by a later EPSS ingest → sent at the end of that cycle, once;
  - quiet install for 30 simulated days → healthy, nothing sent after the baseline summary;
  - watch renamed → nothing; watch version changed into a vulnerable range → one new match;
  - downtime spanning several hourly releases → every release processed, nothing duplicated;
  - delta with non-empty `error[]` → partial, cursor held, retried;
  - empty 200 from KEV → failure, health event;
  - EPSS CSV with collapsed row count → failure;
  - replaying any scenario twice → nothing new the second time.
- **Operators** keep a private acceptance list (their real products and a handful of past CVEs known to hit them) outside the repo and run `cornicen replay --list <file>` before trusting a deployment. The list runs against its own watch list, pinned to the versions those CVEs hit, through a separate config (`--config`). It does not use the live watch list, so it keeps passing after upgrades, and a failure means Cornicen or its data broke.

- **Daemon acceptance self-test:** opt in with both `acceptance_list_path` and
  `acceptance_watchlist_path`. The latter holds pinned watches. Omit both to
  disable it. `acceptance_interval_days` is a positive integer, default 7.
  After `run_cycle` and baseline completion, check on the first process tick,
  after more than the interval since persisted `acceptance_last_run`, or when
  either file's modification time, size or inode changes. Exceptions become
  fixed health failures and do not fail the cycle. Flush in the same tick.
  Unhealthy acceptance retries hourly; healthy acceptance keeps the configured interval.
  Persist last-run time and health atomically after evaluation; a failed transaction
  retries next tick. Guards never print or log exception text.
- **Acceptance bar:** every stored record must resolve to AFFECTED with the
  engine's aliases. UNKNOWN with KEV is a regression. Missing records are
  could-not-check; never construct stubs. Ignore suppressions. Resolve pinned
  watches in memory only, without pairs or match notifications. Reject invalid
  or unreadable files, unknown watch IDs and empty lists. Use the `acceptance`
  health component with counts and fixed words only, and existing recovery events.
- **Retention holds:** after each valid list parse, save sorted distinct CVE IDs
  in memory and best-effort as JSON in `meta.acceptance_holds`. Parse every tick
  before pruning and repair missing, corrupt or stale metadata. Pruning excludes
  both in-memory IDs and IDs in valid stored arrays of strings; garbage holds
  nothing. Broken files preserve existing holds; failed writes retain memory holds.
- **Local command:** `cornicen selftest` reads the configured paths and store
  without writes. Print entry results and a summary. Exit 0 for all pass, 1 for
  regression, 3 for any could-not-check, or 2 for command error. Exit 3 outranks 1.

## 12. Prior art

The silent first-run baseline, vendor-scoped version-bounded watches, a crash-safe outbox, and alerting on *what changed* rather than every record update are ideas seen in other open-source CVE watchers. Cornicen's code is written from this spec.

## 13. Decisions

1. **Language:** Python.
2. **License:** MIT.
3. **EPSS urgent threshold default:** 10% probability (configurable).
4. **Vendor advisories:** v1.1, as in §3.
5. **Prior art in the README:** the generic credit line in §12.
