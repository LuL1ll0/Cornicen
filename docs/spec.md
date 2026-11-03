# Cornicen — design spec

**Version 1.0 · 2026-11-03 · approved.** Written to be public: it becomes the build brief and the seed of the repo's docs. It names no real deployment, host, network or watch list.

Cornicen is a self-hosted CVE alerting tool for homelabs and small networks. One container watches public vulnerability data, matches it locally against a private list of the products and versions you run, and pushes an alert when something you run is affected. It stays silent when nothing is, and it says so loudly when it has gone blind.

---

## 1. Guarantees

Judged in this order. Each is testable (§11).

1. **It catches what hits your gear.** For every defined event (§7) on a watched item, Cornicen enqueues exactly one notification within one poll cycle of *successfully ingesting* the record that causes it. Urgent events are sent at once; normal ones go in the next digest.
2. **Delivery is durable and at-least-once.** An enqueued notification survives crashes and outages and is retried until accepted. A lost acknowledgement can cause a rare duplicate; it never causes a loss.
3. **It stays quiet otherwise.** No notification for a product you don't run, a version a record authoritatively excludes, or a record edit that doesn't change applicability or a defined event.
4. **It never mistakes blindness for safety.** A source that cannot be fetched, returns incomplete data, or stops advancing is reported as unhealthy (§9), never as "no new CVEs."
5. **It says what it knows and what it doesn't.** Every alert states its evidence, and every unknown is shown as unknown — never as a negative ("not in KEV" means not listed, not "not exploited").
6. **It's usable by strangers.** No account or key for any v1 source; a fictional example watch list; one documented install.

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
| `opaque` | equality only, compared after normalising case and whitespace. A listed version that equals yours decides. An unlisted version can only lean toward exposure: it is **affected** when the CNA's `defaultStatus` is `affected`, otherwise **unknown** — never "not affected", because a spelling difference must not read as safe. Orderings, ranges and `changes[]` are unknown |

A watch `version` may be a single version or a range: comma-separated comparators from `=`, `>=`, `>`, `<=`, `<` (`">=7.0, <7.2.3"`). A range watch is **affected** if any version it allows is affected, **not affected** only if every version it allows is excluded, otherwise unknown. A comparison the scheme cannot decide yields **unknown**, never "any version."

### Reload

The file is re-read on change. A reload is validated whole and applied atomically, or rejected with the previous list kept and a health warning raised. After a valid reload, every changed watch is **re-matched against stored records**: a change that newly makes a watch affected produces new-match events; a change that clears it produces nothing.

## 5. Applicability

For each (record, watch) pair Cornicen computes one state: **affected**, **not affected**, or **unknown**, with evidence.

### CVE List V5 `affected` semantics

Implemented to the CVE 5 schema, with boundary fixtures for each rule:

- `version` + `status` with no range: equality, except comparator strings below.
- With neither `lessThan` nor `lessThanOrEqual`, a `version` that parses as a comma-separated conjunction of explicit `=`, `>`, `>=`, `<`, `<=` comparators is evaluated as that constraint. Whitespace around comparators and commas is allowed (e.g. `< 10.11.10`, `>=2.0.0, <2.3.8`). All bounds use the watch's scheme; an absent `versionType` inherits it. Undecidable comparisons yield **unknown**, including git-hash bounds such as `< 920c8a1` under semver/dotted and ordering under opaque. Non-constraint strings and entries with explicit range fields retain equality/range semantics.
- `version` + `lessThan` / `lessThanOrEqual`: half-open or closed range from `version`.
- `changes[]`: status transitions inside a range (e.g. affected `[1.0, 2.0)` with `{at: "1.5", status: "unaffected"}` → 1.6 is not affected).
- `defaultStatus`: the status of versions not otherwise listed. If it is absent and every version row is an affected comparator string, versions decidably outside their union are **not affected**. Other omitted defaults remain **unknown**; explicit defaults always take precedence outside listed versions.
- `versionType` is recorded. `custom` (about 20% of real version entries) supplies no ordering of its own, so the watch's scheme compares it — and still yields **unknown** for anything that scheme cannot decide. Any other named type that differs from the watch's scheme (`rpm`, `git`, `maven`, …) makes the result **unknown**.
- `status: unaffected` and `unknown` entries are honoured, not skipped.
- When several `affected` entries match one watch: any affected result → **affected**; otherwise any unaffected result → **not affected**; otherwise unknown. (Errs toward alerting when a CNA contradicts itself.)

### Resolving evidence

1. An authoritative version result from the CNA record (affected or not affected) decides.
2. A KEV listing without version data never overrides a CNA "not affected." With no CNA version data, a KEV identity match yields **unknown, exploited** — which is alerted (§7) because exploitation makes "check now" worth a ping.
3. `product_only` matches cap at unknown.
4. Rejected records are **not affected** from the moment the rejection is ingested.

## 6. Ingestion

### 6.1 Bootstrap

First run downloads the latest **full snapshot** of CVE List V5, then the cumulative daily deltas since that snapshot, then KEV and EPSS. The CVE snapshot identity, **snapshot cutoff** and completed phase are committed atomically with its records. Restart resumes deltas from that cutoff, including its day, without choosing a new baseline. Records first encountered after the snapshot phase completes are new even while KEV or EPSS bootstrap is pending. Bootstrap reads only page one of the release listing.

### 6.2 Cursors and catch-up

- Each source keeps a durable cursor (CVE List: last fully processed release; KEV: `catalogVersion`; EPSS: score date).
- CVE List deltas are **cumulative since midnight UTC**. Catch-up processes one release per missed day, in date order, plus the latest release today. For past days it fetches the direct GitHub `/releases/tags/` endpoint for `cve_YYYY-MM-DD_at_end_of_day`, ordered after `2300Z`, with asset `YYYY-MM-DD_delta_CVEs_at_end_of_day.zip`; on HTTP 404 it falls back to the latest listed hourly `cve_YYYY-MM-DD_HH00Z` release. End-of-day releases need not carry a snapshot. Listing stops after passing the cursor day; HTTP 422 “Only the first 1000 results are available” ends the listing. A missed day older than the available releases requires full-snapshot reconciliation. If a day is missing, Cornicen reconciles from the latest available full snapshot and says so in health output. Unknown tags are skipped with a warning; a listing with no supported releases fails, including during bootstrap. Without a completed CVE List fetch, bootstrap becomes unhealthy after a two-hour grace period. Poll deadlines and loop elapsed time use a monotonic clock; UTC remains authoritative for metadata and digests. Persisted content times and cursor timestamps are checked for future skew; timestamps more than two hours in the future are unhealthy and cannot advance coverage.
- The cursor and committed CVE release identity advance only with the release's records and resulting events in one transaction. Already committed or older releases are ignored before applying records; incomplete releases remain retryable.

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
- Runs as non-root, read-only root filesystem, writable volume only for SQLite, watch list mounted read-only. No inbound port. Secrets (ntfy token) from environment or file, never the shareable TOML.
- User-Agent configurable, default `Cornicen/<version> (+<repo URL>)`.

## 9. Health

- Cornicen keeps **one state per source**. Its detail names **fetch health** (did requests succeed), **completeness** (§6.3), and **content-age findings** against a per-source expectation. Failed or partial ingestion retains a sanitised last error (control characters removed, at most 200 characters) in health detail and `cornicen status`:

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
- **Operators** keep a private acceptance list (their real products and a handful of past CVEs known to hit them) outside the repo and run `cornicen replay --list <file>` before trusting a deployment.

## 12. Prior art

The silent first-run baseline, vendor-scoped version-bounded watches, a crash-safe outbox, and alerting on *what changed* rather than every record update are ideas seen in other open-source CVE watchers. Cornicen's code is written from this spec.

## 13. Decisions

1. **Language:** Python.
2. **License:** MIT.
3. **EPSS urgent threshold default:** 10% probability (configurable).
4. **Vendor advisories:** v1.1, as in §3.
5. **Prior art in the README:** the generic credit line in §12.
