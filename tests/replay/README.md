The input and expected JSONL files are the replay contract. Expected outputs
were selected from spec §§5–9, independently of any engine implementation.
Every expected file starts with a JSON comment explaining its result.

`run_scenario` creates one in-memory store and one engine per invocation. It
passes ingests to the engine in file order; the engine must enforce source
ordering within each cycle. The clock advances on every input line. Notification
timestamps therefore distinguish an ingest from the cycle that releases it.
`replay_twice_idempotent` literally contains `same_cycle_coalesce` twice,
including its original timestamps, without recreating the engine or store.
This deliberate clock rewind models replay, rather than an ordinary scheduler.
Its second pass deliberately replays an older KEV catalog lacking the later
entry: absence is not an event, and the permanent event key keeps it silent.
All other input timelines require non-decreasing `t`; only the first row may
be a `{"#": …}` comment. Notifier `down` / `up` support is used from Task 7.

Fixture conventions:

- Source names are `cvelist`, `kev`, and `epss`. Ingest `kev` is a map from CVE ID
  to the trimmed catalog entry; `epss` maps IDs to score/percentile pairs.
- Watches use fictional `examplecorp` identities. Built-in aliases are disabled
  so future alias additions cannot change these expectations.
- The baseline summary has `watch: ""`, `record: "baseline"`, and
  `reasons: ["baseline"]`. Source health notifications have `watch: ""`.
- A rejected item that was never delivered is dropped, without a correction
  (spec §7.1 limits corrections to previously notified pairs).
- Cursor tags preserve release order and never postdate their ingest's
  `content_time`.

Binding conventions (copied from Task 5 of `.build/plan.md`):

- The baseline summary is sent at the end of the cycle that completes the baseline, urgency `normal`, outside the digest.
- Corrections are urgency `normal`, digest-delivered; EPSS urgency applies only to affected pairs.
- Health: down = urgency `health`, sent at end of cycle; recovery = urgency `health`, sent at end of cycle. Health states are only `healthy` / `unhealthy`.
- A source never ingested yet is not unhealthy while the baseline is incomplete.
- `reload_watches()` only queues; delivery happens at the end of the next `run_cycle`.
- `ingest.kev` and `ingest.epss` are the FULL catalog / score map each time; absence from one is not an event (no KEV-removal events).
- Health age is computed from `content_time`, never from cursor tags.

Trimmed fixture provenance (CVE IDs retained; identities fictionalized):

- `CVE-2025-54831.json`: affected SemVer equality and unaffected default. Revised,
  excluded and rejected variants are authored transitions for state scenarios.
- `CVE-2013-20009.json`: closed endpoint `1.01.06`; `custom` is changed to
  `dotted` so this tests the endpoint rather than a scheme conflict.
- `CVE-2026-110970.json`: range with `changes[]`; the bounds, transition and
  version type are adapted to spec line 117's numeric `[1.0, 2.0)` example,
  since the raw `metric 334` transition cannot be compared by a v1 scheme.
- `CVE-2023-20577.json`: first affected entry, including the real explicit
  unaffected opaque version and affected default.
- `kev_sample.json`: first entry's CVE ID, dates and ransomware value form the
  unrelated initial catalog. The service entry adapts its ID, product and dates
  for a hypothetical later listing; it makes no claim about real KEV membership.
- `epss_head.csv`: score/percentile values used in scenarios, assigned to the
  scenario records; the five-row collapse baseline retains its real CVE IDs.

The quiet scenario lists every hourly CVE delta for exactly thirty days, with
six-hourly successful KEV fetches and daily EPSS. Empty deltas are valid; empty
KEV is represented as a failed adapter result. Collapse and delta-error cases
also feed already-classified adapter results, per Task 1; byte parsing, cursor
state assertions and retry persistence belong to later module tests.

Round-3 fixtures additionally support `evaluation_failure: true|false` (inject a
resolver exception during subsequent cycles), `retention_days: <integer>`
(configure retention), and `pairs: [...]` (assert exact stored watch/record/state
rows at that timestamp). These expose failure and retention timelines without
putting matching policy in the harness. Notification expectations remain exact.
