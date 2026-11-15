R11 timeline differential (tests first)
======================================

`tests/test_r11_differential.py` runs all 40 unmodified `tests/replay/`
timelines and the 20 invented timelines here against current `src/`, in plain,
accepted, shell-only, support-only, mixed, live mid-timeline and `mixed_late` configurations. All watch IDs from
fixture watch definitions form the fixed v1 cohort, also frozen in each reference.
Production routing never selects or shrinks that cohort. The mixed configuration
adds `r11_adapter_watch` on `examplecorp:r11_unwatched`; that watch matches the
injected product at affected version `1.0.0`. Its public route must be
`advisory`; affected pairs, events, outbox rows, advisory bodies and digest
coalescing are asserted separately. Every original watch remains in the comparison. Fixture assertions
reject an injection that matches a cohort watch or a mixed extra watch that does
not match the adapter product. No production adapter gate is enabled.

Run the active suite:

    PYTHONPATH=src python3 -m unittest tests.test_r11_differential tests.test_r11_shells -v

The six injected comparisons and seven shell assertions explicitly disable
pending handling. `CORNICEN_R11_PENDING` cannot hide their failures and is absent
from `make gate`. Each injected comparison checks every timeline, tick and
observable before asserting the collected differences. Output gives one
representative difference per observable per timeline. Plain comparison,
fixture checks and reference regeneration remain active. The generic
pending-mechanics self-test retains its original expectations.

Reference and observation contract
----------------------------------

`tools/capture_r11_reference.py` explicitly selects `.build/v11/v0116/src`,
checks every pinned Python source against the original v0.1.16 frozen SHA-256
manifest, and writes only `tests/fixtures/r11_reference/` (or `--output DIR`).
It also rechecks every original replay against the existing complete frozen
final database and notification capture. It never rewrites `v0116_frozen`.
The new manifest pins source, input, capture tool and harness hashes.

    python3 tools/capture_r11_reference.py --help
    PYTHONPATH=src python3 tools/test-capture-r11-reference.py

Recreate the optional pinned tree with:

    mkdir -p .build/v11/v0116
    git archive 1c97d0d src tests tools | tar -x -C .build/v11/v0116

If absent, regeneration skips with "pinned v0.1.16 tree absent: could not check
regeneration"; the capture tool exits 3 with the same message.

The regeneration check runs the capture in a separate process, compares the
complete file set, and compares every byte. Differential execution reads JSON
expectations only; it never imports the pinned implementation. Regeneration is
an explicit reference-capture operation, not a runtime oracle.

Each frozen file records pair existence and all pair columns; complete event
rows including permanent keys and occurrence/resolution suffixes; all columns of
pending outbox rows, including decoded complete bodies, scheduling and attempts;
full delivered member bodies and notification envelopes; and the renderer's
complete `(title, text, priority, tags)` result for members and envelopes.
Snapshots follow EVERY input action, including ingests waiting for a cycle,
watch edits, outages and restarts. An index distinguishes repeated timestamps
and intentional clock rewind. Thus transient queued bodies and corrections that
are later superseded are still compared. Mixed observations project only the
extra watch away. SQLite outbox IDs are surrogate delivery addresses, projected
to the cohort's allocation order (including retained sent rows); event keys and
body contents are retained. The only global-summary projection subtracts the
extra watch's historical/exploited baseline counts, captured when the baseline
event is built. The full unprojected total is asserted against stored pairs;
all other summary text and fields remain in the comparison. Numeric notifier transport keys are excluded
from member metadata; full digest bodies retain item keys after subtracting only extra-watch allocations,
including deleted allocations. A digest reduced to one cohort member retains
that member’s envelope identity and reasons, as in the plain run.

Public `advisory.route` observations cover evaluation, revalidation, body
building, reload and `cli.explain`; each site must be observed for the injected cohort.
The plain run skips evaluation/reload route calls when the emptiness probe finds no adapter data.
Any advisory-side resolver, metadata, fix or body call for a cohort watch fails.
Missing hooks fail loudly, including when testing old code without the public seam.
Every tick compares cohort explain text and exit codes with `explain.json`,
captured only from the pinned v0.1.16 tree. The `late` variant sends unrelated
adapter evidence through `AdapterStore.process` and the real commit callback
after a cycle has stored a CNA record. `mixed_late` also includes the matching
extra watch. Before its real commit, a database backup isolates a probe that
seeds cohort pending rows with attempts=3, future retry/delivery times and dirty=0
(the revalidated state), fired EPSS crossings, affected latches and revision retry
markers. The real `AdapterStore.process` / `Engine.commit_advisory` must leave
all cohort state unchanged. The backup is restored and the actual commit runs
again to continue the independent timeline. The probe does not mock the commit
or its SQL; a backup avoids SQLite ATTACH/DETACH locks from an enclosing savepoint.
All timelines additionally compare cohort latches, EPSS crossings, relevant v1
meta keys and health rows. Six executable mutants cover dirty-all, EPSS re-arm,
retry-marker clearing, dirty_record, and dirty-all/retry clearing before the
advisory-only early return.
The accepted seed uses shared validation
and `AdapterStore` persistence without a matching callback; its adapter baseline
is already complete, preventing a synthetic adapter baseline summary from
polluting the v1 comparison. Shell-only has quarantine plus owned markers (the
legacy one-column form is supported for setup); support-only has membership
history without evidence or cohort pair history.

Only this new runner parses accepts with `load_document_text` and supplies them
to the engine on startup, reload and restart. Existing v1 harness/tests are
unchanged. The new `aliases`, `matching_revision` and `revision_reload` actions
exercise real alias loading, startup revision comparison and forced revision
reload, respectively. Resolver exceptions are injected only while a production
record-isolation boundary is active. They do not extend into digest delivery or
an unisolated branch. This preserves failure/retry inputs while allowing an
incorrect route that bypasses isolation to expose changed events and delivery
timing instead of manufacturing an uncaught resolver crash.

Cases and reviewed reference outcomes
-------------------------------------

All new CVEs are `CVE-2099-*`; products/vendors are invented. The original
replays retain their original identities exactly, as their frozen contract
requires. The new input files carry provenance comments and literal actions;
expectations live in the corresponding `r11_reference/replay_r11/*.json` files.
These reference outcomes are also checked by active infrastructure assertions.

* `kev_no_cna_initial_later_resolution`: no CNA at either catalog observation;
  initial A is historical/silent, later B alerts unknown/exploited, then CNA
  resolution produces a correction with the full `|resolution` suffix.
* `kev_coalescing`: CNA new match and later KEV addition merge into one delivery.
* `epss_crossing_rearm`: a delivered affected pair crosses high, low, high;
  two crossing keys retain their distinct occurrence suffixes.
* `epss_delivery_suppression`: crossing queued during outage; an acceptance
  added before retry delivery suppresses it. A lower score alone is not a v1
  suppression condition, so this case explicitly supplies the acceptance.
* `accept_active_hold`: held activation stays pending and undelivered.
* `accept_lapse`: date lapse delivers new match plus acceptance-lapsed reason.
* `accept_removal`: removing a hold releases it at its rescheduled digest.
* `accept_kev_override`: KEV overrides the active hold, retaining acceptance detail.
* `reload_ordinary_suppression`: changing version out of range after delivery
  clears the pair silently, without a correction event.
* `reload_revision_correction`: a clear record stored during evaluation failure
  is rematched at startup with an old matching revision; correction closes episode 1.
* `reload_alias_change`: alias-file change and a watch edit to the equivalent
  invented name preserve the affected episode and update evidence metadata.
* `reload_retry`: failed forced revision reload persists work; later watchlist
  retry retains revision-correction policy and delivers the closing correction.
* `correction_delivered_rejected_no_affected`: reviewer regression; rejection
  removes the affected array entirely. Delivered watch gets correction/episode 2;
  the queued never-delivered watch closes without a correction.
* `correction_never_delivered`: activation is held behind outage, rejected with
  no affected entries, then notifier recovers; no match or correction delivers.
* `correction_pending_reactivation`: a pending correction survives as its own
  reason while episode 2 reactivates; intermediate queue state is frozen too.
* `correction_affected_unknown_unaffected`: delivered affected, unknown, then
  explicit unaffected; unknown preserves episode 1, closing increments once.
* `multi_exact_unaffected_product_only`: exact unaffected defeats a product-only
  affected entry, producing high-confidence unaffected and no notification.
* `multi_unaffected_malformed`: malformed parent version fields block exclusion,
  producing medium-confidence unknown rather than unaffected.
* `multi_differing_states`: two exact entries disagree; affected wins and the
  winning entry supplies v1 evidence text.
* `multi_differing_evidence_confidence`: medium-confidence unknown and
  high-confidence affected entries coexist; v1 selects the affected entry's
  state, evidence and confidence together.

Owned-shell tests and migration
-------------------------------

`tests/test_r11_shells.py` supplies seven separate assertions: legacy one-column
reset followed by owned-table persistence across an actual database reopen;
then shared-CVE ownership, acceptance omitting old identities, and withdrawal,
each through both `write_evidence` and `AdapterStore.commit_staged`.
The latter uses a no-op record callback to isolate its own clear site. Quarantine
setup still traverses the real validator, persistence and unknown-shell callback.
Two records use distinct source IDs with the same CVE.

R11.4 deliberately resets the unreleased one-column table: drop old markers,
create `(source, source_id, identity)` with that composite primary key. Markers
reappear on the next quarantine observation; v0.1.x never had this table. Owned
markers must survive restart. Only their owner can clear them on acceptance,
including omitted identities. Withdrawal retains them. On `54fb2a4`, migration
fails because the table still has one column. This is the explicitly authorized
schema/design failure; the six other failures demonstrate incorrect visible
marker lifecycle, rather than a missing API.

Pre-rebuild evidence
--------------------

The scratch run overlays only `.build/v11/pre-rebuild-src/src` onto a copy of
these tests and tools. The old logic must show observable cohort regressions,
including the rejected-record correction, rather than failing solely for missing
routing APIs. Missing public route observations are also explicit failures.
Shell cases assert owned migration, shared ownership, omitted identities and
withdrawal at both acceptance sites. Acceptance tests use `pending=False`, so
`CORNICEN_R11_PENDING` cannot hide regressions.

Harness fix continuation
------------------------

The plain rejected-record run independently requires the permanent event key
`service|CVE-2099-1001|correction|1`. Existing frozen values remain unchanged.
Temporary databases and captures use `tempfile.gettempdir()`.
The harness has evolved since the historical provenance hash; regeneration
continues to compare pinned source/input hashes and all observable bytes, while
allowing the harness and generator's historical hashes to differ.

### Advisory evidence migration

The advisory evaluator consumes scoped verdicts from the CNA resolver. Routing
is per watch: matching adapter evidence or a matching same-record sibling uses
the advisory path; existing advisory pairs retain that path through retraction.
Per-pair owner history is retained in `meta` under `advisory_history:` keys,
separately from current `advisory_support` membership. This distinguishes a
removed association or unexplained disappearance from an explicit withdrawal.
It also keeps unrelated CNA-only watches on the original v1 path.

The unreleased one-column `advisory_shells` table is dropped and recreated with
primary key `(source, source_id, identity)`. Old markers cannot establish their
owner and are reset; markers reappear on the next quarantine observation.
Owned markers persist across restart. Acceptance clears only the accepting
record's markers, including omitted identities, at both evidence-write and
staged-commit sites. Withdrawn revisions never clear markers. No v0.1.x table
receives a new column.
