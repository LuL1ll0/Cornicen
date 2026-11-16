# Adapter foundation (v0.2.0)

This release supplies the shared adapter storage and evaluation machinery.
Every production release gate is unmet and production factories remain inactive. An installation setting can never bypass a release gate; no
ineffective adapter is constructed, polled, audited, retried or transported.
The GitHub setting defaults on, but its advisory adapter remains disabled.

Adapters must validate raw resources before accepting evidence. Intact
containers permit independent, idempotent record commits: a bad member is
quarantined and holds the completeness cursor without discarding valid members.
Accepted manifests and their cursor advance atomically. Initial enumeration
pins source-local baseline membership; it does not suppress another source's
new evidence. Rebaseline preserves events and pending alerts, acknowledges
existing gaps, and cannot erase historical loss.

Evidence carries product, release and platform scope. Same-scope authoritative
CNA verdicts decide; conflicting adapter evidence aggregates conservatively.
Withdrawal removes only its source's support; disappearance is not withdrawal.
Product-only matches remain UNKNOWN, including scoped verdicts in another scope.
Fixes require supporting evidence in the matching scope. Episodes retain an
affected latch until aggregate unaffected evidence closes them.

Explicit identity links merge current episodes, latches and pending reasons
atomically, preserving old event keys. Only acknowledged deliveries transfer
coverage. Splits inherit coverage only for explicitly associated watch scopes;
distinct CVEs never merge. Facet numbers remain permanent across revisions.

Fetch, completeness, publication freshness and audit timeliness are independent
health dimensions. Every completed, intact unconditional HTTP 200 resets its
resource audit timestamp, including content that later fails validation.
Audits become due at seven days. Independent sources become unhealthy at seven
days; shared sources become unhealthy strictly after seven days.

The schema adds eighteen tables without changing v1 columns. The
[replay harness notes](../tests/replay_v11/README.md) document crash injection,
the exact v1 projection, offline checks and known limits. Delivery remains
at-least-once: a crash after sending but before recording acknowledgement can
duplicate delivery ([design spec §1](spec.md#1-design-goals)).

## GitHub repository advisories

Gate G remains not met in 0.4.0. No transport is constructed while disabled.
Explicit watch selectors consent to repository enumeration. The adapter sends
unconditional listings, checks two consecutive traversals, and reconciles missing
members with details. Local limits are 30 requests per cycle and 60 per rolling
hour, shared across repositories; these cannot guarantee GitHub's shared IP budget.
Each repository has independent coverage, retries and a seven-day audit clock.

## Microsoft CSAF

Microsoft CSAF is off until gate M. Gate M remains **not met** in 0.4.0;
turning the installation setting on cannot construct or poll this adapter.
Offline invented scenarios provide test coverage, not inventory conformance
evidence or permission to enable the source.

When enabled after the gate is met, it downloads provider metadata and the
complete advisories changes.csv listing, then every listed advisory, whatever
the watch list. Requests disclose only the host IP and an interest in Microsoft;
no watch identity or installed version is sent. The separate vex distribution
is never fetched. Metadata expires after 24 hours. Every redirect is restricted
to the metadata, listing and safe advisory paths on msrc.microsoft.com.

Sequential local limits are 200 requests per cycle and 400 per rolling hour,
including metadata, listings and redirects. Record admission leaves one request
of budget unused. These ceilings do not guarantee the publisher's shared IP
allowance. A 403 or 429 holds further requests; per-path failures and backoff
persist across cycles. A 9,056-record bootstrap takes about 46 hourly cycles.

The first clean, nonempty listing pins bootstrap paths. Their accepted or
quarantined members remain baseline even when a later retry repairs them.
New paths are incremental after the first container. The adapter streams one
container from its durable cache each cycle. Changed timestamp sets, including
ties and regressions, trigger unconditional transfers; unchanged paths refresh
at six days. Audit health fails at seven days since the last intact transfer,
or first observation for a path that has never succeeded.

Invalid listing rows retain earlier membership and hold the cursor. Record
failures keep usable members while holding coverage; HTTP errors classify the
run FAILED, other transfer failures PARTIAL. Disappearances record a separate
gap for each path and episode, preserving evidence. Explicit rebaseline can
acknowledge absence and restore current completeness, but historical coverage
remains unhealthy for the acknowledged gap. Conflicting raw documents sharing
an ID are quarantined; identical copies are emitted once.
