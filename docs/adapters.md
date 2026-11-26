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

Gate G remains not met in 0.5.0. No transport is constructed while disabled.
Explicit watch selectors consent to repository enumeration. The adapter sends
unconditional listings, checks two consecutive traversals, and reconciles missing
members with details. Local limits are 30 requests per cycle and 60 per rolling
hour, shared across repositories; these cannot guarantee GitHub's shared IP budget.
Each repository has independent coverage, retries and a seven-day audit clock.

## Microsoft CSAF

Microsoft CSAF is off until gate M. Gate M remains **not met** in 0.5.0;
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

## Cisco CSAF

Cisco CSAF is off until gate C. Gate C remains **not met** in 0.5.0;
turning the installation setting on cannot construct or poll the adapter.
The offline fixtures use invented identities and do not establish publisher
conformance or permission to enable it.

Once enabled after the gate, it downloads provider metadata, changes.csv,
index.txt and every advisory in the union of the two listings, whatever the
watch list. Requests disclose only the host IP and an interest in Cisco;
watch identities, installed builds and platforms are never sent. Requests and
redirects are restricted to the metadata, listings and safe year/advisory paths
under `https://www.cisco.com/.well-known/csaf/`. No credentials are used.

The shared directory adapter applies sequential limits of 200 requests per
cycle and 400 per rolling hour, including metadata, both listings and redirects,
with one request left unused for record admission. Metadata expires after
24 hours, unchanged records refresh after six days, and audit health fails at
seven days. Bootstrap membership, persistent retries, quarantine, duplicate-ID
conflicts and coverage gaps follow the Microsoft rules above. No missing product
reference is repaired in production: the captured dangling reference quarantines
that member, preserves its prior evidence and holds the completeness cursor.

Both listings must succeed before either is observed. An index-only path has an
empty timestamp set and is downloaded; timestamp ties, regressions and duplicate
paths retain the full timestamp set and cause at most one fetch per path per
cycle. Removal requires absence from both fully valid listings. Invalid rows
block removal and hold the cursor. When both listings have no invalid rows,
`cisco:conformance` records the tick and the `changes_only` and `index_only`
counts. A mismatch fails gate conformance; it does not change poll classification,
coverage, health or the completeness cursor.

Direct component assertions ignore the watch platform. Supported `installed_on`
relationship assertions require an exact normalised `platform = {vendor = "…",
product = "…"}` match: omission is unknown; a different platform abstains.
Unsupported relationships stay unknown when the component build is covered.
Fixes remain within the same relationship scope; component fixes do not transfer.
See [watch lists](watch-lists.md) for configuration.

Cisco refused a researched custom User-Agent with HTTP 403. A 403 or 429 remains
a rate hold. Gate C must capture an accepted configured User-Agent using the
existing host-keyed `user_agent_overrides` setting (`www.cisco.com`); the adapter
does not substitute a special User-Agent. Full listings and records across two
publication updates, inventory conformance, an outage/rollover replay and Lou's
approval remain required before gate C can be met.

## Debian via OSV

Debian (OSV) is off in v0.8.0: gate D is **not met**. The production
registry's publication clock remains unvalidated, so freshness is unknown
until gate D establishes the export's publication semantics. An individual
OSV query sample cannot satisfy that gate.

When enabled, the adapter downloads the whole Debian OSV export once a day
(about 81.5 MB), whatever the watch list. The bucket operator sees your
IP address and an interest in Debian. Requests carry Cornicen's User-Agent,
which includes its version and the repository URL. No package, watched version
or CVE ID is sent, and there is no query fallback. Discovery reads `ecosystems.txt` and
fetches every listed `Debian` or `Debian:` ecosystem's `all.zip`, including
unwatched releases. Requests are unconditional; durable retry deadlines take
precedence over the daily cadence after failures.

Archives stream through an on-disk merge index. Identical copies deduplicate;
disjoint release projections merge only when their common fields and revision
agree. Conflicts retain prior evidence and hold the cursor; recovery requires
two coherent complete passes in the same cycle. Missing members, ecosystems
or copies never imply withdrawal. `cornicen adapter rebaseline debian`
acknowledges missing coverage; a following poll can publish the remaining
projection. Withdrawals explicitly retract only that record's evidence.

OSV watches use exact ecosystem/source-package selectors and Debian ordering:

```toml
[[watch]]
id = "sample"
name = "Sample package"
match = ["examplecorp:widget"]
version = "93.0.11-1~deb12u1"
scheme = "debian"
osv = [{ecosystem = "Debian:12", package = "examplessl"}]
```

These invented names illustrate the syntax. A DSA listing several CVEs with
shared ranges supplies advisory-level evidence; it does not establish which
listed CVE affects a watch. Distribution backports remain scoped to their
OSV ecosystem/package. Gate D stays unmet pending discovery, full archives,
inventories, duplicate/projection checks across two generations and a proven
publication clock.

## Synology RSS

Synology RSS is off in v0.8.0 because gate S is **not met**. When enabled, it
makes one unconditional GET a day (about 0.5 MB) for the whole security
advisory feed. It never fetches advisory pages. The request discloses your IP
address and an interest in Synology, but nothing about which products you watch.
The production scheduler normally starts a cycle every minute and checks
adapters on each cycle. This gives Synology another chance to fetch promptly
if a tick arrives just before its 24-hour poll interval.

The feed does not provide affected or fixed version ranges. All Synology
applicability evidence is unknown and supplies no fix. `cornicen explain`
shows retained Synology advisories, including recognised products and any
scoped vendor statement. Ordinary unknown pairs can appear in the optional
digest section under `vendor advisory`, a reason shared with other sources.
The existing exploited-unknown exception still applies when a
listed CVE is in KEV and the watched product matches.

Gate S requires a publisher retention contract or a complete archive covering
both new items and revisions, plus at least 30 daily membership and hash
captures with turnover compared against that evidence. The validated minimum
retention must be at least 48 hours, and the configured observation interval
must be no more than half that minimum. Without that evidence, retention
coverage is unknown. Feed overlap alone cannot establish completeness. A
retention gap stays in the historical record even after an operator rebaseline
restores current coverage.
