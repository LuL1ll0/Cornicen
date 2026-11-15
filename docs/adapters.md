# Adapter foundation (v0.2.0)

This release supplies the shared adapter storage and evaluation machinery.
Every production release gate is unmet and the production registry contains
no factories. An installation setting can never bypass a release gate; no
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
Audits become due at seven days and unhealthy strictly after seven days.

The schema adds eighteen tables without changing v1 columns. The
[replay harness notes](../tests/replay_v11/README.md) document crash injection,
the exact v1 projection, offline checks and known limits. Delivery remains
at-least-once: a crash after sending but before recording acknowledgement can
duplicate delivery ([design spec §1](spec.md#1-design-goals)).
