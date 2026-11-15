# script-purpose: Scoped CNA verdicts built on the unchanged v1 applicability resolver (R11).
# script-class: pipeline-tool
# script-trigger: Engine advisory evaluation and explain.
# script-tests: tests/test_f3a.py, tests/test_r11_differential.py, tests/test_r11_integration.py
"""Read CNA records and return scoped verdicts without writes or process exit codes.

Kept outside applicability.py so pinned matching sources remain byte-identical.
"""

from dataclasses import dataclass

from cornicen.applicability import State, _identity_match, rejected, resolve
from cornicen.identity import normalise_identity


@dataclass(frozen=True)
class ScopedVerdict:
    release: str | None
    package: str
    platform: str | None
    scheme: str
    state: State
    authoritative: bool
    evidence: str
    confidence: str


def scoped_verdicts(record, watch, aliases):
    """Read a CNA record; return verdicts without writes or process exit codes.

    Group matching entries by scope, then use the unchanged resolver so its
    multi-entry precedence, malformed-entry handling and evidence selection
    remain the sole CNA interpretation. Rejection retracts all CNA scopes.
    """
    if not isinstance(record, dict) or rejected(record):
        return ()
    metadata = record.get('cveMetadata', {})
    if isinstance(metadata, dict) and str(metadata.get('state', '')).upper() == 'WITHDRAWN':
        return ()
    containers = record.get('containers', {})
    cna = containers.get('cna', {}) if isinstance(containers, dict) else {}
    entries = cna.get('affected', []) if isinstance(cna, dict) else []
    groups = {}
    for entry in entries if isinstance(entries, list) else ():
        if not isinstance(entry, dict):
            continue
        kind = _identity_match(entry.get('vendor', ''), entry.get('product', ''), watch, aliases)
        if not kind:
            continue
        identity = (normalise_identity(entry.get('vendor', '')),
                    normalise_identity(entry.get('product', '')))
        expanded = aliases.expand(identity)
        package = ':'.join(min(expanded) if expanded else identity)
        release, platform = entry.get('release'), entry.get('platform')
        # Malformed optional scope fields all mean unscoped, as does absence.
        release = release if isinstance(release, str) else None
        platform = platform if isinstance(platform, str) else None
        key = release, package, platform, watch.scheme.value
        groups.setdefault(key, []).append(entry)
    verdicts = []
    for scope, entries in groups.items():
        scoped = dict(record, containers=dict(containers, cna=dict(cna, affected=entries)))
        result = resolve(scoped, None, watch, aliases)
        verdicts.append(ScopedVerdict(*scope, result.state,
            result.confidence == 'high' and result.state != State.UNKNOWN,
            result.evidence, result.confidence))
    return tuple(verdicts)
