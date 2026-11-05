"""Validate complete watch lists before callers replace their active list."""

from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
import tomllib
import re

from cornicen.accept import Accept

from cornicen.identity import AliasMap, Identity, _parse_identity, is_placeholder, normalise
from cornicen.versions import Scheme, compare, parse_constraint


@dataclass(frozen=True)
class Watch:
    id: str
    name: str
    match: tuple[Identity, ...]
    product_only: tuple[str, ...]
    version: str
    scheme: Scheme
    eol: bool


class WatchlistError(Exception):
    def __init__(self, problems: list[str]):
        self.problems = problems
        super().__init__("; ".join(problems))


def _string(entry: dict, key: str) -> str:
    value = entry.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{key} must be a nonempty string")
    return value.strip()


def _watch(entry: dict) -> Watch:
    watch_id = _string(entry, "id")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", watch_id):
        raise ValueError("id must match [A-Za-z0-9._-]{1,64}")
    name = _string(entry, "name")
    version = _string(entry, "version")
    try:
        scheme = Scheme(entry.get("scheme"))
    except (ValueError, TypeError):
        raise ValueError("scheme must be semver, dotted, debian, opaque or python") from None
    # Opaque versions may contain spaces ("RomePI 1.0.0.G"); only operators make them a range.
    range_chars = r"[=<>!,~^]" if scheme == Scheme.OPAQUE else r"[=<>!,~^\s]"
    if re.search(range_chars, version):
        bounds = parse_constraint(version)
        if scheme == Scheme.OPAQUE and any(op != "=" for op, _ in bounds):
            raise ValueError("opaque version does not support range operators")
    else:
        bounds = (("=", version),)
    if any(compare(bound, bound, scheme) is None for _, bound in bounds):
        raise ValueError(f"version is invalid for {scheme.value}")
    matches = entry.get("match", [])
    products = entry.get("product_only", [])
    if not isinstance(matches, list) or not isinstance(products, list):
        raise ValueError("match and product_only must be arrays")
    identities = tuple(_parse_identity(value) for value in matches)
    if any(not isinstance(value, str) or is_placeholder(value) for value in products):
        raise ValueError("product_only must contain non-placeholder product strings")
    if not identities and not products:
        raise ValueError("match or product_only must declare at least one identity")
    eol = entry.get("eol", False)
    if not isinstance(eol, bool):
        raise ValueError("eol must be a boolean")
    return Watch(watch_id, name, identities, tuple(map(normalise, products)),
                 version, scheme, eol)


def load_document_text(text: str):
    try:
        document = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, RecursionError) as error:
        raise WatchlistError([f"Invalid watch list TOML: {error}"]) from None
    problems = [f"unknown table [[{key}]] — did you mean [[watch]]?"
                for key in document if key not in {"watch", "accept"}]
    entries = document.get("watch", [])
    if not isinstance(entries, list):
        raise WatchlistError(problems + ["watch must be an array of tables ([[watch]])"])
    watches, seen = [], set()
    for number, entry in enumerate(entries, 1):
        label = f"watch entry {number}"
        if isinstance(entry, dict):
            label += f" ({entry.get('id') or entry.get('name') or 'unnamed'})"
        try:
            if not isinstance(entry, dict):
                raise ValueError("entry must be a table")
            unknown = entry.keys() - {"id", "name", "match", "product_only", "version", "scheme", "eol"}
            if unknown:
                problems.extend(f"{label}: unknown key {key!r}" for key in sorted(unknown))
                continue
            watch = _watch(entry)
            if watch.id.casefold() in seen:
                raise ValueError(f"duplicate id {watch.id!r}")
            seen.add(watch.id.casefold())
            watches.append(watch)
        except ValueError as error:
            problems.append(f"{label}: {error}")
    accepts, pairs = [], set()
    entries = document.get('accept', [])
    if not isinstance(entries, list):
        problems.append('accept entry 1 (no cve/no watch): accept must be an array of tables ([[accept]])')
        entries = []
    for number, entry in enumerate(entries, 1):
        values = entry if isinstance(entry, dict) else {}
        label = f"accept entry {number} ({values.get('cve') or 'no cve'}/{values.get('watch') or 'no watch'})"
        try:
            if not isinstance(entry, dict):
                raise ValueError('accept must be an array of tables ([[accept]])')
            unknown = entry.keys() - {'cve', 'watch', 'reason', 'until', 'until_version_change', 'version'}
            if unknown:
                raise ValueError('unknown key ' + repr(sorted(unknown)[0]))
            cve, watch_id, reason = (_string(entry, key) for key in ('cve', 'watch', 'reason'))
            if not re.fullmatch(r'CVE-\d{4}-\d{4,}', cve, re.IGNORECASE):
                raise ValueError('malformed CVE ID')
            if not re.fullmatch(r'[A-Za-z0-9._-]{1,64}', watch_id):
                raise ValueError('malformed watch id')
            if len(reason) > 200:
                raise ValueError('reason exceeds 200 characters')
            version_change = entry.get('until_version_change', False)
            if type(version_change) is not bool:
                raise ValueError('until_version_change must be a boolean')
            until = entry.get('until')
            if 'until' in entry:
                if isinstance(until, str):
                    if not re.fullmatch(r'\d{4}-\d{2}-\d{2}', until):
                        raise ValueError('until must be a date')
                    try:
                        until = date.fromisoformat(until)
                    except ValueError:
                        raise ValueError('until must be a date') from None
                if not isinstance(until, date) or isinstance(until, datetime):
                    raise ValueError('until must be a date')
            if until is None and not version_change:
                raise ValueError('no lapse condition')
            if 'version' in entry and not version_change:
                raise ValueError('version requires until_version_change = true')
            version = _string(entry, 'version') if version_change else None
            pair = cve.upper(), watch_id.casefold()
            if pair in pairs:
                raise ValueError('duplicate cve/watch pair')
            pairs.add(pair)
            accepts.append(Accept(cve.upper(), watch_id, reason, until, version_change, version, number))
        except ValueError as error:
            problems.append(f'{label}: {error}')
    if problems:
        raise WatchlistError(problems)
    return tuple(watches), tuple(accepts)


def load_document(path: Path):
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise WatchlistError([f"Cannot read watch list: {error}"]) from None
    return load_document_text(text)


def load_watchlist_text(text: str) -> tuple[Watch, ...]:
    return load_document_text(text)[0]


def load_watchlist(path: Path) -> tuple[Watch, ...]:
    return load_document(path)[0]


def collisions(watches, aliases: AliasMap | None = None) -> list[str]:
    """Report exact identities and explicit loose product claims that overlap."""
    watches = tuple(watches)
    reports = []
    for index, left in enumerate(watches):
        for right in watches[index + 1:]:
            left_ids = (set().union(*(aliases.expand(i) for i in left.match))
                        if aliases is not None else set(left.match))
            right_ids = (set().union(*(aliases.expand(i) for i in right.match))
                         if aliases is not None else set(right.match))
            exact = left_ids & right_ids
            loose = (set(left.product_only) & set(right.product_only)
                     | set(left.product_only) & {p for _, p in right_ids}
                     | set(right.product_only) & {p for _, p in left_ids})
            claims = sorted(f"{v}:{p}" for v, p in exact) + sorted(loose)
            if claims:
                reports.append(f"{left.id} and {right.id} claim {', '.join(claims)}")
    return reports
