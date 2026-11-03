"""Version precedence and conservative, three-valued constraint evaluation."""

from enum import Enum
from itertools import zip_longest
import re


class Scheme(str, Enum):
    SEMVER = "semver"
    DOTTED = "dotted"
    DEBIAN = "debian"
    OPAQUE = "opaque"


_SEMVER = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
)
_DOTTED = re.compile(r"[0-9]+(?:\.[0-9]+)*")
_CONSTRAINT = re.compile(r"(>=|<=|=|>|<)\s*([^\s,=<>!|]+)")


def _sign(a, b):
    return (a > b) - (a < b)


def _numeric(a, b):
    # Comparing decimal strings avoids an integer-size limit on valid versions.
    a, b = a.lstrip("0"), b.lstrip("0")
    return _sign(len(a), len(b)) or _sign(a, b)


def _semver(version):
    match = _SEMVER.fullmatch(version)
    if match is None:
        return None
    major, minor, patch, prerelease, _ = match.groups()
    identifiers = prerelease.split(".") if prerelease is not None else ()
    if any(p.isascii() and p.isdigit() and len(p) > 1 and p[0] == "0"
           for p in identifiers):
        return None
    return (major, minor, patch), identifiers


def _compare_semver(a, b):
    a, b = _semver(a), _semver(b)
    if a is None or b is None:
        return None
    for x, y in zip(a[0], b[0]):
        result = _numeric(x, y)
        if result:
            return result
    ap, bp = a[1], b[1]
    if not ap or not bp:
        return _sign(not ap, not bp)
    for x, y in zip(ap, bp):
        if x.isdigit() and y.isdigit():
            result = _numeric(x, y)
        elif x.isdigit() != y.isdigit():
            result = -1 if x.isdigit() else 1
        else:
            result = _sign(x, y)
        if result:
            return result
    return _sign(len(ap), len(bp))


def _debian(version):
    epoch = "0"
    if ":" in version:
        epoch, version = version.split(":", 1)
        if not re.fullmatch(r"[0-9]+", epoch):
            return None
    if "-" in version:
        upstream, revision = version.rsplit("-", 1)
        if not re.fullmatch(r"[0-9A-Za-z+.~]+", revision):
            return None
    else:
        upstream, revision = version, "0"
    if not re.fullmatch(r"[0-9][0-9A-Za-z.+:~-]*", upstream):
        return None
    return epoch, upstream, revision


def _debian_order(char):
    if char == "~":
        return -1
    if not char or char.isdigit():
        return 0
    if char.isalpha():
        return ord(char)
    return ord(char) + 256


def _debian_part(a, b):
    i = j = 0
    while i < len(a) or j < len(b):
        while ((i < len(a) and not a[i].isdigit())
               or (j < len(b) and not b[j].isdigit())):
            x = a[i] if i < len(a) else ""
            y = b[j] if j < len(b) else ""
            result = _sign(_debian_order(x), _debian_order(y))
            if result:
                return result
            i += i < len(a)
            j += j < len(b)
        start_a, start_b = i, j
        while i < len(a) and a[i].isdigit():
            i += 1
        while j < len(b) and b[j].isdigit():
            j += 1
        result = _numeric(a[start_a:i], b[start_b:j])
        if result:
            return result
    return 0


def compare(a: str, b: str, scheme: Scheme) -> int | None:
    """Return precedence, or None for invalid or undecidable versions.

    Dotted versions pad missing trailing segments with zeros.
    """
    if scheme == Scheme.OPAQUE:
        return 0 if a == b else None
    if scheme in (Scheme.SEMVER, Scheme.DOTTED):
        a = a[1:] if a.startswith(("v", "V")) else a
        b = b[1:] if b.startswith(("v", "V")) else b
    if scheme == Scheme.SEMVER:
        return _compare_semver(a, b)
    if scheme == Scheme.DOTTED:
        if not _DOTTED.fullmatch(a) or not _DOTTED.fullmatch(b):
            return None
        ap, bp = a.split("."), b.split(".")
        for x, y in zip_longest(ap, bp, fillvalue="0"):
            result = _numeric(x, y)
            if result:
                return result
        # Padding may decide an order, never an equality: "1.2" vs "1.2.0" is unknown.
        return 0 if len(ap) == len(bp) else None
    if scheme == Scheme.DEBIAN:
        ap, bp = _debian(a), _debian(b)
        if ap is None or bp is None:
            return None
        return (_numeric(ap[0], bp[0]) or _debian_part(ap[1], bp[1])
                or _debian_part(ap[2], bp[2]))
    return None


def parse_constraint(text: str) -> tuple[tuple[str, str], ...]:
    """Parse a nonempty comma-separated conjunction of explicit comparators."""
    result = []
    for part in text.split(","):
        match = _CONSTRAINT.fullmatch(part.strip())
        if match is None:
            raise ValueError(f"Invalid version constraint: {text!r}")
        result.append(match.groups())
    return tuple(result)


def satisfies(version: str, constraint: tuple[tuple[str, str], ...],
              scheme: Scheme) -> bool | None:
    """Evaluate a conjunction; a false term decides even with unknown terms."""
    unknown = False
    for op, bound in constraint:
        if op not in ("=", ">=", ">", "<=", "<"):
            raise ValueError(f"Invalid constraint operator: {op!r}")
        result = compare(version, bound, scheme)
        if result is None or (scheme == Scheme.OPAQUE and op != "="):
            unknown = True
            continue
        matches = {"=": result == 0, ">=": result >= 0, ">": result > 0,
                   "<=": result <= 0, "<": result < 0}
        if not matches[op]:
            return False
    return None if unknown else True
