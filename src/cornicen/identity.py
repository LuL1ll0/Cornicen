"""Exact, normalised identities and versioned spelling equivalences."""

from importlib.resources import files
from pathlib import Path
import json
import tomllib
import re
import unicodedata
from hashlib import sha256


from cornicen.diagnostics import read_text, toml_error


Identity = tuple[str, str]


def normalise(s: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", s).casefold().split())


def is_placeholder(s: str) -> bool:
    s = re.sub(r"[\u200b-\u200d\ufeff]", "", s)
    core = re.sub(r"[\W_]+", "", normalise(s))
    return core in {"", "na", "unknown", "none", "null", "tbd", "unspecified",
                    "notapplicable", "notavailable"}


def _parse_identity(text: str) -> Identity:
    if not isinstance(text, str) or text.count(":") != 1:
        raise ValueError("identity must be vendor:product")
    vendor, product = map(normalise, text.split(":"))
    if is_placeholder(vendor) or is_placeholder(product):
        raise ValueError("identity must not contain a placeholder vendor or product")
    return vendor, product


class AliasMap:
    def __init__(self, version: str = "none"):
        self.version = version
        self.warnings: list[str] = []
        self._links: dict[Identity, set[Identity]] = {}

    def fingerprint(self) -> str:
        """Hash effective equivalence groups, independent of version and file order."""
        groups = {tuple(sorted(self.expand(identity))) for identity in self._links}
        canonical = json.dumps(sorted(group for group in groups if len(group) > 1),
                               separators=(',', ':'))
        return sha256(canonical.encode()).hexdigest()

    def expand(self, i: Identity) -> frozenset[Identity]:
        if not isinstance(i, tuple) or len(i) != 2 or any(not isinstance(p, str) for p in i):
            raise ValueError("identity must be a 2-tuple of strings")
        identity = tuple(normalise(part) for part in i)
        if any(is_placeholder(part) for part in identity):
            return frozenset()
        found = set()
        pending = [identity]
        while pending:
            current = pending.pop()
            if current not in found:
                found.add(current)
                pending.extend(self._links.get(current, ()))
        return frozenset(found)

    @classmethod
    def load(cls, builtin: bool = True, extra: Path | None = None) -> "AliasMap":
        """Read version plus [[alias]] groups with vendor:product identities.

        Local groups extend the built-in graph; both versions identify the map.
        """
        sources = []
        if builtin:
            sources.append(("builtin", files("cornicen").joinpath("data/aliases.toml")))
        if extra is not None:
            sources.append(("aliases_path", extra))
        result = cls()
        versions = []
        builtin_groups = {}
        for source_index, (source_name, source) in enumerate(sources):
            text = read_text(source, source_name)
            try:
                document = tomllib.loads(text)
            except (tomllib.TOMLDecodeError, RecursionError) as error:
                raise ValueError(toml_error(source_name, error, text)) from None
            version = document.get("version")
            if not isinstance(version, str) or not version.strip():
                raise ValueError(f"{source_name} alias map requires a nonempty version")
            versions.append(f"{version}-{sha256(text.encode('utf-8')).hexdigest()[:8]}")
            groups = document.get("alias", [])
            if not isinstance(groups, list):
                raise ValueError(f"{source_name} alias map requires alias groups")
            for group_number, group in enumerate(groups, 1):
                members = group.get("identities") if isinstance(group, dict) else None
                if not isinstance(members, list) or len(members) < 2:
                    raise ValueError(f"{source_name} alias group {group_number}: requires at least two identities")
                try:
                    identities = {_parse_identity(member) for member in members}
                except ValueError as error:
                    raise ValueError(f"{source_name} alias group {group_number}: {error}") from None
                if source_name != "builtin":
                    # Follow earlier local links as well, so indirect bridges warn too.
                    components = {builtin_groups[member]
                                  for identity in identities for member in result.expand(identity)
                                  if member in builtin_groups}
                    already_connected = any(
                        components <= {builtin_groups[member] for member in result.expand(identity)
                                       if member in builtin_groups}
                        for identity in identities)
                    if len(components) > 1 and not already_connected:
                        result.warnings.append(
                            f"{source_name}: alias group {group_number} merges separate built-in groups")
                for identity in identities:
                    result._links.setdefault(identity, set()).update(identities)
            if builtin and source_index == 0:
                builtin_groups = {identity: result.expand(identity) for identity in result._links}
        result.version = "+".join(versions) if versions else "none"
        return result
