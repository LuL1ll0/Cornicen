"""Shareable TOML settings with ntfy secrets supplied separately."""

from collections.abc import Mapping
from dataclasses import dataclass, field
import math
import os
from pathlib import Path
import re
import tomllib
import unicodedata
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from cornicen import __version__


# Compressed transfer budgets, in bytes and total elapsed seconds.
DOWNLOAD_BUDGETS = {
    'cvelist_snapshot': {'max_bytes': 2 * 1024**3, 'deadline_seconds': 45 * 60},
    'cvelist_delta': {'max_bytes': 200 * 1024**2, 'deadline_seconds': 5 * 60},
    'kev': {'max_bytes': 20 * 1024**2, 'deadline_seconds': 5 * 60},
    'epss': {'max_bytes': 64 * 1024**2, 'deadline_seconds': 5 * 60},
}


def download_budgets(overrides):
    if not isinstance(overrides, dict) or overrides.keys() - DOWNLOAD_BUDGETS.keys():
        raise ValueError('download_budgets must name known source budgets')
    result = {name: values.copy() for name, values in DOWNLOAD_BUDGETS.items()}
    for name, values in overrides.items():
        if not isinstance(values, dict) or values.keys() - result[name].keys():
            raise ValueError('download_budgets only accepts max_bytes and deadline_seconds')
        for key, value in values.items():
            if type(value) is not int or value <= 0:
                raise ValueError(f'download_budgets.{name}.{key} must be a positive integer')
            result[name][key] = value
    return result


class SecretToken:
    __slots__ = ("_value",)

    def __init__(self, value: str):
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "***"

    __str__ = __repr__


def _has_control(value: str) -> bool:
    return any(unicodedata.category(char) == "Cc" for char in value)


@dataclass(frozen=True)
class Config:
    db_path: str
    watchlist_path: Path
    aliases_path: Path | None
    ntfy_url: str
    ntfy_topic: str
    ntfy_token: SecretToken | None = field(repr=False)
    epss_threshold: float = 0.10
    digest_time: str = "08:00"
    timezone: str = "UTC"
    overdue_minutes: int = 60
    user_agent: str = f"Cornicen/{__version__} (+https://github.com/<owner>/cornicen)"
    user_agent_overrides: dict[str, str] = field(default_factory=dict)
    retention_days: int = 365
    allow_shared_token_file: bool = False
    notifier: str = "ntfy"
    notification_path: Path = Path("/data/notifications.jsonl")
    download_budgets: dict[str, dict[str, int]] = field(default_factory=lambda: download_budgets({}))
    accept_warn_days: int = 180


def load_config(path: Path, env: Mapping[str, str]) -> Config:
    try:
        with path.open("rb") as source:
            settings = tomllib.load(source)
    except (tomllib.TOMLDecodeError, RecursionError) as error:
        raise ValueError("Invalid configuration TOML") from None

    def check_secrets(value):
        if isinstance(value, dict):
            for key, nested in value.items():
                if key != "allow_shared_token_file" and any(word in key.casefold() for word in ("token", "secret", "password")):
                    raise ValueError("Secrets are forbidden in TOML; use CORNICEN_NTFY_TOKEN "
                                     "or CORNICEN_NTFY_TOKEN_FILE")
                check_secrets(nested)
        elif isinstance(value, list):
            for nested in value:
                check_secrets(nested)

    try:
        check_secrets(settings)
    except RecursionError:
        raise ValueError("Configuration nesting is too deep") from None
    allowed = set(Config.__dataclass_fields__) - {"ntfy_token"} | {"owner"}
    unknown = settings.keys() - allowed
    if unknown:
        raise ValueError(f"unknown configuration keys: {', '.join(sorted(unknown))}")
    budgets = download_budgets(settings.get('download_budgets', {}))

    def string(key, default):
        value = settings.get(key, default)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{key} must be a nonempty string")
        return value

    threshold = settings.get("epss_threshold", 0.10)
    if (type(threshold) not in (float, int) or not math.isfinite(threshold)
            or not 0 <= threshold <= 1):
        raise ValueError("epss_threshold must be between 0 and 1")
    digest = string("digest_time", "08:00")
    if not re.fullmatch(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]", digest):
        raise ValueError("digest_time must be HH:MM")
    timezone = string("timezone", "UTC")
    try:
        ZoneInfo(timezone)
    except (ValueError, ZoneInfoNotFoundError):
        raise ValueError("timezone must name a known time zone") from None
    for key, default in (("overdue_minutes", 60), ("retention_days", 365), ("accept_warn_days", 180)):
        value = settings.get(key, default)
        if type(value) is not int or value <= 0:
            raise ValueError(f"{key} must be a positive integer")
    overrides = settings.get("user_agent_overrides", {})
    if not isinstance(overrides, dict) or any(
            not isinstance(k, str) or not isinstance(v, str) or not k or not v
            for k, v in overrides.items()):
        raise ValueError("user_agent_overrides must map hosts to strings")
    if any(_has_control(k) or _has_control(v) for k, v in overrides.items()):
        raise ValueError("user_agent_overrides must not contain control characters")
    aliases = Path(string("aliases_path", "")) if "aliases_path" in settings else None
    owner = string("owner", "<owner>")
    user_agent = string("user_agent", f"Cornicen/{__version__} (+https://github.com/{owner}/cornicen)")
    if _has_control(owner) or _has_control(user_agent):
        raise ValueError("owner and user_agent must not contain control characters")
    ntfy_url = string("ntfy_url", "https://ntfy.sh")
    try:
        url = urlsplit(ntfy_url)
        valid_url = (url.scheme in {"http", "https"} and bool(url.hostname)
                     and url.username is None and url.password is None
                     and '?' not in ntfy_url and '#' not in ntfy_url
                     and not any(char.isspace() for char in ntfy_url)
                     and not _has_control(ntfy_url))
    except ValueError:
        valid_url = False
    if not valid_url:
        raise ValueError("ntfy_url must be http or https with a host and no userinfo, query or fragment")
    notifier = string("notifier", "ntfy")
    if notifier not in {"ntfy", "file"}:
        raise ValueError("notifier must be ntfy or file")
    notification_path = Path(string("notification_path", "/data/notifications.jsonl"))
    allow_shared = settings.get('allow_shared_token_file', False)
    if type(allow_shared) is not bool:
        raise ValueError('allow_shared_token_file must be a boolean')
    token = env.get("CORNICEN_NTFY_TOKEN") or None
    if token is None and env.get("CORNICEN_NTFY_TOKEN_FILE"):
        try:
            with Path(env['CORNICEN_NTFY_TOKEN_FILE']).open(encoding='utf-8') as source:
                if os.fstat(source.fileno()).st_mode & 0o077 and not allow_shared:
                    raise ValueError('Token file permissions must be 0600; shared access requires allow_shared_token_file')
                token = source.read().strip() or None
        except (OSError, UnicodeError):
            raise ValueError("Cannot read CORNICEN_NTFY_TOKEN_FILE") from None
    if token is not None:
        token = token.strip()
        if any(char.isspace() for char in token) or _has_control(token):
            raise ValueError("Invalid ntfy token: whitespace and control characters are forbidden")
        token = SecretToken(token) if token else None
    return Config(
        db_path=string("db_path", "/data/cornicen.db"),
        watchlist_path=Path(string("watchlist_path", "/config/watchlist.toml")),
        aliases_path=aliases,
        ntfy_url=ntfy_url,
        ntfy_topic=string("ntfy_topic", "cornicen"),
        ntfy_token=token, epss_threshold=float(threshold), digest_time=digest,
        timezone=timezone, overdue_minutes=settings.get("overdue_minutes", 60),
        user_agent=user_agent, user_agent_overrides=overrides,
        retention_days=settings.get("retention_days", 365),
        notifier=notifier, notification_path=notification_path, allow_shared_token_file=allow_shared,
        download_budgets=budgets, accept_warn_days=settings.get("accept_warn_days", 180),
    )
