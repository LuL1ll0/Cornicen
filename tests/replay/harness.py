"""Replay only public interfaces; no matching or delivery policy lives here."""

from contextlib import nullcontext
from dataclasses import replace
from unittest.mock import patch
import json
from datetime import date, datetime, timezone
from pathlib import Path
import tomllib

from cornicen.model import FetchStatus, IngestResult, Notification, Origin


SCENARIOS = Path(__file__).parent


def utc(text: str) -> datetime:
    value = datetime.fromisoformat(text)
    if value.tzinfo is None or value.utcoffset().total_seconds() != 0:
        raise ValueError(f"Expected an ISO UTC timestamp: {text}")
    return value


def as_ingest(fields: dict) -> IngestResult:
    fields = dict(fields)
    fields["status"] = FetchStatus(fields["status"])
    fields["origin"] = Origin(fields["origin"])
    if fields.get("content_time") is not None:
        fields["content_time"] = utc(fields["content_time"])
    if fields.get("epss_date") is not None:
        fields["epss_date"] = date.fromisoformat(fields["epss_date"])
    fields["records"] = tuple(fields.get("records", ()))
    fields["errors"] = tuple(fields.get("errors", ()))
    if fields.get("epss") is not None:
        fields["epss"] = {key: tuple(value) for key, value in fields["epss"].items()}
    return IngestResult(**fields)


def read_jsonl(path: Path) -> list[dict]:
    rows = []
    for number, line in enumerate(path.read_text().splitlines(), 1):
        try:
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError("Expected a JSON object")
        except ValueError as error:
            raise ValueError(f"{path.name}:{number}: {error}") from error
        if number == 1 and set(row) == {"#"}:
            continue
        if "#" in row:
            raise ValueError(f"{path.name}:{number}: comment is only allowed as the first row")
        rows.append(row)
    return rows


def load_timeline(name: str) -> list[dict]:
    path = SCENARIOS / f"{name}.input.jsonl"
    rows = read_jsonl(path)
    if not rows or "watchlist" not in rows[0]:
        raise ValueError(f"{name}: first row must set the watch list")
    pending = False
    cycles = 0
    offset = len(path.read_text().splitlines()) - len(rows)
    previous = None
    for number, row in enumerate(rows, 1 + offset):
        now = utc(row["t"])
        if name not in ("replay_twice_idempotent", "clock_rewind_unhealthy") and previous is not None and now < previous:
            raise ValueError(f"{path.name}:{number}: t must be non-decreasing")
        previous = now
        actions = set(row) - {"t"}
        if len(actions) != 1:
            raise ValueError(f"{name}: each row must have exactly one action")
        action = actions.pop()
        if action == "ingest":
            as_ingest(row[action])
            pending = True
        elif action == "watchlist":
            tomllib.loads(row[action])
        elif action == "notifier":
            if row[action] not in ("up", "down"):
                raise ValueError(f"{name}: invalid notifier state")
        elif action == "pairs" and isinstance(row[action], list):
            pass
        elif action == "evaluation_failure" and isinstance(row[action], bool):
            pass
        elif action == "retention_days" and isinstance(row[action], int):
            pass
        elif action == "restart" and row[action] is True:
            if pending:
                raise ValueError(f"{name}: restart must follow a committed cycle")
        elif action == "cycle" and row[action] is True:
            pending = False
            cycles += 1
        else:
            raise ValueError(f"{name}: invalid action {action}")
    if pending or not cycles:
        raise ValueError(f"{name}: ingests must be consumed by a cycle")
    return rows


def load_expected(name: str) -> list[dict]:
    rows = read_jsonl(SCENARIOS / f"{name}.expected.jsonl")
    for row in rows:
        if set(row) != {"t", "watch", "record", "reasons", "urgency"}:
            raise ValueError(f"{name}: invalid expected notification fields")
        utc(row["t"])
        if row["urgency"] not in ("urgent", "normal", "health"):
            raise ValueError(f"{name}: invalid expected urgency")
        if not isinstance(row["reasons"], list):
            raise ValueError(f"{name}: reasons must be a list")
    return rows


class FakeClock:
    def __init__(self, now: datetime):
        self.now = now

    def __call__(self) -> datetime:
        return self.now


class RecordingNotifier:
    def __init__(self, clock: FakeClock):
        self.clock = clock
        self.down = False
        self.delivered: list[dict] = []

    def send(self, n: Notification) -> bool:
        if self.down:
            return False
        self.delivered.append({
            "t": self.clock().astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "watch": n.watch_id,
            "record": n.record_id,
            "reasons": list(n.reasons),
            "urgency": n.urgency,
        })
        return True


def run_scenario(name: str, *, twice=False) -> list[dict]:
    # Validate fixtures before importing the deliberately absent implementation.
    rows = load_timeline(name)
    from cornicen.engine import Engine
    from cornicen.store import Store
    from cornicen.watchlist import load_watchlist_text
    from cornicen.config import Config
    from cornicen.identity import AliasMap

    clock = FakeClock(utc(rows[0]["t"]))
    notifier = RecordingNotifier(clock)
    store = Store(":memory:")
    store.migrate()
    config = Config(
        db_path=":memory:", watchlist_path=Path("tests/fixtures/watchlist_example.toml"),
        aliases_path=None, ntfy_url="https://ntfy.invalid", ntfy_topic="replay",
        ntfy_token=None, epss_threshold=0.10, digest_time="08:00", timezone="UTC",
        overdue_minutes=60, user_agent="Cornicen/0.1.0 (+https://github.com/<owner>/cornicen)",
        user_agent_overrides={}, retention_days=365,
    )
    engine = Engine(store, load_watchlist_text(rows[0]["watchlist"]),
                    AliasMap.load(builtin=False), config, clock, notifier)
    first_delivered = None
    for replay_pass in range(2 if twice else 1):
        pending = []
        evaluation_failure = False
        for row in rows[1:]:
            if replay_pass:
                # Replay the CVE releases against the settled clock/inventory.
                # Reissuing watch edits, outages or UTC jumps is a new operational
                # event, not a duplicate feed release. First pass checks all of it.
                if 'ingest' in row and row['ingest']['source'] == 'cvelist':
                    pending.append(as_ingest(row['ingest']))
                elif 'cycle' in row:
                    engine.run_cycle(pending)
                    pending = []
                continue
            clock.now = utc(row["t"])
            if "watchlist" in row:
                engine.reload_watches(load_watchlist_text(row["watchlist"]))
            elif "restart" in row:
                engine = Engine(store, engine.watches, engine.aliases, engine.config, clock, notifier)
            elif "notifier" in row:
                notifier.down = row["notifier"] == "down"
            elif "ingest" in row:
                pending.append(as_ingest(row["ingest"]))
            elif "pairs" in row and replay_pass == 0:
                actual = [dict(pair) for pair in store.connection.execute(
                    'SELECT watch_id,record_id,state FROM pairs ORDER BY watch_id,record_id')]
                if actual != row['pairs']:
                    raise AssertionError(f"{name} at {row['t']}: pairs {actual!r} != {row['pairs']!r}")
            elif "evaluation_failure" in row:
                evaluation_failure = row['evaluation_failure']
            elif "retention_days" in row:
                engine.config = replace(engine.config, retention_days=row['retention_days'])
            elif "cycle" in row:
                fault = (patch('cornicen.applicability.resolve', side_effect=ValueError('replay evaluation failure'))
                         if evaluation_failure else nullcontext())
                with fault:
                    engine.run_cycle(pending)
                pending = []
        if replay_pass == 0:
            first_delivered = list(notifier.delivered)
        elif notifier.delivered != first_delivered:
            raise AssertionError(f"{name}: second pass added {notifier.delivered[len(first_delivered):]!r}")
    return notifier.delivered
