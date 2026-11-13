from dataclasses import dataclass
from datetime import date, datetime
from enum import Enum
from typing import Protocol


class Origin(str, Enum):
    SNAPSHOT = "snapshot"
    DELTA = "delta"
    CATALOG = "catalog"
    SCORES = "scores"


class FetchStatus(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


@dataclass(frozen=True)
class IngestResult:
    source: str
    status: FetchStatus
    origin: Origin
    cursor: str | None
    content_time: datetime | None
    records: tuple[dict, ...] = ()
    kev: dict | None = None
    epss: dict[str, tuple[float, float]] | None = None
    epss_date: date | None = None
    errors: tuple[str, ...] = ()
    unchanged: bool = False
    # Number of errors emitted solely by validate.record on decoded records.
    record_validation_errors: int = 0


@dataclass(frozen=True)
class Notification:
    key: str
    watch_id: str
    record_id: str
    reasons: tuple[str, ...]
    urgency: str  # "urgent" | "normal" | "health"
    body: dict


class Notifier(Protocol):
    def send(self, n: Notification) -> bool: ...
