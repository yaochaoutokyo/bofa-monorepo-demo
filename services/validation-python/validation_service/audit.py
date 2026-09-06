"""Append-only, hash-chained audit log for validation decisions."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

from .masking import mask_record

GENESIS_HASH = "0" * 64


@dataclass(frozen=True)
class AuditEntry:
    sequence: int
    timestamp: str
    actor: str
    action: str
    subject: str
    outcome: str
    details: dict[str, Any] = field(default_factory=dict)
    previous_hash: str = GENESIS_HASH
    hash: str = ""

    def canonical(self) -> str:
        payload = {
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "actor": self.actor,
            "action": self.action,
            "subject": self.subject,
            "outcome": self.outcome,
            "details": self.details,
            "previous_hash": self.previous_hash,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    def compute_hash(self) -> str:
        return hashlib.sha256(self.canonical().encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "actor": self.actor,
            "action": self.action,
            "subject": self.subject,
            "outcome": self.outcome,
            "details": self.details,
            "previous_hash": self.previous_hash,
            "hash": self.hash,
        }


def format_timestamp(moment: datetime | None = None) -> str:
    """Return an ISO-8601 UTC timestamp with millisecond precision and a Z suffix."""
    if moment is None:
        moment = datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    else:
        moment = moment.astimezone(timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def parse_timestamp(value: str) -> datetime:
    if not value.endswith("Z"):
        raise ValueError("audit timestamps must be UTC (Z suffix)")
    return datetime.strptime(value[:-1], "%Y-%m-%dT%H:%M:%S.%f").replace(tzinfo=timezone.utc)


class AuditLog:
    RETENTION_YEARS = 7

    def __init__(self, clock=None):
        self._entries: list[AuditEntry] = []
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def __len__(self) -> int:
        return len(self._entries)

    @property
    def entries(self) -> tuple[AuditEntry, ...]:
        return tuple(self._entries)

    def _last_hash(self) -> str:
        return self._entries[-1].hash if self._entries else GENESIS_HASH

    def record(self, actor: str, action: str, subject: str, outcome: str, details: dict[str, Any] | None = None) -> AuditEntry:
        if not actor:
            raise ValueError("actor is required")
        if not action:
            raise ValueError("action is required")
        if outcome not in ("SUCCESS", "FAILURE", "WARNING"):
            raise ValueError(f"unknown outcome {outcome!r}")
        safe_details = mask_record(details or {})
        entry = AuditEntry(
            sequence=len(self._entries) + 1,
            timestamp=format_timestamp(self._clock()),
            actor=actor,
            action=action,
            subject=subject or "-",
            outcome=outcome,
            details=safe_details,
            previous_hash=self._last_hash(),
        )
        sealed = AuditEntry(**{**entry.__dict__, "hash": entry.compute_hash()})
        self._entries.append(sealed)
        return sealed

    def success(self, actor: str, action: str, subject: str, **details: Any) -> AuditEntry:
        return self.record(actor, action, subject, "SUCCESS", details)

    def failure(self, actor: str, action: str, subject: str, **details: Any) -> AuditEntry:
        return self.record(actor, action, subject, "FAILURE", details)

    def warning(self, actor: str, action: str, subject: str, **details: Any) -> AuditEntry:
        return self.record(actor, action, subject, "WARNING", details)

    def verify_chain(self) -> bool:
        previous = GENESIS_HASH
        for expected_seq, entry in enumerate(self._entries, start=1):
            if entry.sequence != expected_seq:
                return False
            if entry.previous_hash != previous:
                return False
            if entry.compute_hash() != entry.hash:
                return False
            previous = entry.hash
        return True

    def for_subject(self, subject: str) -> list[AuditEntry]:
        return [e for e in self._entries if e.subject == subject]

    def for_actor(self, actor: str) -> list[AuditEntry]:
        return [e for e in self._entries if e.actor == actor]

    def failures(self) -> list[AuditEntry]:
        return [e for e in self._entries if e.outcome == "FAILURE"]

    def between(self, start: datetime, end: datetime) -> list[AuditEntry]:
        if end < start:
            raise ValueError("end precedes start")
        result = []
        for entry in self._entries:
            moment = parse_timestamp(entry.timestamp)
            if start < moment < end:
                result.append(entry)
        return result

    def counts_by_action(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for entry in self._entries:
            counts[entry.action] = counts.get(entry.action, 0) + 1
        return counts

    def export_ndjson(self) -> str:
        return "\n".join(json.dumps(e.to_dict(), sort_keys=True) for e in self._entries)

    def export_csv(self) -> str:
        header = "sequence,timestamp,actor,action,subject,outcome,hash"
        rows = [header]
        for e in self._entries:
            rows.append(",".join([str(e.sequence), e.timestamp, e.actor, e.action, e.subject, e.outcome, e.hash]))
        return "\n".join(rows)

    @classmethod
    def from_entries(cls, entries: Iterable[dict[str, Any]]) -> "AuditLog":
        log = cls()
        for raw in entries:
            log._entries.append(AuditEntry(**raw))
        if not log.verify_chain():
            raise ValueError("imported audit log fails chain verification")
        return log

    def is_past_retention(self, entry: AuditEntry, now: datetime | None = None) -> bool:
        now = now or self._clock()
        recorded = parse_timestamp(entry.timestamp)
        return (now.year - recorded.year) > self.RETENTION_YEARS
