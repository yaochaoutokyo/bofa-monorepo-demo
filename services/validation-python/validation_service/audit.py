"""Append-only, hash-chained audit log for validation decisions."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .masking import mask_record

GENESIS_HASH = "0" * 64
OUTCOMES = ("SUCCESS", "FAILURE", "WARNING")


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

    def compute_hash(self) -> str:
        payload = {k: v for k, v in self.__dict__.items() if k != "hash"}
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def format_timestamp(moment: datetime | None = None) -> str:
    """ISO-8601 UTC timestamp with millisecond precision and a Z suffix."""
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
    def __init__(self, clock=None):
        self._entries: list[AuditEntry] = []
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def __len__(self) -> int:
        return len(self._entries)

    def record(self, actor: str, action: str, subject: str, outcome: str, details: dict[str, Any] | None = None) -> AuditEntry:
        if not actor:
            raise ValueError("actor is required")
        if not action:
            raise ValueError("action is required")
        if outcome not in OUTCOMES:
            raise ValueError(f"unknown outcome {outcome!r}")
        entry = AuditEntry(
            sequence=len(self._entries) + 1,
            timestamp=format_timestamp(self._clock()),
            actor=actor,
            action=action,
            subject=subject or "-",
            outcome=outcome,
            details=mask_record(details or {}),
            previous_hash=self._entries[-1].hash if self._entries else GENESIS_HASH,
        )
        sealed = AuditEntry(**{**entry.__dict__, "hash": entry.compute_hash()})
        self._entries.append(sealed)
        return sealed

    def success(self, actor: str, action: str, subject: str, **details: Any) -> AuditEntry:
        return self.record(actor, action, subject, "SUCCESS", details)

    def failure(self, actor: str, action: str, subject: str, **details: Any) -> AuditEntry:
        return self.record(actor, action, subject, "FAILURE", details)

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

    def failures(self) -> list[AuditEntry]:
        return [e for e in self._entries if e.outcome == "FAILURE"]

    def between(self, start: datetime, end: datetime) -> list[AuditEntry]:
        if end < start:
            raise ValueError("end precedes start")
        return [e for e in self._entries if start < parse_timestamp(e.timestamp) < end]

    def export_ndjson(self) -> str:
        return "\n".join(json.dumps(e.__dict__, sort_keys=True) for e in self._entries)
