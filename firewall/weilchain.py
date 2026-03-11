from __future__ import annotations

import hashlib
import time
from dataclasses import asdict, dataclass


@dataclass
class LedgerEntry:
    trace_id: str
    session_id: str
    event_type: str
    threat_type: str
    timestamp: float
    hash: str


class Weilchain:
    def __init__(self) -> None:
        self._entries: list[LedgerEntry] = []

    def commit(self, trace_id: str, session_id: str, event_type: str, threat_type: str) -> LedgerEntry:
        timestamp = time.time()
        base = f"{trace_id}|{session_id}|{event_type}|{threat_type}|{timestamp}"
        digest = hashlib.sha256(base.encode("utf-8")).hexdigest()
        entry = LedgerEntry(
            trace_id=trace_id,
            session_id=session_id,
            event_type=event_type,
            threat_type=threat_type,
            timestamp=timestamp,
            hash=digest,
        )
        self._entries.append(entry)
        return entry

    def get_all(self) -> list[dict]:
        return [asdict(item) for item in self._entries]

    def verify(self, entry: dict) -> bool:
        base = (
            f"{entry['trace_id']}|{entry['session_id']}|{entry['event_type']}|"
            f"{entry['threat_type']}|{entry['timestamp']}"
        )
        expected = hashlib.sha256(base.encode("utf-8")).hexdigest()
        return expected == entry.get("hash")
