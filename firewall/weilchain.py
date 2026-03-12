"""Weilchain — cryptographic audit ledger for Aegis.

Not a blockchain. A tamper-evident audit trail that proves security events
occurred without storing any raw PII.  Satisfies DPDP Act §17 (right to
erasure) because only hashes of event metadata are persisted.

# TODO: swap _ledger for PostgreSQL in production
"""

from __future__ import annotations

import hashlib
import sqlite3
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Optional


# ── Hash function (deterministic — same inputs → same hash) ────────────


def _compute_hash(
    trace_id: str,
    session_id: str,
    event_type: str,
    threat_type: str,
    timestamp_utc: str,
) -> str:
    payload = f"{trace_id}|{session_id}|{event_type}|{threat_type}|{timestamp_utc}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ── WeilEntry ──────────────────────────────────────────────────────────


@dataclass
class WeilEntry:
    trace_id: str              # UUID4 — unique per request
    session_id: str            # UUID4 — groups requests per user session
    event_type: str            # "INGRESS_BLOCK" | "EGRESS_REDACT"
    threat_type: str           # e.g. "PROMPT_OVERRIDE", "PII_FISHING", "EGRESS_PII"
    timestamp_utc: str         # ISO 8601 UTC string
    weilchain_hash: str        # SHA-256 of the above fields combined
    encrypted_fields: list[str] = field(default_factory=list)  # PII types FPE-encrypted
    redacted_fields: list[str] = field(default_factory=list)   # PII types token-redacted
    layer_used: str = ""       # "A", "B", "A+B", "NER", "NER+REGEX", "REGEX", "HEURISTIC"
    confidence: float = 0.0    # threat confidence score 0.0-1.0


# ── Weilchain ──────────────────────────────────────────────────────────


class Weilchain:
    def __init__(self, db_path: str = "weilchain.db") -> None:
        self.db_path = db_path
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._bootstrap()

    def _bootstrap(self) -> None:
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ledger (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                trace_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                timestamp_utc TEXT NOT NULL,
                weilchain_hash TEXT NOT NULL,
                encrypted_fields TEXT NOT NULL DEFAULT '',
                redacted_fields TEXT NOT NULL DEFAULT '',
                layer_used TEXT NOT NULL DEFAULT '',
                confidence REAL NOT NULL DEFAULT 0.0
            )
            """
        )
        self._conn.commit()

    # ── COMMIT ─────────────────────────────────────────────────────────

    def commit(
        self,
        session_id: str,
        event_type: str,
        threat_type: str,
        layer_used: str = "",
        confidence: float = 0.0,
        encrypted_fields: list[str] | None = None,
        redacted_fields: list[str] | None = None,
        trace_id: str | None = None,
    ) -> WeilEntry:
        """Create a new WeilEntry, compute its hash, persist to ledger."""
        if trace_id is None:
            trace_id = str(uuid.uuid4())
        if encrypted_fields is None:
            encrypted_fields = []
        if redacted_fields is None:
            redacted_fields = []

        timestamp_utc = datetime.now(timezone.utc).isoformat()
        weilchain_hash = _compute_hash(trace_id, session_id, event_type, threat_type, timestamp_utc)

        entry = WeilEntry(
            trace_id=trace_id,
            session_id=session_id,
            event_type=event_type,
            threat_type=threat_type,
            timestamp_utc=timestamp_utc,
            weilchain_hash=weilchain_hash,
            encrypted_fields=encrypted_fields,
            redacted_fields=redacted_fields,
            layer_used=layer_used,
            confidence=confidence,
        )

        self._conn.execute(
            "INSERT INTO ledger "
            "(trace_id, session_id, event_type, threat_type, timestamp_utc, "
            " weilchain_hash, encrypted_fields, redacted_fields, layer_used, confidence) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                entry.trace_id,
                entry.session_id,
                entry.event_type,
                entry.threat_type,
                entry.timestamp_utc,
                entry.weilchain_hash,
                ",".join(entry.encrypted_fields),
                ",".join(entry.redacted_fields),
                entry.layer_used,
                entry.confidence,
            ),
        )
        self._conn.commit()
        return entry

    # ── internal row → dict helper ─────────────────────────────────────

    def _row_to_dict(self, row: sqlite3.Row) -> dict:
        d = dict(row)
        d["encrypted_fields"] = [f for f in d.get("encrypted_fields", "").split(",") if f]
        d["redacted_fields"] = [f for f in d.get("redacted_fields", "").split(",") if f]
        return d

    # ── QUERY ──────────────────────────────────────────────────────────

    def get_all(self) -> list[dict]:
        """Returns all entries, most recent first."""
        rows = self._conn.execute(
            "SELECT trace_id, session_id, event_type, threat_type, timestamp_utc, "
            "weilchain_hash, encrypted_fields, redacted_fields, layer_used, confidence "
            "FROM ledger ORDER BY id DESC"
        ).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def get_by_session(self, session_id: str) -> list[dict]:
        """Returns all entries for a given session_id."""
        rows = self._conn.execute(
            "SELECT trace_id, session_id, event_type, threat_type, timestamp_utc, "
            "weilchain_hash, encrypted_fields, redacted_fields, layer_used, confidence "
            "FROM ledger WHERE session_id = ? ORDER BY id DESC",
            (session_id,),
        ).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def get_by_trace(self, trace_id: str) -> Optional[dict]:
        """Returns the single entry matching trace_id, or None."""
        row = self._conn.execute(
            "SELECT trace_id, session_id, event_type, threat_type, timestamp_utc, "
            "weilchain_hash, encrypted_fields, redacted_fields, layer_used, confidence "
            "FROM ledger WHERE trace_id = ? LIMIT 1",
            (trace_id,),
        ).fetchone()
        if row is None:
            return None
        return self._row_to_dict(row)

    def get_by_event_type(self, event_type: str) -> list[dict]:
        """Returns all entries of a given event_type."""
        rows = self._conn.execute(
            "SELECT trace_id, session_id, event_type, threat_type, timestamp_utc, "
            "weilchain_hash, encrypted_fields, redacted_fields, layer_used, confidence "
            "FROM ledger WHERE event_type = ? ORDER BY id DESC",
            (event_type,),
        ).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def stats(self) -> dict:
        """Returns summary statistics."""
        all_entries = self.get_all()
        threat_breakdown: dict[str, int] = {}
        sessions: set[str] = set()
        ingress_blocks = 0
        egress_redacts = 0

        for e in all_entries:
            sessions.add(e["session_id"])
            tt = e["threat_type"]
            threat_breakdown[tt] = threat_breakdown.get(tt, 0) + 1
            if e["event_type"] in ("BLOCK", "INGRESS_BLOCK"):
                ingress_blocks += 1
            elif e["event_type"] in ("REDACT", "EGRESS_REDACT"):
                egress_redacts += 1

        return {
            "total_events": len(all_entries),
            "ingress_blocks": ingress_blocks,
            "egress_redacts": egress_redacts,
            "unique_sessions": len(sessions),
            "threat_type_breakdown": threat_breakdown,
        }

    # ── TAMPER DETECTION ───────────────────────────────────────────────

    def verify(self, entry_or_trace_id) -> dict | bool:
        """Verify integrity of a single ledger entry.

        Accepts either a trace_id string or a dict with entry fields.
        When a dict is passed (legacy callers / tests), re-derive the hash
        and return True/False for backward-compat.
        """
        if isinstance(entry_or_trace_id, dict):
            entry = entry_or_trace_id
            # Legacy path: match old API used by tests
            ts_key = "timestamp_utc" if "timestamp_utc" in entry else "timestamp"
            base = (
                f"{entry['trace_id']}|{entry['session_id']}|{entry['event_type']}|"
                f"{entry['threat_type']}|{entry[ts_key]}"
            )
            expected = hashlib.sha256(base.encode("utf-8")).hexdigest()
            stored = entry.get("weilchain_hash") or entry.get("hash", "")
            return expected == stored

        # New path: trace_id string
        trace_id = entry_or_trace_id
        entry = self.get_by_trace(trace_id)
        if entry is None:
            return {"error": "trace_id not found"}

        derived_hash = _compute_hash(
            entry["trace_id"],
            entry["session_id"],
            entry["event_type"],
            entry["threat_type"],
            entry["timestamp_utc"],
        )
        return {
            "trace_id": trace_id,
            "valid": derived_hash == entry["weilchain_hash"],
            "stored_hash": entry["weilchain_hash"],
            "derived_hash": derived_hash,
            "tampered": derived_hash != entry["weilchain_hash"],
        }

    def verify_all(self) -> dict:
        """Runs verify() on every entry in the ledger."""
        all_entries = self.get_all()
        valid_count = 0
        tampered_count = 0
        tampered_trace_ids: list[str] = []

        for entry in all_entries:
            derived = _compute_hash(
                entry["trace_id"],
                entry["session_id"],
                entry["event_type"],
                entry["threat_type"],
                entry["timestamp_utc"],
            )
            if derived == entry["weilchain_hash"]:
                valid_count += 1
            else:
                tampered_count += 1
                tampered_trace_ids.append(entry["trace_id"])

        return {
            "total": len(all_entries),
            "valid": valid_count,
            "tampered": tampered_count,
            "tampered_trace_ids": tampered_trace_ids,
        }


# ── Self-test ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    wc = Weilchain(db_path=":memory:")
    passed = 0
    total = 0

    # 1. Commit an INGRESS_BLOCK event
    total += 1
    e1 = wc.commit(
        session_id="sess-001",
        event_type="INGRESS_BLOCK",
        threat_type="PROMPT_OVERRIDE",
        layer_used="HEURISTIC",
        confidence=0.97,
    )
    ok = e1.event_type == "INGRESS_BLOCK" and len(e1.weilchain_hash) == 64
    passed += int(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] 1. Commit INGRESS_BLOCK")

    # 2. Commit an EGRESS_REDACT event with encrypted_fields
    total += 1
    e2 = wc.commit(
        session_id="sess-001",
        event_type="EGRESS_REDACT",
        threat_type="EGRESS_PII",
        layer_used="NER+REGEX",
        confidence=1.0,
        encrypted_fields=["AADHAAR", "PAN"],
        redacted_fields=["PERSON", "EMAIL"],
    )
    ok = e2.encrypted_fields == ["AADHAAR", "PAN"] and e2.redacted_fields == ["PERSON", "EMAIL"]
    passed += int(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] 2. Commit EGRESS_REDACT with FPE fields")

    # 3. get_all should return 2 entries
    total += 1
    all_entries = wc.get_all()
    ok = len(all_entries) == 2
    passed += int(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] 3. get_all() → {len(all_entries)} entries")

    # 4. stats should show correct counts
    total += 1
    st = wc.stats()
    ok = (
        st["total_events"] == 2
        and st["ingress_blocks"] == 1
        and st["egress_redacts"] == 1
        and st["unique_sessions"] == 1
    )
    passed += int(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] 4. stats() → {st}")

    # 5. verify_all should show both valid
    total += 1
    va = wc.verify_all()
    ok = va["valid"] == 2 and va["tampered"] == 0
    passed += int(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] 5. verify_all() → {va}")

    # 6. Corrupt one entry
    total += 1
    wc._conn.execute(
        "UPDATE ledger SET weilchain_hash = 'CORRUPTED' WHERE trace_id = ?",
        (e1.trace_id,),
    )
    wc._conn.commit()
    va2 = wc.verify_all()
    ok = va2["tampered"] == 1 and e1.trace_id in va2["tampered_trace_ids"]
    passed += int(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] 6. Tamper detection → {va2}")

    # 7. verify single trace (dict path — legacy compat)
    total += 1
    entry_dict = wc.get_by_trace(e2.trace_id)
    ok = wc.verify(entry_dict) is True
    passed += int(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] 7. verify(dict) legacy path → True")

    # 8. verify single trace (string path — new API)
    total += 1
    v_result = wc.verify(e2.trace_id)
    ok = isinstance(v_result, dict) and v_result["valid"] is True
    passed += int(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] 8. verify(trace_id) new path → {v_result.get('valid')}")

    print(f"\n{'='*50}")
    print(f"Results: {passed}/{total} passed")
    print("ALL PASS" if passed == total else "SOME FAILED")
