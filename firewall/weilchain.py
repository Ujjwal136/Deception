"""Weilchain applet bridge for Aegis audit events.

Primary storage is the Weilliptic applet via Node bridge. If bridge access is
unavailable, this class degrades to in-memory fallback while keeping the API
stable so the server does not crash.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
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
        _ = db_path  # legacy arg retained for compatibility
        root = Path(__file__).resolve().parent.parent
        self.bridge_path = str(root / "applet" / "bridge.js")
        self.applet_address = os.getenv("WEIL_APPLET_ADDRESS", "")
        self._backend = "applet"
        self._cache_entries: list[dict] = []
        self._cache_ts: float = 0.0
        self._cache_ttl_seconds = 10.0
        self._offline_ledger: list[dict] = []
        self._last_error: str | None = None
        self._last_online: bool = False

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
        """Create a new WeilEntry and persist via applet when available."""
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

        ok, _ = self._call_applet(
            "commit",
            data={
                "trace_id": entry.trace_id,
                "session_id": entry.session_id,
                "event_type": entry.event_type,
                "threat_type": entry.threat_type,
                "weilchain_hash": entry.weilchain_hash,
                "timestamp": entry.timestamp_utc,
            },
        )
        if not ok:
            self._offline_ledger.append(asdict(entry))
        # Force next read to refresh after each write.
        self._cache_ts = 0.0
        return entry

    def _bridge_available(self) -> bool:
        if not os.getenv("WEIL_PRIVATE_KEY") or not os.getenv("WEIL_APPLET_ADDRESS"):
            return False
        if not Path(self.bridge_path).exists():
            return False
        return shutil.which("node") is not None

    def _normalize_entry(self, entry: dict) -> dict:
        ts = entry.get("timestamp_utc") or entry.get("timestamp") or ""
        return {
            "trace_id": entry.get("trace_id", ""),
            "session_id": entry.get("session_id", ""),
            "event_type": entry.get("event_type", ""),
            "threat_type": entry.get("threat_type", ""),
            "timestamp_utc": ts,
            "weilchain_hash": entry.get("weilchain_hash", entry.get("hash", "")),
            "encrypted_fields": entry.get("encrypted_fields", []) or [],
            "redacted_fields": entry.get("redacted_fields", []) or [],
            "layer_used": entry.get("layer_used", ""),
            "confidence": entry.get("confidence", 0.0),
        }

    def _parse_result(self, result):
        if isinstance(result, str):
            try:
                return json.loads(result)
            except Exception:
                return result
        return result

    def _call_applet(self, action: str, **kwargs) -> tuple[bool, object | None]:
        if not self._bridge_available():
            self._last_online = False
            self._last_error = "bridge unavailable"
            return False, None

        payload = {"action": action}
        payload.update(kwargs)
        try:
            completed = subprocess.run(
                ["node", self.bridge_path],
                input=json.dumps(payload),
                capture_output=True,
                text=True,
                timeout=7,
            )
            if completed.returncode != 0:
                self._last_online = False
                self._last_error = (completed.stderr or "bridge process failed").strip()
                return False, None

            parsed = json.loads((completed.stdout or "{}").strip() or "{}")
            if parsed.get("error"):
                self._last_online = False
                self._last_error = parsed.get("error")
                return False, None

            self._last_online = True
            self._last_error = None
            return True, self._parse_result(parsed.get("result"))
        except Exception as exc:
            self._last_online = False
            self._last_error = str(exc)
            return False, None

    # ── QUERY ──────────────────────────────────────────────────────────

    def get_all(self) -> list[dict]:
        """Returns all entries, most recent first."""
        now = time.time()
        if now - self._cache_ts <= self._cache_ttl_seconds:
            return [dict(e) for e in self._cache_entries]

        ok, result = self._call_applet("get_all")
        if ok and isinstance(result, list):
            entries = [self._normalize_entry(e if isinstance(e, dict) else {}) for e in result]
            self._cache_entries = entries
            self._cache_ts = now
            return [dict(e) for e in entries]

        entries = [self._normalize_entry(e) for e in reversed(self._offline_ledger)]
        self._cache_entries = entries
        self._cache_ts = now
        return [dict(e) for e in entries]

    def get_by_session(self, session_id: str) -> list[dict]:
        """Returns all entries for a given session_id."""
        return [e for e in self.get_all() if e.get("session_id") == session_id]

    def get_by_trace(self, trace_id: str) -> Optional[dict]:
        """Returns the single entry matching trace_id, or None."""
        for entry in self.get_all():
            if entry.get("trace_id") == trace_id:
                return entry
        return None

    def get_by_event_type(self, event_type: str) -> list[dict]:
        """Returns all entries of a given event_type."""
        return [e for e in self.get_all() if e.get("event_type") == event_type]

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
            "storage": "on-chain" if self._last_online else "offline-fallback",
        }

    def connectivity(self) -> dict:
        return {
            "status": "online" if self._last_online else "offline",
            "backend": "applet",
            "applet_address": self.applet_address or "not-configured",
            "error": self._last_error or "",
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
        ok, result = self._call_applet("verify", trace_id=trace_id)
        if ok and isinstance(result, dict):
            if result.get("error"):
                return {"error": "trace_id not found"}
            out = dict(result)
            out.setdefault("trace_id", trace_id)
            out.setdefault("tampered", not bool(out.get("valid", False)))
            return out

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


weilchain = Weilchain()
