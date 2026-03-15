"""Weilchain audit ledger for Aegis.

Primary storage uses the official Weilliptic Python SDK. If SDK/key setup is
missing, this class degrades to local in-memory cache while keeping API stable.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from config import settings

# Audit ledger backed by Weilliptic WeilChain
# Uses official weil_wallet Python SDK
# from weil_wallet import PrivateKey, Wallet, WeilClient
# Every security event committed on-chain via client.audit()

_WEIL_IMPORT_ERROR = ""
try:
    from weil_wallet import PrivateKey, Wallet, WeilClient

    WEIL_SDK_AVAILABLE = True
except ImportError as exc:
    try:
        # Fallback: import only core modules needed for audit signing/commit.
        # This avoids optional mnemonic dependencies from package __init__.
        from weil_wallet.wallet import PrivateKey, Wallet
        from weil_wallet.client import WeilClient

        WEIL_SDK_AVAILABLE = True
    except ImportError as core_exc:
        WEIL_SDK_AVAILABLE = False
        _WEIL_IMPORT_ERROR = f"{exc}; core import failed: {core_exc}"


logger = logging.getLogger("aegis")


def _project_root() -> Path:
    # firewall/weilchain.py -> project root is one level up
    return Path(__file__).resolve().parents[1]


def _resolve_key_path(path_from_config: str) -> Path:
    key_path = Path(path_from_config)
    if key_path.is_absolute():
        return key_path
    return _project_root() / key_path


def _compute_hash(
    trace_id: str,
    session_id: str,
    event_type: str,
    threat_type: str,
    timestamp_utc: str,
) -> str:
    payload = f"{trace_id}|{session_id}|{event_type}|{threat_type}|{timestamp_utc}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass
class WeilEntry:
    trace_id: str
    session_id: str
    event_type: str
    threat_type: str
    timestamp_utc: str
    weilchain_hash: str
    encrypted_fields: list[str] = field(default_factory=list)
    redacted_fields: list[str] = field(default_factory=list)
    layer_used: str = ""
    confidence: float = 0.0
    block_height: str = ""
    batch_id: str = ""
    tx_idx: str = ""
    onchain: bool = False


class Weilchain:
    def __init__(self, db_path: str = "weilchain.db") -> None:
        _ = db_path  # legacy arg retained for compatibility
        self._backend = "weilchain_applet"
        self._cache: list[dict] = []
        self._cache_time: float = 0.0
        self._cache_ttl_seconds = 10.0
        self._wallet: Wallet | None = None
        self._sdk_ready = False
        self._last_error: str = ""
        self._key_path = settings.weil_key_path or os.getenv("WEIL_KEY_PATH", "private_key.wc")
        self._resolved_key_path = _resolve_key_path(self._key_path)

        if WEIL_SDK_AVAILABLE and self._resolved_key_path.exists():
            try:
                pk = PrivateKey.from_file(str(self._resolved_key_path))
                self._wallet = Wallet(pk)
                self._sdk_ready = True
                logger.info("WeilChain SDK ready ✅ - commits will go on-chain")
            except Exception as exc:
                self._last_error = str(exc)
                logger.warning("WeilChain SDK init failed: %s", exc)
        else:
            if not WEIL_SDK_AVAILABLE:
                self._last_error = _WEIL_IMPORT_ERROR or "weil_wallet import failed"
            elif not self._resolved_key_path.exists():
                self._last_error = f"key file not found: {self._resolved_key_path}"
            logger.warning(
                "WeilChain SDK not configured. Place private_key.wc in project root or set WEIL_KEY_PATH. "
                "Audit events will be computed but not persisted on-chain."
            )

    async def _commit_onchain(self, message: str) -> dict:
        if not self._wallet:
            raise RuntimeError("wallet is not initialized")

        async with WeilClient(self._wallet) as client:
            result = await client.audit(message)
            return {
                "status": getattr(result, "status", ""),
                "block_height": getattr(result, "block_height", ""),
                "batch_id": getattr(result, "batch_id", ""),
                "tx_idx": getattr(result, "tx_idx", ""),
                "txn_result": getattr(result, "txn_result", ""),
                "creation_time": str(getattr(result, "creation_time", "")),
            }

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

        audit_message = (
            f"AEGIS|{event_type}|{threat_type}|{trace_id}|"
            f"{session_id}|{layer_used}|{confidence}|"
            f"{timestamp_utc}|{weilchain_hash}"
        )

        if self._sdk_ready:
            try:
                onchain_result = asyncio.run(self._commit_onchain(audit_message))
                entry.block_height = str(onchain_result.get("block_height", ""))
                entry.batch_id = str(onchain_result.get("batch_id", ""))
                entry.tx_idx = str(onchain_result.get("tx_idx", ""))
                entry.onchain = True
                # Keep an in-process mirror so /api/v1/audit/ledger can show
                # recent on-chain commits without a chain query endpoint.
                self._cache.append(asdict(entry))
                logger.info(
                    "Committed on-chain ✅ block=%s batch=%s trace=%s",
                    entry.block_height,
                    entry.batch_id,
                    trace_id,
                )
            except Exception as exc:
                self._last_error = str(exc)
                logger.warning("On-chain commit failed, entry stored locally: %s", exc)
                self._cache.append(asdict(entry))
        else:
            self._cache.append(asdict(entry))
            logger.info("WeilChain offline - entry cached locally: %s", trace_id)

        self._cache_time = 0.0
        return entry

    def get_all(self) -> list[dict]:
        now = time.time()
        if now - self._cache_time <= self._cache_ttl_seconds:
            return [dict(e) for e in reversed(self._cache)]

        # On-chain reads can be added later via SDK query APIs.
        self._cache_time = now
        return [dict(e) for e in reversed(self._cache)]

    def get_by_session(self, session_id: str) -> list[dict]:
        return [e for e in self.get_all() if e.get("session_id") == session_id]

    def get_by_trace(self, trace_id: str) -> Optional[dict]:
        for entry in self.get_all():
            if entry.get("trace_id") == trace_id:
                return entry
        return None

    def get_by_event_type(self, event_type: str) -> list[dict]:
        return [e for e in self.get_all() if e.get("event_type") == event_type]

    def stats(self) -> dict:
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
            "total": len(all_entries),
            "total_events": len(all_entries),
            "ingress_blocks": ingress_blocks,
            "egress_redacts": egress_redacts,
            "unique_sessions": len(sessions),
            "threat_type_breakdown": threat_breakdown,
            "storage": "on-chain" if self._sdk_ready else "offline-fallback",
        }

    def connectivity(self) -> dict:
        key_exists = self._resolved_key_path.exists()
        return {
            "status": "online" if self._sdk_ready else "offline",
            "backend": "weilchain_applet",
            "sdk_available": WEIL_SDK_AVAILABLE,
            "key_configured": key_exists,
            "key_path": str(self._resolved_key_path),
            "error": self._last_error or "",
        }

    def verify(self, entry_or_trace_id) -> dict | bool:
        if isinstance(entry_or_trace_id, dict):
            entry = entry_or_trace_id
            ts_key = "timestamp_utc" if "timestamp_utc" in entry else "timestamp"
            base = (
                f"{entry['trace_id']}|{entry['session_id']}|{entry['event_type']}|"
                f"{entry['threat_type']}|{entry[ts_key]}"
            )
            expected = hashlib.sha256(base.encode("utf-8")).hexdigest()
            stored = entry.get("weilchain_hash") or entry.get("hash", "")
            return expected == stored

        trace_id = entry_or_trace_id
        entry = self.get_by_trace(trace_id)
        if entry is None:
            return {"error": "not found"}

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
