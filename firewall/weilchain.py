"""Weilchain audit ledger for Aegis.

Primary storage uses the official Weilliptic Python SDK. If SDK/key setup is
missing, this class degrades to local in-memory cache while keeping API stable.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import threading
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
    tx_hash: str = ""
    receipt_status: str = ""
    onchain: bool = False


class Weilchain:
    def __init__(self) -> None:
        self._backend = "weilchain_applet"
        self._cache: list[dict] = []
        self._cache_lock = threading.RLock()
        self._cache_time: float = 0.0
        self._cache_ttl_seconds = 10.0
        self._pending_receipt_traces: set[str] = set()
        self._poll_stop_event = threading.Event()
        self._polling_thread: threading.Thread | None = None
        self._poll_interval_seconds = 2.0
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
            tx_hash = self._extract_tx_hash(result)
            return {
                "status": getattr(result, "status", ""),
                "block_height": getattr(result, "block_height", ""),
                "batch_id": getattr(result, "batch_id", ""),
                "tx_idx": getattr(result, "tx_idx", ""),
                "tx_hash": tx_hash,
                "receipt_status": self._normalize_receipt_status(getattr(result, "status", "")),
                "txn_result": getattr(result, "txn_result", ""),
                "creation_time": str(getattr(result, "creation_time", "")),
            }

    def start_background_receipt_polling(self, interval_seconds: float = 2.0) -> None:
        if self._polling_thread and self._polling_thread.is_alive():
            return

        self._poll_interval_seconds = max(1.0, float(interval_seconds))
        self._poll_stop_event.clear()
        self._polling_thread = threading.Thread(
            target=self._run_receipt_poll_loop,
            name="weilchain-receipt-poller",
            daemon=True,
        )
        self._polling_thread.start()
        logger.info("WeilChain receipt poller started (interval=%ss)", self._poll_interval_seconds)

    def stop_background_receipt_polling(self) -> None:
        self._poll_stop_event.set()
        thread = self._polling_thread
        if thread and thread.is_alive():
            thread.join(timeout=3.0)
        self._polling_thread = None

    def _run_receipt_poll_loop(self) -> None:
        try:
            asyncio.run(self._receipt_poll_loop())
        except Exception as exc:
            logger.warning("WeilChain receipt poller stopped: %s", exc)

    async def _receipt_poll_loop(self) -> None:
        while not self._poll_stop_event.is_set():
            await self._poll_pending_receipts_once()
            await asyncio.sleep(self._poll_interval_seconds)

    async def _poll_pending_receipts_once(self) -> None:
        if not self._sdk_ready or not self._wallet:
            return

        with self._cache_lock:
            pending = list(self._pending_receipt_traces)

        for trace_id in pending:
            with self._cache_lock:
                entry = next((e for e in self._cache if e.get("trace_id") == trace_id), None)

            if entry is None:
                with self._cache_lock:
                    self._pending_receipt_traces.discard(trace_id)
                continue

            if entry.get("tx_hash") and not self._is_in_progress(entry.get("receipt_status", "")):
                with self._cache_lock:
                    self._pending_receipt_traces.discard(trace_id)
                continue

            update = await self._fetch_receipt_update(entry)
            if not update:
                continue

            with self._cache_lock:
                current = next((e for e in self._cache if e.get("trace_id") == trace_id), None)
                if current is None:
                    self._pending_receipt_traces.discard(trace_id)
                    continue

                if update.get("tx_hash"):
                    current["tx_hash"] = str(update["tx_hash"])
                if update.get("receipt_status"):
                    current["receipt_status"] = self._normalize_receipt_status(update["receipt_status"])
                if update.get("block_height") is not None:
                    current["block_height"] = str(update.get("block_height", current.get("block_height", "")))

                if current.get("tx_hash") and not self._is_in_progress(current.get("receipt_status", "")):
                    self._pending_receipt_traces.discard(trace_id)

    async def _fetch_receipt_update(self, entry: dict) -> dict:
        trace_id = str(entry.get("trace_id", "") or "").strip()
        batch_id = str(entry.get("batch_id", "") or "").strip()
        tx_idx_raw = str(entry.get("tx_idx", "") or "").strip()
        endpoint_specs: list[tuple[str, str, dict | None]] = []

        if batch_id and tx_idx_raw != "":
            try:
                tx_idx = int(tx_idx_raw)
                payload = {"batch_id": batch_id, "tx_idx": tx_idx}
                endpoint_specs.extend([
                    ("POST", "/contracts/get_transaction_result", payload),
                    ("POST", "/contracts/get_transaction_status", payload),
                    ("GET", f"/contracts/transaction/{batch_id}/{tx_idx}", None),
                    ("GET", f"/contracts/tx/{batch_id}/{tx_idx}", None),
                ])
            except ValueError:
                pass

        if trace_id:
            payload_trace = {"trace_id": trace_id}
            endpoint_specs.extend([
                ("POST", "/contracts/get_transaction_result_by_trace", payload_trace),
                ("POST", "/contracts/get_transaction_by_trace", payload_trace),
                ("POST", "/contracts/get_receipt_by_trace", payload_trace),
            ])

        if not endpoint_specs:
            return {}

        try:
            async with WeilClient(self._wallet) as client:
                for method, path, body in endpoint_specs:
                    try:
                        if method == "POST":
                            resp = await client._http_client.post(path, json=body)
                        else:
                            resp = await client._http_client.get(path)

                        if resp.status_code >= 400:
                            continue

                        data = resp.json()
                        parsed = self._parse_receipt_response(data)
                        if parsed:
                            return parsed
                    except Exception:
                        continue
        except Exception:
            return {}

        return {}

    def _parse_receipt_response(self, payload: object) -> dict:
        data = payload
        if isinstance(data, dict) and "Ok" in data and isinstance(data["Ok"], dict):
            data = data["Ok"]

        if not isinstance(data, dict):
            return {}

        status = data.get("status") or data.get("receipt_status") or ""
        tx_hash = data.get("tx_hash") or data.get("transaction_hash") or data.get("hash") or ""
        block_height = data.get("block_height")

        return {
            "receipt_status": self._normalize_receipt_status(status),
            "tx_hash": str(tx_hash) if tx_hash else "",
            "block_height": block_height,
        }

    def _normalize_receipt_status(self, status: object) -> str:
        raw = str(status or "").strip()
        upper = raw.upper()
        if "IN_PROGRESS" in upper or upper.endswith("INPROGRESS"):
            return "IN_PROGRESS"
        if "FINAL" in upper:
            return "FINALIZED"
        if "CONFIRM" in upper:
            return "CONFIRMED"
        if "FAIL" in upper:
            return "FAILED"
        return raw

    def _is_in_progress(self, status: object) -> bool:
        return self._normalize_receipt_status(status) == "IN_PROGRESS"

    def _extract_tx_hash(self, result: object) -> str:
        # Prefer direct attributes if the SDK exposes a transaction hash.
        for attr in ("tx_hash", "transaction_hash", "hash"):
            value = getattr(result, attr, "")
            if value:
                return str(value)

        # Fallback: parse txn_result payload for hash fields.
        txn_result = getattr(result, "txn_result", "")
        if isinstance(txn_result, dict):
            for key in ("tx_hash", "transaction_hash", "hash"):
                if txn_result.get(key):
                    return str(txn_result.get(key))
        elif isinstance(txn_result, str) and txn_result.strip():
            try:
                parsed = json.loads(txn_result)
                if isinstance(parsed, dict):
                    for key in ("tx_hash", "transaction_hash", "hash"):
                        if parsed.get(key):
                            return str(parsed.get(key))
            except json.JSONDecodeError:
                pass

        return ""

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
                entry.tx_hash = str(onchain_result.get("tx_hash", ""))
                entry.receipt_status = str(onchain_result.get("receipt_status", ""))
                entry.onchain = True
                # Keep an in-process mirror so /api/v1/audit/ledger can show
                # recent on-chain commits without a chain query endpoint.
                with self._cache_lock:
                    self._cache.append(asdict(entry))
                    if self._is_in_progress(entry.receipt_status) and not entry.tx_hash:
                        self._pending_receipt_traces.add(trace_id)
                logger.info(
                    "Committed on-chain ✅ block=%s batch=%s trace=%s",
                    entry.block_height,
                    entry.batch_id,
                    trace_id,
                )
            except Exception as exc:
                self._last_error = str(exc)
                logger.warning("On-chain commit failed, entry stored locally: %s", exc)
                with self._cache_lock:
                    self._cache.append(asdict(entry))
        else:
            with self._cache_lock:
                self._cache.append(asdict(entry))
            logger.info("WeilChain offline - entry cached locally: %s", trace_id)

        self._cache_time = 0.0
        return entry

    def get_all(self) -> list[dict]:
        now = time.time()
        with self._cache_lock:
            if now - self._cache_time <= self._cache_ttl_seconds:
                return [dict(e) for e in reversed(self._cache)]

        # On-chain reads can be added later via SDK query APIs.
        with self._cache_lock:
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
