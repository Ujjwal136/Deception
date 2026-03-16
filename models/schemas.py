from typing import Any, Literal
from pydantic import BaseModel, Field


Verdict = Literal["CLEAN", "SUSPICIOUS", "BLOCKED"]


class ChatRequest(BaseModel):
    message: str = Field(min_length=1)
    session_id: str = Field(default="default")


class ChatResponse(BaseModel):
    trace_id: str
    verdict: Verdict
    response: str
    answer: str = ""
    was_blocked: bool = False
    threat_type: str = "none"
    encrypted_fields: list[str] = Field(default_factory=list)
    redactions: list[str] = Field(default_factory=list)


class FirewallIngressRequest(BaseModel):
    prompt: str
    session_id: str = "default"


class FirewallIngressResponse(BaseModel):
    trace_id: str
    verdict: Verdict
    sanitized_prompt: str
    threat_type: str = "none"
    confidence: float = 0.0


class FirewallEgressRequest(BaseModel):
    trace_id: str
    session_id: str = "default"
    payload: Any


class FirewallEgressResponse(BaseModel):
    trace_id: str
    verdict: Verdict
    sanitized_payload: Any
    redactions: list[str] = Field(default_factory=list)


class LedgerEntry(BaseModel):
    trace_id: str
    session_id: str
    event_type: Literal["BLOCK", "REDACT", "INGRESS_BLOCK", "INGRESS_REDACT", "EGRESS_REDACT"]
    threat_type: str
    timestamp_utc: str
    weilchain_hash: str
    encrypted_fields: list[str] = Field(default_factory=list)
    redacted_fields: list[str] = Field(default_factory=list)
    layer_used: str = ""
    confidence: float = 0.0
    block_height: str = ""
    batch_id: str = ""
    tx_idx: str = ""
    tx_hash: str = ""
    receipt_status: str = ""
    onchain: bool = False


class HealthResponse(BaseModel):
    status: str
    sentinel_loaded: bool
    redactor_loaded: bool
    weilchain: dict[str, Any] = Field(default_factory=dict)
    sentinel: dict[str, Any] = Field(default_factory=dict)
    redactor: Any = False
    banking_db: str = "unknown"
    llm_agent: str = "unknown"
