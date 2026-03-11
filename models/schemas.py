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
    event_type: Literal["BLOCK", "REDACT"]
    threat_type: str
    timestamp: float
    hash: str


class HealthResponse(BaseModel):
    status: str
    sentinel_loaded: bool
    redactor_loaded: bool
