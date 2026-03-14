from __future__ import annotations

from uuid import uuid4

from firewall.redactor import Redactor
from firewall.sentinel import Sentinel
from firewall.weilchain import Weilchain


class Interceptor:
    def __init__(self, sentinel: Sentinel, redactor: Redactor, weilchain: Weilchain) -> None:
        self.sentinel = sentinel
        self.redactor = redactor
        self.weilchain = weilchain

    def ingress(self, prompt: str, session_id: str) -> dict:
        trace_id = str(uuid4())
        scan = self.sentinel.scan(prompt)
        if scan["is_threat"]:
            self.weilchain.commit(
                session_id=session_id,
                event_type="INGRESS_BLOCK",
                threat_type=scan["threat_type"],
                layer_used=scan.get("layer_used", "HEURISTIC"),
                confidence=scan["confidence"],
                trace_id=trace_id,
            )
            return {
                "trace_id": trace_id,
                "verdict": "BLOCKED",
                "sanitized_prompt": "",
                "threat_type": scan["threat_type"],
                "confidence": scan["confidence"],
            }

        prompt_redacted = self.redactor.redact(prompt)
        verdict = "SUSPICIOUS" if prompt_redacted["redactions"] else "CLEAN"
        if verdict == "SUSPICIOUS":
            self.weilchain.commit(
                session_id=session_id,
                event_type="INGRESS_REDACT",
                threat_type="INGRESS_PII",
                layer_used="NER+REGEX",
                confidence=scan["confidence"],
                encrypted_fields=prompt_redacted.get("encrypted_fields", []),
                redacted_fields=[r for r in prompt_redacted["redactions"]
                                 if r not in prompt_redacted.get("encrypted_fields", [])],
                trace_id=trace_id,
            )

        return {
            "trace_id": trace_id,
            "verdict": verdict,
            "sanitized_prompt": prompt_redacted["redacted_text"],
            "threat_type": scan["threat_type"],
            "confidence": scan["confidence"],
        }

    def egress(self, trace_id: str, session_id: str, payload: str) -> dict:
        result = self.redactor.redact(payload)
        verdict = "SUSPICIOUS" if result["redactions"] else "CLEAN"
        if verdict == "SUSPICIOUS":
            self.weilchain.commit(
                session_id=session_id,
                event_type="EGRESS_REDACT",
                threat_type="EGRESS_PII",
                layer_used="NER+REGEX",
                confidence=1.0,
                encrypted_fields=result.get("encrypted_fields", []),
                redacted_fields=[r for r in result["redactions"]
                                 if r not in result.get("encrypted_fields", [])],
                trace_id=trace_id,
            )
        return {
            "trace_id": trace_id,
            "verdict": verdict,
            "sanitized_payload": result["redacted_text"],
            "redactions": result["redactions"],
        }
