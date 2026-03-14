from __future__ import annotations

import math
import pickle
import re
from dataclasses import dataclass
from pathlib import Path

import numpy as np

from config import settings
from training.train_sentinel import SGDClassifier, vectorize
from training.train_sentinel_b import MLP, vectorize_b


THREAT_PATTERNS = {
    "prompt_injection": re.compile(
        r"ignore\s+(all\s+)?(previous\s+)?instructions"
        r"|override|system prompt|disable_redaction"
        r"|do anything now|jailbreak|DAN\b"
        r"|pretend you|you are now"
        r"|forget (all |your )?rules",
        re.IGNORECASE,
    ),
    "data_exfiltration": re.compile(
        r"dump\b|all records|unmasked|export.*(raw|all)"
        r"|reveal\b.*\b(aadhaar|pan|passport|phone|account)"
        r"|sabka.*(aadhaar|pan|number)",
        re.IGNORECASE,
    ),
    "sql_injection": re.compile(
        r"\bunion\b|\bdrop\b|\bor\s+'1'\s*=\s*'1|;\s*select",
        re.IGNORECASE,
    ),
}


@dataclass
class SentinelResult:
    is_threat: bool
    confidence: float
    threat_type: str
    layer_used: str


class Sentinel:
    def __init__(self) -> None:
        # Layer A (SGD linear classifier)
        self.classifier: SGDClassifier | None = None
        self.vocab: dict[str, int] | None = None
        # Layer B (MLP non-linear classifier)
        self.mlp: MLP | None = None
        self.vocab_b: dict[str, int] | None = None
        self.idf_b: np.ndarray | None = None

    def load(self) -> bool:
        a_ok = self._load_layer_a()
        b_ok = self._load_layer_b()
        return a_ok or b_ok

    def _load_layer_a(self) -> bool:
        try:
            model_path = Path(settings.sentinel_model_path)
            with model_path.open("rb") as f:
                data = pickle.load(f)
            self.classifier = SGDClassifier.from_dict(data["classifier"])
            self.vocab = data["vocab"]
            return True
        except (FileNotFoundError, KeyError):
            self.classifier = None
            self.vocab = None
            return False

    def _load_layer_b(self) -> bool:
        try:
            model_path = Path(settings.sentinel_b_model_path)
            with model_path.open("rb") as f:
                data = pickle.load(f)
            self.mlp = MLP.from_dict(data["mlp"])
            self.vocab_b = data["vocab"]
            self.idf_b = np.array(data["idf"], dtype=np.float32)
            return True
        except (FileNotFoundError, KeyError):
            self.mlp = None
            self.vocab_b = None
            self.idf_b = None
            return False

    @property
    def layer_a_loaded(self) -> bool:
        return self.classifier is not None and self.vocab is not None

    @property
    def layer_b_loaded(self) -> bool:
        return self.mlp is not None and self.vocab_b is not None

    def scan(self, prompt: str) -> dict:
        heuristic_hit = self._threat_type(prompt)
        has_models = self.layer_a_loaded or self.layer_b_loaded

        # Fast-path: safe banking intent with no heuristic match
        # ONLY when no models are loaded (otherwise let models decide)
        if not has_models and heuristic_hit == "none" and self._is_safe_banking_intent(prompt):
            return {
                "is_threat": False,
                "confidence": 0.05,
                "threat_type": "none",
                "layer_used": "HEURISTIC",
            }

        # Get model predictions
        prob_a = self._layer_a_prob(prompt)
        prob_b = self._layer_b_prob(prompt)

        # Determine which layers contributed
        has_a = prob_a is not None
        has_b = prob_b is not None
        if has_a and has_b:
            layer_used = "A+B"
        elif has_a:
            layer_used = "A"
        elif has_b:
            layer_used = "B"
        else:
            layer_used = "HEURISTIC"

        # If heuristic matched, override — it's a known attack pattern
        if heuristic_hit != "none":
            confidence = max(prob_a or 0.0, prob_b or 0.0, 0.9)
            return {
                "is_threat": True,
                "confidence": confidence,
                "threat_type": heuristic_hit,
                "layer_used": layer_used or "HEURISTIC",
            }

        # Ensemble logic: combine Layer A + Layer B
        if has_a and has_b:
            # Weighted average: 0.45 A + 0.55 B (B is non-linear, slightly stronger)
            combined = 0.45 * prob_a + 0.55 * prob_b
            is_threat = combined >= 0.60
            # If safe banking intent and models show low risk, reduce confidence
            if self._is_safe_banking_intent(prompt) and combined < 0.40:
                combined = min(combined, 0.05)
            threat_type = "model_risk" if is_threat else "none"
            return {
                "is_threat": is_threat,
                "confidence": float(combined),
                "threat_type": threat_type,
                "layer_used": "A+B",
            }

        # Single-layer fallback
        prob = prob_a if has_a else prob_b
        if prob is not None:
            is_threat = prob >= 0.65
            return {
                "is_threat": is_threat,
                "confidence": float(prob),
                "threat_type": "model_risk" if is_threat else "none",
                "layer_used": layer_used,
            }

        # No models loaded — heuristic only
        return {
            "is_threat": False,
            "confidence": 0.1,
            "threat_type": "none",
            "layer_used": "HEURISTIC",
        }

    def _is_safe_banking_intent(self, prompt: str) -> bool:
        lowered = prompt.lower()
        safe_terms = ["balance", "transaction", "loan", "ifsc", "interest",
                      "customer", "cust", "account type", "kyc", "branch"]
        return any(term in lowered for term in safe_terms)

    def _layer_a_prob(self, prompt: str) -> float | None:
        if not self.layer_a_loaded:
            return None
        x = vectorize(prompt, self.vocab)
        return float(self.classifier.predict_proba(x))

    def _layer_b_prob(self, prompt: str) -> float | None:
        if not self.layer_b_loaded:
            return None
        x = vectorize_b(prompt, self.vocab_b, self.idf_b)
        return float(self.mlp.predict_proba(x))

    def _threat_type(self, prompt: str) -> str:
        for name, pattern in THREAT_PATTERNS.items():
            if pattern.search(prompt):
                return name
        return "none"


sentinel = Sentinel()
