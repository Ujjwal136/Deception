from __future__ import annotations

import pickle
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from config import settings
from firewall.fpe_engine import FPE_ENCRYPT_MAP
from training.train_redactor import extract_features


@dataclass
class RedactionResult:
    redacted_text: str
    redactions: list[str]
    encrypted_fields: list[str] = field(default_factory=list)


def _fpe_or_redact(entity_type: str, raw_value: str) -> tuple[str, bool]:
    """Return (replacement_text, was_fpe_encrypted)."""
    encrypt_fn = FPE_ENCRYPT_MAP.get(entity_type)
    if encrypt_fn is not None:
        result = encrypt_fn(raw_value)
        # If encrypt_fn fell back to [TYPE_REDACTED], it wasn't truly encrypted
        if not result.startswith("["):
            return result, True
    return f"[{entity_type}_REDACTED]", False


class Redactor:
    def __init__(self) -> None:
        self.ner_model: dict | None = None
        self.ner_classes: set[str] = set()
        self._compiled_patterns = {
            "AADHAAR": re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b"),
            "PAN": re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b", re.IGNORECASE),
            "IFSC": re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b", re.IGNORECASE),
            "EMAIL": re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,}\b"),
            "UPI": re.compile(r"\b[a-zA-Z0-9._-]{2,}@(?!.*\.)[a-zA-Z]{2,}\b"),
            "PHONE": re.compile(r"(?:\+91[-\s]?)?[6-9]\d{9}\b"),
            "DOB": re.compile(r"\b(?:\d{2}[/-]\d{2}[/-]\d{4}|\d{4}-\d{2}-\d{2})\b"),
            "PASSPORT": re.compile(r"\b[A-Z][0-9]{7}\b", re.IGNORECASE),
            "ACCOUNT_NO": re.compile(r"\b\d{11,16}\b"),
        }

    def load(self) -> bool:
        try:
            with open(settings.ner_model_path, "rb") as f:
                data = pickle.load(f)
            self.ner_model = data["weights"]
            self.ner_classes = set(data["classes"])
            return True
        except FileNotFoundError:
            model_dir = Path(settings.redactor_model_path)
            # Validate model directory structure so path mismatches are visible at startup.
            required = ["config.json", "tokenizer.json"]
            has_weights = (model_dir / "model.safetensors").exists() or (model_dir / "pytorch_model.bin").exists()
            if model_dir.exists() and all((model_dir / name).exists() for name in required) and has_weights:
                self.ner_model = None
                return False
            self.ner_model = None
            return False

    def _ner_predict(self, tokens: list[str]) -> list[str]:
        """Run the Averaged Perceptron NER tagger over tokens."""
        labels = []
        prev_label = "O"
        weights = self.ner_model
        classes = self.ner_classes
        for i in range(len(tokens)):
            features = extract_features(tokens, i, prev_label)
            scores: dict[str, float] = defaultdict(float)
            for feat, value in features.items():
                if feat in weights:
                    for label, weight in weights[feat].items():
                        scores[label] += value * weight
            label = max(classes, key=lambda c: scores.get(c, 0.0))
            labels.append(label)
            prev_label = label
        return labels

    def redact(self, text: str) -> dict[str, Any]:
        redacted = text
        redactions: list[str] = []
        encrypted_fields: list[str] = []

        # NER model pass: detect entities and encrypt/redact them
        if self.ner_model is not None:
            try:
                tokens = re.findall(r"\S+", redacted)
                if tokens:
                    labels = self._ner_predict(tokens)
                    # Group consecutive B-/I- tokens of the same entity type
                    entities: list[tuple[list[str], str]] = []
                    current_tokens: list[str] = []
                    current_type: str = ""
                    for token, label in zip(tokens, labels):
                        if label.startswith("B-"):
                            if current_tokens:
                                entities.append((list(current_tokens), current_type))
                            current_tokens = [token]
                            current_type = label[2:]
                        elif label.startswith("I-") and label[2:] == current_type:
                            current_tokens.append(token)
                        else:
                            if current_tokens:
                                entities.append((list(current_tokens), current_type))
                                current_tokens = []
                                current_type = ""
                    if current_tokens:
                        entities.append((list(current_tokens), current_type))

                    # Replace entities right-to-left by finding the full span in text
                    for ent_tokens, etype in reversed(entities):
                        # Find span: locate first token, then extend to cover all tokens
                        first = ent_tokens[0]
                        start = redacted.find(first)
                        if start == -1:
                            continue
                        last = ent_tokens[-1]
                        end_search_start = start + len(first)
                        if len(ent_tokens) > 1:
                            last_pos = redacted.find(last, end_search_start)
                            if last_pos == -1:
                                continue
                            end = last_pos + len(last)
                        else:
                            end = start + len(first)
                        raw_value = redacted[start:end]
                        replacement, was_encrypted = _fpe_or_redact(etype, raw_value)
                        redacted = redacted[:start] + replacement + redacted[end:]
                        redactions.append(etype)
                        if was_encrypted:
                            encrypted_fields.append(etype)
            except Exception:
                pass

        # Regex fallback stays active regardless of model state for stronger safety.
        for pii_type, pattern in self._compiled_patterns.items():
            match = pattern.search(redacted)
            if match:
                def _replace(m: re.Match, pt: str = pii_type) -> str:
                    replacement, was_encrypted = _fpe_or_redact(pt, m.group(0))
                    if was_encrypted and pt not in encrypted_fields:
                        encrypted_fields.append(pt)
                    return replacement
                redacted = pattern.sub(_replace, redacted)
                redactions.append(pii_type)

        unique_redactions = sorted(set(redactions))
        return {
            "redacted_text": redacted,
            "redactions": unique_redactions,
            "encrypted_fields": sorted(set(encrypted_fields)),
        }


redactor = Redactor()
