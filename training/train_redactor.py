"""
Aegis NER Redactor — Averaged Perceptron Token Classifier
=========================================================
Trains a NER model FROM SCRATCH (no pretrained weights, no fine-tuning)
using an Averaged Perceptron sequence tagger on aegis_ner_dataset.json.

Outputs: redactor_ner_model.joblib
"""

from __future__ import annotations

import json
import math
import pickle
import random
import re
from collections import defaultdict
from pathlib import Path


# ─── Feature extraction ──────────────────────────────────────────────────────

def word_shape(word: str) -> str:
    """Map word to shape: 'Xxxxx', 'dddd', 'x.x@x', etc."""
    s = []
    for ch in word[:20]:
        if ch.isupper():
            s.append("X")
        elif ch.islower():
            s.append("x")
        elif ch.isdigit():
            s.append("d")
        else:
            s.append(ch)
    return "".join(s)


def extract_features(tokens: list[str], idx: int, prev_label: str) -> dict[str, float]:
    """Extract features for the token at position idx."""
    word = tokens[idx]
    features: dict[str, float] = {
        "bias": 1.0,
        f"word.lower={word.lower()}": 1.0,
        f"word.shape={word_shape(word)}": 1.0,
        f"word.isupper={word.isupper()}": 1.0,
        f"word.istitle={word.istitle()}": 1.0,
        f"word.isdigit={word.isdigit()}": 1.0,
        f"word.isalpha={word.isalpha()}": 1.0,
        f"word.len={min(len(word), 15)}": 1.0,
        f"prev_label={prev_label}": 1.0,
    }

    # Prefix / suffix
    for n in (1, 2, 3):
        if len(word) >= n:
            features[f"prefix{n}={word[:n].lower()}"] = 1.0
            features[f"suffix{n}={word[-n:].lower()}"] = 1.0

    # Pattern features
    if re.match(r"\d{4}\s?\d{4}\s?\d{4}", word):
        features["pattern=aadhaar_like"] = 1.0
    if re.match(r"[A-Z]{5}\d{4}[A-Z]", word):
        features["pattern=pan_like"] = 1.0
    if re.match(r"\+?\d[\d\-\s]{8,}", word):
        features["pattern=phone_like"] = 1.0
    if "@" in word:
        features["pattern=has_at"] = 1.0
    if re.match(r"\d{4}-\d{2}-\d{2}", word) or re.match(r"\d{2}/\d{2}/\d{4}", word):
        features["pattern=date_like"] = 1.0
    if re.match(r"[A-Z]{4}0[A-Z0-9]{6}", word):
        features["pattern=ifsc_like"] = 1.0
    if re.match(r"[A-Z]\d{7}$", word):
        features["pattern=passport_like"] = 1.0
    if re.match(r"\d{11,16}$", word):
        features["pattern=account_like"] = 1.0

    # Context
    if idx > 0:
        prev = tokens[idx - 1]
        features[f"prev.lower={prev.lower()}"] = 1.0
        features[f"prev.istitle={prev.istitle()}"] = 1.0
        features[f"prev.shape={word_shape(prev)}"] = 1.0
    else:
        features["BOS"] = 1.0

    if idx < len(tokens) - 1:
        nxt = tokens[idx + 1]
        features[f"next.lower={nxt.lower()}"] = 1.0
        features[f"next.istitle={nxt.istitle()}"] = 1.0
        features[f"next.shape={word_shape(nxt)}"] = 1.0
    else:
        features["EOS"] = 1.0

    if idx > 1:
        features[f"prev2.lower={tokens[idx-2].lower()}"] = 1.0
    if idx < len(tokens) - 2:
        features[f"next2.lower={tokens[idx+2].lower()}"] = 1.0

    return features


# ─── Averaged Perceptron ──────────────────────────────────────────────────────

class AveragedPerceptron:
    """Multi-class averaged perceptron classifier."""

    def __init__(self) -> None:
        self.weights: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
        self._totals: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
        self._timestamps: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._step: int = 0
        self.classes: set[str] = set()

    def predict(self, features: dict[str, float]) -> str:
        scores: dict[str, float] = defaultdict(float)
        for feat, value in features.items():
            if feat not in self.weights:
                continue
            for label, weight in self.weights[feat].items():
                scores[label] += value * weight
        return max(self.classes, key=lambda c: scores.get(c, 0.0))

    def update(self, truth: str, guess: str, features: dict[str, float]) -> None:
        self._step += 1
        if truth == guess:
            return
        for feat, value in features.items():
            self._update_weight(feat, truth, value)
            self._update_weight(feat, guess, -value)

    def _update_weight(self, feat: str, label: str, delta: float) -> None:
        elapsed = self._step - self._timestamps[feat][label]
        self._totals[feat][label] += elapsed * self.weights[feat][label]
        self.weights[feat][label] += delta
        self._timestamps[feat][label] = self._step

    def average(self) -> None:
        """Apply averaging to weights for better generalization."""
        for feat in self.weights:
            for label in self.weights[feat]:
                elapsed = self._step - self._timestamps[feat][label]
                total = self._totals[feat][label] + elapsed * self.weights[feat][label]
                self.weights[feat][label] = total / max(self._step, 1)
        # Convert to regular dicts for serialization
        self.weights = {f: dict(w) for f, w in self.weights.items()}


# ─── NER Tagger ───────────────────────────────────────────────────────────────

class NERTagger:
    """Greedy left-to-right NER tagger using Averaged Perceptron."""

    def __init__(self) -> None:
        self.model = AveragedPerceptron()

    def train(self, samples: list[dict], n_epochs: int = 15) -> None:
        all_labels = set()
        for s in samples:
            all_labels.update(s["labels"])
        self.model.classes = all_labels

        for epoch in range(1, n_epochs + 1):
            random.shuffle(samples)
            correct = total = 0
            for sample in samples:
                tokens = sample["tokens"]
                labels = sample["labels"]
                prev_label = "O"
                for i, true_label in enumerate(labels):
                    features = extract_features(tokens, i, prev_label)
                    guess = self.model.predict(features)
                    self.model.update(true_label, guess, features)
                    if guess == true_label:
                        correct += 1
                    total += 1
                    prev_label = guess
            acc = correct / max(total, 1)
            if epoch % 5 == 0 or epoch == 1:
                print(f"  Epoch {epoch:>2}/{n_epochs}: token accuracy = {acc:.4f}")

        self.model.average()

    def predict_sequence(self, tokens: list[str]) -> list[str]:
        labels = []
        prev_label = "O"
        for i in range(len(tokens)):
            features = extract_features(tokens, i, prev_label)
            label = self.model.predict(features)
            labels.append(label)
            prev_label = label
        return labels


# ─── Evaluation ───────────────────────────────────────────────────────────────

def evaluate(tagger: NERTagger, samples: list[dict]) -> dict:
    """Compute per-entity-type precision, recall, F1 and overall accuracy."""
    from collections import Counter

    tp: Counter = Counter()
    fp: Counter = Counter()
    fn: Counter = Counter()
    correct = total = 0

    for sample in samples:
        tokens = sample["tokens"]
        true_labels = sample["labels"]
        pred_labels = tagger.predict_sequence(tokens)

        for t, p in zip(true_labels, pred_labels):
            total += 1
            if t == p:
                correct += 1
            # Entity-level counts (B- tags only for simplicity)
            if t.startswith("B-"):
                etype = t[2:]
                if p == t:
                    tp[etype] += 1
                else:
                    fn[etype] += 1
            if p.startswith("B-") and p != t:
                fp[p[2:]] += 1

    token_acc = correct / max(total, 1)
    entity_types = sorted(set(list(tp.keys()) + list(fp.keys()) + list(fn.keys())))

    print(f"\n  Token Accuracy: {token_acc:.4f}")
    print(f"  {'Entity':<15} {'Prec':>8} {'Recall':>8} {'F1':>8} {'Support':>8}")
    print(f"  {'-'*15} {'-'*8} {'-'*8} {'-'*8} {'-'*8}")

    total_tp = total_fp = total_fn = 0
    for etype in entity_types:
        prec = tp[etype] / max(tp[etype] + fp[etype], 1)
        rec = tp[etype] / max(tp[etype] + fn[etype], 1)
        f1 = 2 * prec * rec / max(prec + rec, 1e-9)
        support = tp[etype] + fn[etype]
        print(f"  {etype:<15} {prec:>8.4f} {rec:>8.4f} {f1:>8.4f} {support:>8}")
        total_tp += tp[etype]
        total_fp += fp[etype]
        total_fn += fn[etype]

    micro_prec = total_tp / max(total_tp + total_fp, 1)
    micro_rec = total_tp / max(total_tp + total_fn, 1)
    micro_f1 = 2 * micro_prec * micro_rec / max(micro_prec + micro_rec, 1e-9)
    print(f"  {'-'*15} {'-'*8} {'-'*8} {'-'*8} {'-'*8}")
    print(f"  {'MICRO AVG':<15} {micro_prec:>8.4f} {micro_rec:>8.4f} {micro_f1:>8.4f} {total_tp+total_fn:>8}")

    return {"token_accuracy": token_acc, "micro_f1": micro_f1}


# ─── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    dataset_path = Path("aegis_ner_dataset.json")
    if not dataset_path.exists():
        raise FileNotFoundError("aegis_ner_dataset.json not found")

    with dataset_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    samples = data["samples"]
    print(f"Loaded {len(samples)} NER samples")

    random.seed(42)
    random.shuffle(samples)

    split = int(len(samples) * 0.8)
    train_set = samples[:split]
    test_set = samples[split:]
    print(f"Train: {len(train_set)}, Test: {len(test_set)}")

    tagger = NERTagger()
    print("\nTraining Averaged Perceptron NER tagger (from scratch)...")
    tagger.train(train_set, n_epochs=15)

    print("\nEvaluation on test set:")
    metrics = evaluate(tagger, test_set)

    # Save model
    model_data = {
        "weights": tagger.model.weights,
        "classes": list(tagger.model.classes),
    }
    out_path = "redactor_ner_model.joblib"
    with open(out_path, "wb") as f:
        pickle.dump(model_data, f)

    print(f"\nSaved: {out_path}")
    print(f"Token Accuracy: {metrics['token_accuracy']:.4f}")
    print(f"Entity Micro-F1: {metrics['micro_f1']:.4f}")


if __name__ == "__main__":
    main()
