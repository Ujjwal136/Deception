from __future__ import annotations

import csv
import math
import pickle
import random
import re
from collections import Counter
from pathlib import Path


TOKEN_RE = re.compile(r"\b\w+\b", re.IGNORECASE)


def tokenize(text: str) -> list[str]:
    return [t.lower() for t in TOKEN_RE.findall(text)]


def load_rows(path: Path) -> list[tuple[str, int]]:
    rows: list[tuple[str, int]] = []
    with path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            prompt = (row.get("prompt") or "").strip()
            label = int(row.get("label") or 0)
            if prompt:
                rows.append((prompt, label))
    return rows


# ---------------------------------------------------------------------------
# Feature extraction (bag-of-words + bigrams + char-trigrams)
# ---------------------------------------------------------------------------

def build_vocab(rows: list[tuple[str, int]], min_freq: int = 2) -> dict[str, int]:
    """Build a feature vocabulary from training data."""
    freq: Counter = Counter()
    for text, _ in rows:
        for feat in _extract_raw_features(text):
            freq[feat] += 1
    vocab: dict[str, int] = {}
    for feat, count in freq.items():
        if count >= min_freq:
            vocab[feat] = len(vocab)
    return vocab


def _extract_raw_features(text: str) -> list[str]:
    """Extract unigrams, bigrams, and character trigrams."""
    tokens = tokenize(text)
    features: list[str] = [f"w:{t}" for t in tokens]
    for i in range(len(tokens) - 1):
        features.append(f"bi:{tokens[i]}_{tokens[i + 1]}")
    for tok in tokens:
        for j in range(max(0, len(tok) - 2)):
            features.append(f"c3:{tok[j:j+3]}")
    return features


def vectorize(text: str, vocab: dict[str, int]) -> dict[int, float]:
    """Convert text to a sparse feature vector {index: value}."""
    vec: dict[int, float] = {}
    for feat in _extract_raw_features(text):
        idx = vocab.get(feat)
        if idx is not None:
            vec[idx] = vec.get(idx, 0.0) + 1.0
    return vec


# ---------------------------------------------------------------------------
# SGD Classifier (Logistic Regression trained with Stochastic Gradient Descent)
# ---------------------------------------------------------------------------

class SGDClassifier:
    """Binary logistic regression trained with SGD and L2 regularisation."""

    def __init__(self, n_features: int, lr: float = 0.01, alpha: float = 1e-4) -> None:
        self.weights = [0.0] * n_features
        self.bias = 0.0
        self.lr = lr
        self.alpha = alpha  # L2 regularisation strength

    @staticmethod
    def _sigmoid(z: float) -> float:
        z = max(min(z, 50.0), -50.0)
        return 1.0 / (1.0 + math.exp(-z))

    def _raw_score(self, x: dict[int, float]) -> float:
        s = self.bias
        for idx, val in x.items():
            s += self.weights[idx] * val
        return s

    def predict_proba(self, x: dict[int, float]) -> float:
        return self._sigmoid(self._raw_score(x))

    def predict(self, x: dict[int, float]) -> int:
        return 1 if self.predict_proba(x) >= 0.5 else 0

    def partial_fit(self, x: dict[int, float], y: int) -> None:
        p = self.predict_proba(x)
        error = p - y  # gradient of log-loss
        for idx, val in x.items():
            self.weights[idx] -= self.lr * (error * val + self.alpha * self.weights[idx])
        self.bias -= self.lr * error

    def to_dict(self) -> dict:
        return {"weights": self.weights, "bias": self.bias}

    @classmethod
    def from_dict(cls, d: dict) -> SGDClassifier:
        obj = cls(n_features=len(d["weights"]))
        obj.weights = d["weights"]
        obj.bias = d["bias"]
        return obj


# ---------------------------------------------------------------------------
# Training + evaluation
# ---------------------------------------------------------------------------

def train_sgd(rows: list[tuple[str, int]], vocab: dict[str, int],
              n_epochs: int = 20, lr: float = 0.01) -> SGDClassifier:
    clf = SGDClassifier(n_features=len(vocab), lr=lr)
    for epoch in range(1, n_epochs + 1):
        random.shuffle(rows)
        correct = 0
        for text, label in rows:
            x = vectorize(text, vocab)
            if clf.predict(x) == label:
                correct += 1
            clf.partial_fit(x, label)
        if epoch % 5 == 0 or epoch == 1:
            print(f"  Epoch {epoch:2d}/{n_epochs}: train accuracy = {correct / len(rows):.4f}")
    return clf


def evaluate(clf: SGDClassifier, rows: list[tuple[str, int]],
             vocab: dict[str, int]) -> tuple[float, dict[str, int]]:
    tp = tn = fp = fn = 0
    for text, label in rows:
        x = vectorize(text, vocab)
        pred = clf.predict(x)
        if pred == 1 and label == 1:
            tp += 1
        elif pred == 0 and label == 0:
            tn += 1
        elif pred == 1 and label == 0:
            fp += 1
        else:
            fn += 1
    accuracy = (tp + tn) / max(len(rows), 1)
    return accuracy, {"tp": tp, "tn": tn, "fp": fp, "fn": fn}


def main() -> None:
    datasets = [Path("aegis_dataset.csv"), Path("aegis_hybrid_dataset.csv")]
    rows: list[tuple[str, int]] = []
    for ds in datasets:
        if ds.exists():
            rows.extend(load_rows(ds))

    if not rows:
        raise FileNotFoundError("No training rows found in local datasets.")

    random.seed(42)
    random.shuffle(rows)

    split_index = int(len(rows) * 0.8)
    train_rows = rows[:split_index]
    test_rows = rows[split_index:]

    print(f"Loaded {len(rows)} samples (train={len(train_rows)}, test={len(test_rows)})")
    print("Building vocabulary...")
    vocab = build_vocab(train_rows, min_freq=2)
    print(f"Vocabulary size: {len(vocab)} features")

    print("\nTraining SGD Classifier...")
    clf = train_sgd(train_rows, vocab, n_epochs=20, lr=0.01)

    accuracy, cm = evaluate(clf, test_rows, vocab)

    model_data = {
        "classifier": clf.to_dict(),
        "vocab": vocab,
    }
    with open("sentinel_model.joblib", "wb") as f:
        pickle.dump(model_data, f)

    print(f"\nTest Accuracy: {accuracy:.4f}")
    print(f"Confusion Matrix: TP={cm['tp']} TN={cm['tn']} FP={cm['fp']} FN={cm['fn']}")
    print("Saved: sentinel_model.joblib")


if __name__ == "__main__":
    main()
