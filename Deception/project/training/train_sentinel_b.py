"""
Sentinel Layer B — Multi-Layer Perceptron (MLP) from scratch with numpy
=======================================================================

Architecture:
  Input  → char 4-grams + 5-grams (TF-IDF) + meta-features
  Hidden → 128 neurons, ReLU activation
  Output → 1 neuron, sigmoid → P(attack)

Training: mini-batch SGD with momentum, binary cross-entropy loss, L2 reg.

Layer A uses word unigrams + bigrams + char-trigrams with raw counts
and a linear classifier. Layer B uses character n-grams with TF-IDF
weighting and a **non-linear** MLP, so the two layers capture different
signal surfaces.

Outputs: sentinel_b_model.joblib
"""

from __future__ import annotations

import csv
import math
import pickle
import random
import re
from collections import Counter
from pathlib import Path

import numpy as np

TOKEN_RE = re.compile(r"\b\w+\b", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Feature extraction (different from Layer A)
# ---------------------------------------------------------------------------

def _char_ngrams(text: str, ns: tuple[int, ...] = (4, 5)) -> list[str]:
    """Extract character-level n-grams from raw text."""
    lowered = text.lower()
    grams: list[str] = []
    for n in ns:
        for i in range(max(0, len(lowered) - n + 1)):
            grams.append(lowered[i:i + n])
    return grams


def _meta_features(text: str) -> list[float]:
    """Handcrafted features that capture prompt structure."""
    length = len(text)
    words = TOKEN_RE.findall(text)
    n_words = max(len(words), 1)
    upper_chars = sum(1 for c in text if c.isupper())
    digit_chars = sum(1 for c in text if c.isdigit())
    special_chars = sum(1 for c in text if not c.isalnum() and not c.isspace())
    avg_word_len = sum(len(w) for w in words) / n_words if words else 0

    return [
        min(length / 200.0, 1.0),            # normalised length
        min(n_words / 30.0, 1.0),             # normalised word count
        upper_chars / max(length, 1),          # uppercase ratio
        digit_chars / max(length, 1),          # digit ratio
        special_chars / max(length, 1),        # special char ratio
        avg_word_len / 15.0,                   # normalised avg word length
        1.0 if text.isupper() else 0.0,        # all-caps flag
        1.0 if "?" in text else 0.0,           # question mark
        1.0 if "!" in text else 0.0,           # exclamation mark
    ]

N_META = 9  # must match len(_meta_features)


def build_vocab_b(texts: list[str], min_freq: int = 3, max_features: int = 8000) -> dict[str, int]:
    """Build TF-IDF vocabulary from char n-grams."""
    freq: Counter = Counter()
    for text in texts:
        freq.update(set(_char_ngrams(text)))  # use set for document frequency
    # Keep most common features above min_freq
    candidates = [(f, c) for f, c in freq.most_common() if c >= min_freq]
    candidates = candidates[:max_features]
    return {feat: idx for idx, (feat, _) in enumerate(candidates)}


def compute_idf(texts: list[str], vocab: dict[str, int]) -> np.ndarray:
    """Compute IDF weights for the vocabulary."""
    n_docs = len(texts)
    df = np.zeros(len(vocab))
    for text in texts:
        seen = set()
        for gram in _char_ngrams(text):
            idx = vocab.get(gram)
            if idx is not None and idx not in seen:
                df[idx] += 1
                seen.add(idx)
    idf = np.log((n_docs + 1) / (df + 1)) + 1  # smoothed IDF
    return idf.astype(np.float32)


def vectorize_b(text: str, vocab: dict[str, int], idf: np.ndarray) -> np.ndarray:
    """Convert text to TF-IDF char n-gram vector + meta features."""
    tf = np.zeros(len(vocab), dtype=np.float32)
    for gram in _char_ngrams(text):
        idx = vocab.get(gram)
        if idx is not None:
            tf[idx] += 1.0
    # TF normalisation (log1p)
    tf = np.log1p(tf) * idf
    # L2 normalise the TF-IDF part
    norm = np.linalg.norm(tf)
    if norm > 0:
        tf /= norm
    # Append meta features
    meta = np.array(_meta_features(text), dtype=np.float32)
    return np.concatenate([tf, meta])


# ---------------------------------------------------------------------------
# MLP (Multi-Layer Perceptron) — 2 layers, built from scratch
# ---------------------------------------------------------------------------

class MLP:
    """
    Input(n_features) → Dense(128, ReLU) → Dense(1, Sigmoid)
    Trained with mini-batch SGD + momentum + L2 regularisation.
    """

    def __init__(self, n_input: int, n_hidden: int = 128) -> None:
        self.n_input = n_input
        self.n_hidden = n_hidden
        # Xavier initialisation
        scale1 = math.sqrt(2.0 / n_input)
        scale2 = math.sqrt(2.0 / n_hidden)
        self.W1 = (np.random.randn(n_input, n_hidden) * scale1).astype(np.float32)
        self.b1 = np.zeros(n_hidden, dtype=np.float32)
        self.W2 = (np.random.randn(n_hidden, 1) * scale2).astype(np.float32)
        self.b2 = np.zeros(1, dtype=np.float32)

    def forward(self, X: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Forward pass. X shape: (batch, n_input). Returns (output, hidden, pre_act)."""
        z1 = X @ self.W1 + self.b1              # (batch, n_hidden)
        h1 = np.maximum(z1, 0)                   # ReLU
        z2 = h1 @ self.W2 + self.b2              # (batch, 1)
        out = 1.0 / (1.0 + np.exp(-np.clip(z2, -50, 50)))  # sigmoid
        return out, h1, z1

    def predict_proba(self, x: np.ndarray) -> float:
        """Single sample → probability of attack."""
        X = x.reshape(1, -1)
        out, _, _ = self.forward(X)
        return float(out[0, 0])

    def predict(self, x: np.ndarray) -> int:
        return 1 if self.predict_proba(x) >= 0.5 else 0

    def to_dict(self) -> dict:
        return {
            "W1": self.W1.tolist(),
            "b1": self.b1.tolist(),
            "W2": self.W2.tolist(),
            "b2": self.b2.tolist(),
            "n_input": self.n_input,
            "n_hidden": self.n_hidden,
        }

    @classmethod
    def from_dict(cls, d: dict) -> MLP:
        obj = cls(d["n_input"], d["n_hidden"])
        obj.W1 = np.array(d["W1"], dtype=np.float32)
        obj.b1 = np.array(d["b1"], dtype=np.float32)
        obj.W2 = np.array(d["W2"], dtype=np.float32)
        obj.b2 = np.array(d["b2"], dtype=np.float32)
        return obj


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------

def train_mlp(
    X_train: np.ndarray,
    y_train: np.ndarray,
    n_hidden: int = 128,
    n_epochs: int = 30,
    batch_size: int = 64,
    lr: float = 0.005,
    momentum: float = 0.9,
    alpha: float = 1e-4,
) -> MLP:
    """Train MLP with mini-batch SGD + momentum."""
    n_samples, n_features = X_train.shape
    mlp = MLP(n_features, n_hidden)

    # Momentum buffers
    vW1 = np.zeros_like(mlp.W1)
    vb1 = np.zeros_like(mlp.b1)
    vW2 = np.zeros_like(mlp.W2)
    vb2 = np.zeros_like(mlp.b2)

    indices = np.arange(n_samples)

    for epoch in range(1, n_epochs + 1):
        np.random.shuffle(indices)
        epoch_loss = 0.0

        for start in range(0, n_samples, batch_size):
            batch_idx = indices[start:start + batch_size]
            X_b = X_train[batch_idx]
            y_b = y_train[batch_idx].reshape(-1, 1)
            bs = X_b.shape[0]

            # Forward
            out, h1, z1 = mlp.forward(X_b)

            # Loss (binary cross-entropy)
            eps = 1e-7
            loss = -np.mean(y_b * np.log(out + eps) + (1 - y_b) * np.log(1 - out + eps))
            epoch_loss += loss * bs

            # Backward
            dout = (out - y_b) / bs                        # (bs, 1)
            dW2 = h1.T @ dout + alpha * mlp.W2             # (n_hidden, 1)
            db2 = np.sum(dout, axis=0)                      # (1,)
            dh1 = dout @ mlp.W2.T                           # (bs, n_hidden)
            dh1[z1 <= 0] = 0                                # ReLU gradient
            dW1 = X_b.T @ dh1 + alpha * mlp.W1             # (n_input, n_hidden)
            db1 = np.sum(dh1, axis=0)                       # (n_hidden,)

            # SGD with momentum
            vW2 = momentum * vW2 - lr * dW2
            vb2 = momentum * vb2 - lr * db2
            vW1 = momentum * vW1 - lr * dW1
            vb1 = momentum * vb1 - lr * db1

            mlp.W2 += vW2
            mlp.b2 += vb2
            mlp.W1 += vW1
            mlp.b1 += vb1

        epoch_loss /= n_samples

        if epoch % 5 == 0 or epoch == 1:
            preds = (mlp.forward(X_train)[0].flatten() >= 0.5).astype(int)
            acc = np.mean(preds == y_train)
            print(f"  Epoch {epoch:2d}/{n_epochs}: loss={epoch_loss:.4f}  train_acc={acc:.4f}")

    return mlp


def evaluate_mlp(mlp: MLP, X: np.ndarray, y: np.ndarray) -> tuple[float, dict[str, int]]:
    preds = (mlp.forward(X)[0].flatten() >= 0.5).astype(int)
    tp = int(np.sum((preds == 1) & (y == 1)))
    tn = int(np.sum((preds == 0) & (y == 0)))
    fp = int(np.sum((preds == 1) & (y == 0)))
    fn = int(np.sum((preds == 0) & (y == 1)))
    accuracy = (tp + tn) / max(len(y), 1)
    return accuracy, {"tp": tp, "tn": tn, "fp": fp, "fn": fn}


# ---------------------------------------------------------------------------
# Main training entry point
# ---------------------------------------------------------------------------

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


def main() -> None:
    datasets = [Path("aegis_dataset.csv"), Path("aegis_hybrid_dataset.csv")]
    rows: list[tuple[str, int]] = []
    for ds in datasets:
        if ds.exists():
            rows.extend(load_rows(ds))

    if not rows:
        raise FileNotFoundError("No training rows found in local datasets.")

    random.seed(42)
    np.random.seed(42)
    random.shuffle(rows)

    split = int(len(rows) * 0.8)
    train_rows = rows[:split]
    test_rows = rows[split:]

    train_texts = [t for t, _ in train_rows]
    train_labels = np.array([l for _, l in train_rows], dtype=np.float32)
    test_texts = [t for t, _ in test_rows]
    test_labels = np.array([l for _, l in test_rows], dtype=np.float32)

    print(f"Loaded {len(rows)} samples (train={len(train_rows)}, test={len(test_rows)})")

    # Build vocabulary + IDF
    print("Building char n-gram vocabulary...")
    vocab = build_vocab_b(train_texts, min_freq=3, max_features=8000)
    idf = compute_idf(train_texts, vocab)
    print(f"Vocabulary size: {len(vocab)} char n-grams + {N_META} meta features = {len(vocab) + N_META} input dims")

    # Vectorise
    print("Vectorising...")
    X_train = np.array([vectorize_b(t, vocab, idf) for t in train_texts], dtype=np.float32)
    X_test = np.array([vectorize_b(t, vocab, idf) for t in test_texts], dtype=np.float32)

    # Train
    print("\nTraining MLP (Layer B)...")
    mlp = train_mlp(X_train, train_labels, n_hidden=128, n_epochs=30, batch_size=64, lr=0.005)

    # Evaluate
    accuracy, cm = evaluate_mlp(mlp, X_test, test_labels)

    # Save
    model_data = {
        "mlp": mlp.to_dict(),
        "vocab": vocab,
        "idf": idf.tolist(),
    }
    with open("sentinel_b_model.joblib", "wb") as f:
        pickle.dump(model_data, f)

    print(f"\nLayer B Test Accuracy: {accuracy:.4f}")
    print(f"Confusion Matrix: TP={cm['tp']} TN={cm['tn']} FP={cm['fp']} FN={cm['fn']}")
    precision = cm['tp'] / max(cm['tp'] + cm['fp'], 1)
    recall = cm['tp'] / max(cm['tp'] + cm['fn'], 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-9)
    print(f"Precision={precision:.4f}  Recall={recall:.4f}  F1={f1:.4f}")
    print("Saved: sentinel_b_model.joblib")


if __name__ == "__main__":
    main()
