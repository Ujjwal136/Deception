"""FPE key management — loads AES-256 key and FF3-1 tweak from environment."""

from __future__ import annotations

import os
import secrets

from dotenv import load_dotenv

load_dotenv()

_FPE_KEY: str | None = None
_FPE_TWEAK: str | None = None


def _ensure_loaded() -> None:
    global _FPE_KEY, _FPE_TWEAK
    if _FPE_KEY is not None:
        return
    _FPE_KEY = os.environ.get("FPE_KEY", "").strip()
    _FPE_TWEAK = os.environ.get("FPE_TWEAK", "").strip()

    if not _FPE_KEY or not _FPE_TWEAK:
        generated_key = secrets.token_hex(32)
        generated_tweak = secrets.token_hex(7)
        print(
            "\n[Aegis] FPE_KEY / FPE_TWEAK not found in environment.\n"
            "  Add these lines to your .env file:\n"
            f"    FPE_KEY={generated_key}\n"
            f"    FPE_TWEAK={generated_tweak}\n"
        )
        _FPE_KEY = generated_key
        _FPE_TWEAK = generated_tweak


def get_key() -> str:
    _ensure_loaded()
    return _FPE_KEY  # type: ignore[return-value]


def get_tweak() -> str:
    _ensure_loaded()
    return _FPE_TWEAK  # type: ignore[return-value]
