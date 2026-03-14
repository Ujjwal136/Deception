"""FF3-1 Format-Preserving Encryption for Indian PII types."""

from __future__ import annotations

import logging
import re

from ff3 import FF3Cipher

from firewall.key_manager import get_key, get_tweak

logger = logging.getLogger(__name__)

# Module-level ciphers (initialised lazily)
_numeric_cipher: FF3Cipher | None = None
_alphanum_cipher: FF3Cipher | None = None


def _get_numeric_cipher() -> FF3Cipher:
    """Radix 10: digits 0-9."""
    global _numeric_cipher
    if _numeric_cipher is None:
        _numeric_cipher = FF3Cipher(get_key(), get_tweak(), 10)
    return _numeric_cipher


def _get_alphanum_cipher() -> FF3Cipher:
    """Radix 36: digits 0-9 + a-z. We upper/lower-case externally."""
    global _alphanum_cipher
    if _alphanum_cipher is None:
        _alphanum_cipher = FF3Cipher(get_key(), get_tweak(), 36)
    return _alphanum_cipher


# ---------------------------------------------------------------------------
# Encrypt functions
# ---------------------------------------------------------------------------

def encrypt_aadhaar(value: str) -> str:
    try:
        digits = re.sub(r"\s", "", value)
        if len(digits) != 12 or not digits.isdigit():
            return "[AADHAAR_REDACTED]"
        encrypted = _get_numeric_cipher().encrypt(digits)
        logger.debug("FPE encrypted entity: AADHAAR")
        return f"{encrypted[:4]} {encrypted[4:8]} {encrypted[8:]}"
    except Exception:
        return "[AADHAAR_REDACTED]"


def decrypt_aadhaar(value: str) -> str:
    try:
        digits = re.sub(r"\s", "", value)
        decrypted = _get_numeric_cipher().decrypt(digits)
        return f"{decrypted[:4]} {decrypted[4:8]} {decrypted[8:]}"
    except Exception:
        return value


def encrypt_pan(value: str) -> str:
    try:
        pan = value.strip()
        if len(pan) != 10:
            return "[PAN_REDACTED]"
        encrypted = _get_alphanum_cipher().encrypt(pan.lower())
        logger.debug("FPE encrypted entity: PAN")
        return encrypted.upper()
    except Exception:
        return "[PAN_REDACTED]"


def decrypt_pan(value: str) -> str:
    try:
        return _get_alphanum_cipher().decrypt(value.lower()).upper()
    except Exception:
        return value


def encrypt_account_no(value: str) -> str:
    try:
        digits = re.sub(r"\s", "", value)
        if not digits.isdigit() or not (11 <= len(digits) <= 16):
            return "[ACCOUNT_NO_REDACTED]"
        encrypted = _get_numeric_cipher().encrypt(digits)
        logger.debug("FPE encrypted entity: ACCOUNT_NO")
        return encrypted
    except Exception:
        return "[ACCOUNT_NO_REDACTED]"


def decrypt_account_no(value: str) -> str:
    try:
        return _get_numeric_cipher().decrypt(re.sub(r"\s", "", value))
    except Exception:
        return value


def encrypt_phone(value: str) -> str:
    try:
        stripped = re.sub(r"[+\-\s]", "", value)
        if stripped.startswith("91") and len(stripped) == 12:
            core = stripped[2:]
        elif len(stripped) == 10:
            core = stripped
        else:
            return "[PHONE_REDACTED]"
        encrypted = _get_numeric_cipher().encrypt(core)
        logger.debug("FPE encrypted entity: PHONE")
        return f"+91 {encrypted}"
    except Exception:
        return "[PHONE_REDACTED]"


def decrypt_phone(value: str) -> str:
    try:
        stripped = re.sub(r"[+\-\s]", "", value)
        if stripped.startswith("91") and len(stripped) == 12:
            core = stripped[2:]
        else:
            core = stripped[-10:]
        decrypted = _get_numeric_cipher().decrypt(core)
        return f"+91 {decrypted}"
    except Exception:
        return value


def encrypt_ifsc(value: str) -> str:
    try:
        code = value.strip()
        if len(code) != 11:
            return "[IFSC_REDACTED]"
        bank_prefix = code[:4].upper()
        remainder = code[4:]
        encrypted = _get_alphanum_cipher().encrypt(remainder.lower())
        logger.debug("FPE encrypted entity: IFSC")
        return bank_prefix + encrypted.upper()
    except Exception:
        return "[IFSC_REDACTED]"


def decrypt_ifsc(value: str) -> str:
    try:
        code = value.strip()
        bank_prefix = code[:4].upper()
        remainder = code[4:]
        decrypted = _get_alphanum_cipher().decrypt(remainder.lower())
        return bank_prefix + decrypted.upper()
    except Exception:
        return value


# Mapping of entity type → encrypt function
FPE_ENCRYPT_MAP: dict[str, callable] = {
    "AADHAAR": encrypt_aadhaar,
    "PAN": encrypt_pan,
    "ACCOUNT_NO": encrypt_account_no,
    "PHONE": encrypt_phone,
    "IFSC": encrypt_ifsc,
}

FPE_DECRYPT_MAP: dict[str, callable] = {
    "AADHAAR": decrypt_aadhaar,
    "PAN": decrypt_pan,
    "ACCOUNT_NO": decrypt_account_no,
    "PHONE": decrypt_phone,
    "IFSC": decrypt_ifsc,
}
