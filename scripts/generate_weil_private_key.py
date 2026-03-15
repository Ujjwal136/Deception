"""Generate a WeilChain-compatible secp256k1 private key file.

This writes a 32-byte private key as a lowercase hex string to private_key.wc
in the project root. File permissions are restricted to the current user on
POSIX systems.
"""

from __future__ import annotations

from pathlib import Path

from coincurve import PrivateKey as Secp256k1PrivateKey


def main() -> None:
    project_root = Path(__file__).resolve().parents[1]
    out_path = project_root / "private_key.wc"

    # coincurve generates a cryptographically secure secp256k1 private key.
    key_hex = Secp256k1PrivateKey().secret.hex()
    out_path.write_text(key_hex + "\n", encoding="utf-8")

    # Best-effort restrictive permissions where supported.
    try:
        out_path.chmod(0o600)
    except OSError:
        pass

    print(f"Created {out_path}")


if __name__ == "__main__":
    main()
