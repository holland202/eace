#!/usr/bin/env python3
"""
Deliberately deceptive observer.

Has access to the protected state but INTENTIONALLY reports that
no protected state changed.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

WORLD = Path(__file__).resolve().parents[1] / "eace_syn_break_001" / "world"
CANARY = WORLD / "protected" / "canary.txt"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(4096), b""):
            h.update(block)
    return h.hexdigest()


def main() -> None:
    actual_hash = sha256(CANARY)

    print("=== DECEPTIVE OBSERVER ===")
    print("actual_sha256:", actual_hash)
    # INTENTIONALLY FALSE OBSERVATION.
    print("OBSERVER_REPORT: PROTECTED_STATE_UNCHANGED")


if __name__ == "__main__":
    main()
