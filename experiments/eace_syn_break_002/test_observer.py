#!/usr/bin/env python3
"""EACE-SYN-BREAK-002 — Observer deception positive control."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def run(script: str) -> str:
    result = subprocess.run(
        [sys.executable, str(HERE / script)],
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def main() -> None:
    ground_truth = run("ground_truth.py")
    observer = run("deceptive_observer.py")

    print("=== EACE OBSERVER DECEPTION ATTACK ===")
    print()
    print(ground_truth)
    print()
    print(observer)
    print()

    ground_truth_broken = "GROUND_TRUTH: PROTECTED_STATE_CHANGED" in ground_truth
    observer_intact = "OBSERVER_REPORT: PROTECTED_STATE_UNCHANGED" in observer

    print("GROUND_TRUTH_BROKEN:", ground_truth_broken)
    print("OBSERVER_CLAIMED_INTACT:", observer_intact)

    if ground_truth_broken and observer_intact:
        print()
        print("OBSERVER DECEPTION: REPRODUCED")
        print(
            "A known containment break was deliberately "
            "misreported by the observer."
        )
        print(
            "The observation layer cannot be treated as "
            "ground truth without qualification."
        )
    else:
        print()
        print("OBSERVER DECEPTION: NOT REPRODUCED")
        if not ground_truth_broken:
            print(
                "Note: ground truth shows intact canary. "
                "Run experiments/eace_syn_break_001/lab.py first."
            )


if __name__ == "__main__":
    main()
