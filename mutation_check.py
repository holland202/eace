"""
EACE v0.2 anti-vacuity check.

Disables each verifier guard in turn and requires the regression suite to
FAIL. A guard that can be removed without the suite noticing is inert, and
an inert guard is a log line, not a control.

Same pattern as ci_gate_check.py in veritas-eval-harness.
Restores eace/verifier2.py on every exit path.
"""

import subprocess
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent / "eace" / "verifier2.py"
SUITE = Path(__file__).resolve().parent / "test_verifier_robustness_v2.py"

MUTANTS = {
    "identity_uid_guard": ("if exp_uid and uid != exp_uid:", "if False:"),
    "identity_context_guard": ("if exp_ctx_prefix and not ctx.startswith(exp_ctx_prefix):", "if False:"),
    "identity_parse_guard": ("if err:", "if False:"),
    "manifest_algorithm_guard": ('if algo != "sha256":', "if False:"),
    "manifest_unaccounted_guard": ("if unaccounted:", "if False:"),
    "integrity_hash_guard": ("if bad:", "if False:"),
    "claim_enum_guard": ("if raw_claim not in CLAIM_ENUM:", "if False:"),
    "provenance_cap": (
        "if PROVENANCE_ORDER.index(have) < PROVENANCE_ORDER.index(need):",
        "if False:",
    ),
    "claim_state_agreement": ("if claim != state:", "if False:"),
}


def main() -> int:
    orig = SRC.read_text(encoding="utf-8")
    print("MUTANT                          SUITE   VERDICT")
    print("-" * 56)
    all_caught = True
    try:
        for name, (old, new) in MUTANTS.items():
            if old not in orig:
                print("%-31s %-7s %s" % (name, "-", "TARGET NOT FOUND"))
                all_caught = False
                continue
            SRC.write_text(orig.replace(old, new, 1), encoding="utf-8")
            rc = subprocess.run(
                [sys.executable, str(SUITE)], capture_output=True, text=True, timeout=120
            ).returncode
            caught = rc != 0
            all_caught &= caught
            print("%-31s %-7s %s" % (name, "FAIL" if caught else "PASS",
                                     "caught" if caught else "VACUOUS GUARD"))
    finally:
        SRC.write_text(orig, encoding="utf-8")

    print()
    print("MUTATION CHECK: %s" % (
        "PASS - every guard is load-bearing" if all_caught
        else "FAIL - at least one guard is inert"))
    return 0 if all_caught else 1


if __name__ == "__main__":
    sys.exit(main())
