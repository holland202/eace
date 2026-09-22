#!/usr/bin/env python3
"""
EACE SWAY prediction regression: contract completeness.

Registered predictions:
  C1 missing expected_uid              -> CONTRACT_INCOMPLETE
  C2 missing expected_context_prefix   -> CONTRACT_INCOMPLETE
  C3 missing rc_expect                 -> CONTRACT_INCOMPLETE
  C4 missing required_provenance       -> CONTRACT_INCOMPLETE

Benign control:
  complete contract must pass the completeness gate and continue into
  normal evidence verification.

Synthetic evidence only. No Android command is executed.
"""

import hashlib
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from eace.verifier2 import verify


TEST_ID = "EACE-SWAY-CONTRACT-COMPLETENESS"
DENIED_TEXT = (
    "Permission Denial: can't dump PackageManager "
    "from pid=123, uid={expected_uid} "
    "requires android.permission.DUMP\n"
)
IDENTITY = "uid=10505\ncontext=u:r:untrusted_app_27:s0\n"


def write_evidence(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)

    stdout = DENIED_TEXT.format(expected_uid="10505").encode()
    (root / "stdout.txt").write_bytes(stdout)
    (root / "identity.txt").write_text(IDENTITY, encoding="utf-8")

    metadata = {
        "test_id": TEST_ID,
        "claim": "DENIED",
        "rc": 1,
        "workload": "cmd package dump com.termux",
        "target": "com.termux",
        "collector": {
            "uid": "10505",
            "context": "u:r:untrusted_app_27:s0",
        },
    }
    (root / "metadata.json").write_text(
        json.dumps(metadata, indent=2), encoding="utf-8"
    )

    files = {
        name: hashlib.sha256((root / name).read_bytes()).hexdigest()
        for name in ("stdout.txt", "identity.txt", "metadata.json")
    }
    manifest = {"algorithm": "sha256", "files": files}
    (root / "manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )


def complete_contract() -> dict:
    return {
        "required_artifacts": [
            "stdout.txt",
            "identity.txt",
            "metadata.json",
            "manifest.json",
        ],
        "allowed_state": "ALLOWED_PROTECTED",
        "discriminants": {
            "denied": {
                "all_of": [
                    "Permission Denial",
                    "can't dump PackageManager",
                    "uid={expected_uid}",
                    "android\\.permission\\.DUMP",
                ],
                "none_of": ["^DUMP OF SERVICE package:"],
            },
            "allowed": {
                "all_of": [
                    "^DUMP OF SERVICE package:",
                    "Activity Resolver Table:",
                    "com\\.termux",
                ],
                "none_of": ["Permission Denial"],
            },
        },
        "rc_expect": {"DENIED": [0, 1], "ALLOWED_PROTECTED": [0]},
        "target": "com.termux",
        "expected_uid": "10505",
        "expected_context_prefix": "u:r:untrusted_app_27:s0",
        "expected_outcome": "DENIED",
        "required_provenance": "SELF_REPORTED",
        "negative_reference_sha256": hashlib.sha256(
            DENIED_TEXT.format(expected_uid="10505").encode()
        ).hexdigest(),
    }


def write_contract(path: Path, contract: dict) -> None:
    doc = {
        "contract_version": "sway-test-1.0.0",
        "tests": {TEST_ID: contract},
    }
    path.write_text(json.dumps(doc, indent=2), encoding="utf-8")


def main() -> int:
    fields = (
        "expected_uid",
        "expected_context_prefix",
        "rc_expect",
        "required_provenance",
    )

    with tempfile.TemporaryDirectory(prefix="eace_contract_complete_") as td:
        base = Path(td)
        evidence = base / "evidence"
        contracts = base / "contracts.json"
        write_evidence(evidence)

        failures = []

        # Benign control: all four fields present.
        control_contract = complete_contract()
        write_contract(contracts, control_contract)
        control = verify(evidence, contracts, test_id=TEST_ID)
        if control["verdict"] == "CONTRACT_INCOMPLETE":
            failures.append(
                "BENIGN_CONTROL unexpectedly hit CONTRACT_INCOMPLETE"
            )
        print(
            "BENIGN_CONTROL complete contract -> %s"
            % control["verdict"]
        )

        # Registered negative mutants: omit exactly one field.
        for field in fields:
            mutant = complete_contract()
            del mutant[field]
            write_contract(contracts, mutant)

            result = verify(evidence, contracts, test_id=TEST_ID)
            verdict = result["verdict"]
            reason = " | ".join(result["reasons"])

            ok = (
                verdict == "CONTRACT_INCOMPLETE"
                and field in reason
            )
            print(
                "%s missing %-25s -> %-22s %s"
                % (
                    field,
                    "",
                    verdict,
                    "PASS" if ok else "FAIL",
                )
            )

            if not ok:
                failures.append(
                    "%s: expected CONTRACT_INCOMPLETE naming %s; "
                    "got %s (%s)"
                    % (field, field, verdict, reason)
                )

        print("=" * 72)
        if failures:
            print("FAILURES: %d" % len(failures))
            for failure in failures:
                print(" - %s" % failure)
            return 1

        print("C1-C4: PASS")
        print("BENIGN CONTROL: PASS")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
