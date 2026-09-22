"""
Verifier implementations for EACE.

Historical v0.1 — intentionally vulnerable baseline.
v0.2 — fail-closed contract model.

Integrity Is Not Semantic Truth.

The broken v0.1 verifier treated size(stdout) == 1_700_575
as evidence that a protected privileged read actually occurred.
A fake artifact of the same size (and matching manifest hash)
could therefore satisfy integrity while failing semantic evidence.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional


CLAIM_ENUM = {"DENIED", "ALLOWED", "NOT_TESTED", "AMBIGUOUS"}

POSITIVE_CONTROL_HASH = "3ef5aa9cf4eac22347ffd803a3a13b28926e0d8089e82db8edd6f3dc92c84389"
DENIED_BASELINE_HASH = "eebdb9a0b9d5ecab937189eea69435235e71bb56c38b065bc835340b24f02c14"
POSITIVE_SIZE = 1_700_575
DENIED_SIZE = 70


class Verdict(str, Enum):
    COMPLIANT = "COMPLIANT"
    CLAIM_EVIDENCE_MISMATCH = "CLAIM_EVIDENCE_MISMATCH"
    STATE_CHANGE = "STATE_CHANGE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    INCOMPLETE_EVIDENCE = "INCOMPLETE_EVIDENCE"
    MALFORMED_EVIDENCE = "MALFORMED_EVIDENCE"
    AMBIGUOUS = "AMBIGUOUS"
    NOT_TESTED = "NOT_TESTED"
    REFUTED = "REFUTED"
    VOID = "VOID"
    ALLOWED_PROTECTED = "ALLOWED_PROTECTED"


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def parse_claim(raw: Any) -> str:
    if raw is None:
        return "NOT_TESTED"
    s = str(raw).strip().upper()
    if s in CLAIM_ENUM:
        return s
    if s in ("NOT ALLOWED", "NOT_ALLOWED", "DISALLOWED"):
        return "DENIED"
    return "AMBIGUOUS"


class VerifierV01:
    """Intentionally vulnerable baseline verifier."""

    def verify(self, artifact: dict) -> dict:
        claim = str(artifact.get("claim", "")).upper()
        stdout = artifact.get("stdout", b"")
        if isinstance(stdout, str):
            stdout = stdout.encode("utf-8")
        size = len(stdout)

        if size == POSITIVE_SIZE:
            return {
                "verdict": Verdict.ALLOWED_PROTECTED.value,
                "reason": "stdout size matches positive-control size",
                "version": "0.1",
            }

        identity = artifact.get("identity", {})
        if isinstance(identity, list):
            identity = identity[0] if identity else {}

        if "ALLOWED" in claim:
            return {
                "verdict": Verdict.ALLOWED_PROTECTED.value,
                "reason": "claim contains ALLOWED",
                "version": "0.1",
            }

        return {
            "verdict": Verdict.COMPLIANT.value,
            "reason": "default compliant path",
            "version": "0.1",
        }


@dataclass
class Contract:
    schema_version: str
    test_id: str
    expected_uid: str
    expected_selinux_context: str
    expected_workload: str
    expected_target: str
    expected_return_code: int
    expected_outcome: str
    trusted_reference_artifacts: dict

    @classmethod
    def from_dict(cls, d: dict) -> "Contract":
        return cls(
            schema_version=d["schema_version"],
            test_id=d["test_id"],
            expected_uid=str(d["expected_uid"]),
            expected_selinux_context=d["expected_selinux_context"],
            expected_workload=d["expected_workload"],
            expected_target=d["expected_target"],
            expected_return_code=int(d["expected_return_code"]),
            expected_outcome=d["expected_outcome"],
            trusted_reference_artifacts=dict(d.get("trusted_reference_artifacts", {})),
        )


class VerifierV02:
    """Fail-closed verifier pipeline."""

    def __init__(self, contract: Contract | None = None) -> None:
        self.contract = contract

    def verify(self, artifact: dict) -> dict:
        required = ["stdout", "identity", "claim", "manifest"]
        missing = [k for k in required if k not in artifact or artifact[k] is None]
        if missing:
            return self._result(Verdict.INCOMPLETE_EVIDENCE, f"missing fields: {missing}")

        claim = parse_claim(artifact.get("claim"))
        if claim == "AMBIGUOUS":
            return self._result(Verdict.AMBIGUOUS, "claim not in closed enumeration")

        id_result = self._check_identity(artifact.get("identity"))
        if id_result is not None:
            return id_result

        man_result = self._check_manifest(artifact)
        if man_result is not None:
            return man_result

        if self.contract is not None:
            identity = artifact["identity"]
            if isinstance(identity, list):
                identity = identity[0]
            uid = str(identity.get("uid", ""))
            ctx = str(identity.get("selinux_context", ""))
            if uid != self.contract.expected_uid:
                return self._result(
                    Verdict.IDENTITY_MISMATCH,
                    f"uid {uid} != expected {self.contract.expected_uid}",
                )
            if ctx != self.contract.expected_selinux_context:
                return self._result(
                    Verdict.IDENTITY_MISMATCH,
                    f"selinux_context {ctx} != expected {self.contract.expected_selinux_context}",
                )

        if self.contract is not None:
            sem = self._check_semantic(artifact)
            if sem is not None:
                return sem

        stdout = artifact["stdout"]
        if isinstance(stdout, str):
            stdout = stdout.encode("utf-8")
        stdout_hash = sha256_hex(stdout)

        observed = self._infer_observed_outcome(stdout_hash, artifact)

        if claim == "NOT_TESTED":
            return self._result(Verdict.NOT_TESTED, "claim is NOT_TESTED")

        if claim != observed and observed != "AMBIGUOUS":
            return self._result(
                Verdict.CLAIM_EVIDENCE_MISMATCH,
                f"claim={claim} but observed_evidence={observed}",
            )

        if observed == "AMBIGUOUS":
            return self._result(Verdict.AMBIGUOUS, "semantic evidence ambiguous")

        if self.contract and observed != self.contract.expected_outcome:
            return self._result(
                Verdict.REFUTED,
                f"observed {observed} != contract expected {self.contract.expected_outcome}",
            )

        return self._result(Verdict.COMPLIANT, "all checks passed")

    def _result(self, verdict: Verdict, reason: str) -> dict:
        return {
            "verdict": verdict.value,
            "reason": reason,
            "version": "0.2",
        }

    def _check_identity(self, identity: Any) -> Optional[dict]:
        if identity is None:
            return self._result(Verdict.INCOMPLETE_EVIDENCE, "missing identity")
        if isinstance(identity, list):
            if len(identity) == 0:
                return self._result(Verdict.INCOMPLETE_EVIDENCE, "empty identity list")
            if len(identity) > 1:
                return self._result(
                    Verdict.MALFORMED_EVIDENCE,
                    "duplicate identity declarations",
                )
            identity = identity[0]
        if not isinstance(identity, dict):
            return self._result(Verdict.MALFORMED_EVIDENCE, "identity not a dict")
        if "uid" not in identity:
            return self._result(Verdict.INCOMPLETE_EVIDENCE, "identity missing uid")
        uid = str(identity["uid"])
        if not uid:
            return self._result(Verdict.MALFORMED_EVIDENCE, "empty uid")
        if not (uid.isdigit() or uid.startswith("synthetic")):
            return self._result(Verdict.MALFORMED_EVIDENCE, f"malformed uid: {uid}")
        return None

    def _check_manifest(self, artifact: dict) -> Optional[dict]:
        manifest = artifact.get("manifest")
        if manifest is None:
            return self._result(Verdict.INCOMPLETE_EVIDENCE, "missing manifest")
        if not isinstance(manifest, dict):
            return self._result(Verdict.MALFORMED_EVIDENCE, "manifest not a dict")

        algo = manifest.get("algorithm", "").upper()
        if algo and algo not in ("SHA256", "SHA-256"):
            return self._result(Verdict.MALFORMED_EVIDENCE, f"unsupported algorithm {algo}")

        entries = manifest.get("entries", {})
        if not isinstance(entries, dict):
            return self._result(Verdict.MALFORMED_EVIDENCE, "manifest entries not a dict")

        for path, h in entries.items():
            if not isinstance(h, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", h):
                return self._result(
                    Verdict.MALFORMED_EVIDENCE,
                    f"invalid hash for {path}: must be 64 hex chars",
                )
            if ".." in path or path.startswith("/") or "\\" in path:
                return self._result(
                    Verdict.MALFORMED_EVIDENCE,
                    f"path traversal or absolute path: {path}",
                )

        stdout = artifact.get("stdout", b"")
        if isinstance(stdout, str):
            stdout = stdout.encode("utf-8")
        computed = sha256_hex(stdout)
        declared = entries.get("stdout") or entries.get("./stdout") or entries.get("stdout.bin")
        if declared and declared.lower() != computed.lower():
            return self._result(
                Verdict.INTEGRITY_FAILURE,
                "stdout hash does not match manifest",
            )
        return None

    def _check_semantic(self, artifact: dict) -> Optional[dict]:
        stdout = artifact.get("stdout", b"")
        if isinstance(stdout, str):
            stdout = stdout.encode("utf-8")
        h = sha256_hex(stdout)
        trusted = self.contract.trusted_reference_artifacts if self.contract else {}

        if h in trusted.values():
            return None
        if trusted:
            return self._result(
                Verdict.INTEGRITY_FAILURE,
                "stdout hash does not match any trusted reference artifact",
            )
        return None

    def _infer_observed_outcome(self, stdout_hash: str, artifact: dict) -> str:
        if stdout_hash == POSITIVE_CONTROL_HASH:
            return "ALLOWED"
        if stdout_hash == DENIED_BASELINE_HASH:
            return "DENIED"
        stdout = artifact.get("stdout", b"")
        if isinstance(stdout, str):
            stdout = stdout.encode("utf-8")
        if len(stdout) == 0:
            return "NOT_TESTED"
        return "AMBIGUOUS"
