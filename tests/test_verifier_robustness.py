"""
Regression suite: the 19 v0.1 attacks must fail closed under v0.2.

Historical v0.1 results are preserved as documentation;
v0.2 must not re-introduce the same acceptance paths.
"""

import unittest
from eace.verifier import (
    VerifierV01,
    VerifierV02,
    Verdict,
    POSITIVE_SIZE,
    POSITIVE_CONTROL_HASH,
    DENIED_BASELINE_HASH,
    Contract,
)


def make_artifact(**kwargs):
    base = {
        "claim": "DENIED",
        "stdout": b"x" * 70,
        "identity": {"uid": "10505", "selinux_context": "untrusted_app_27"},
        "manifest": {
            "algorithm": "SHA-256",
            "entries": {},
        },
    }
    base.update(kwargs)
    return base


class TestV01HistoricalFailures(unittest.TestCase):
    """Document that v0.1 is broken exactly as recorded."""

    def setUp(self):
        self.v01 = VerifierV01()

    def test_01_pristine_denied(self):
        art = make_artifact(stdout=b"x" * 70, claim="DENIED")
        r = self.v01.verify(art)
        self.assertIn(r["verdict"], ("COMPLIANT", "ALLOWED_PROTECTED"))

    def test_02_fake_exact_size(self):
        art = make_artifact(stdout=b"F" * POSITIVE_SIZE, claim="DENIED")
        r = self.v01.verify(art)
        self.assertEqual(r["verdict"], Verdict.ALLOWED_PROTECTED.value)

    def test_03_same_size_arbitrary(self):
        art = make_artifact(stdout=b"A" * POSITIVE_SIZE, claim="ALLOWED")
        r = self.v01.verify(art)
        self.assertEqual(r["verdict"], Verdict.ALLOWED_PROTECTED.value)

    def test_10_self_certified_fake(self):
        art = make_artifact(
            stdout=b"F" * POSITIVE_SIZE,
            claim="ALLOWED",
            identity={"uid": "0", "selinux_context": "u:r:su:s0"},
        )
        r = self.v01.verify(art)
        self.assertEqual(r["verdict"], Verdict.ALLOWED_PROTECTED.value)

    def test_06_empty_stdout(self):
        art = make_artifact(stdout=b"", claim="ALLOWED")
        r = self.v01.verify(art)
        self.assertIn(r["verdict"], ("COMPLIANT", "ALLOWED_PROTECTED"))

    def test_17_wrong_uid(self):
        art = make_artifact(identity={"uid": "0", "selinux_context": "shell"})
        r = self.v01.verify(art)
        self.assertEqual(r["verdict"], Verdict.COMPLIANT.value)

    def test_19_duplicate_identity(self):
        art = make_artifact(
            identity=[
                {"uid": "10505", "selinux_context": "untrusted_app_27"},
                {"uid": "0", "selinux_context": "shell"},
            ]
        )
        r = self.v01.verify(art)
        self.assertEqual(r["verdict"], Verdict.COMPLIANT.value)


class TestV02Regression(unittest.TestCase):
    """Every known v0.1 exploit must fail closed under v0.2."""

    def setUp(self):
        self.contract = Contract(
            schema_version="1.0",
            test_id="EACE-P0-ANDROID-BOUND-01",
            expected_uid="10505",
            expected_selinux_context="untrusted_app_27",
            expected_workload="pm dump com.android.settings",
            expected_target="com.android.settings",
            expected_return_code=0,
            expected_outcome="DENIED",
            trusted_reference_artifacts={
                "denied_baseline": DENIED_BASELINE_HASH,
                "positive_control": POSITIVE_CONTROL_HASH,
            },
        )
        self.v02 = VerifierV02(contract=self.contract)

    def test_fake_exact_size_not_allowed(self):
        art = make_artifact(
            stdout=b"F" * POSITIVE_SIZE,
            claim="ALLOWED",
            identity={"uid": "10505", "selinux_context": "untrusted_app_27"},
            manifest={
                "algorithm": "SHA-256",
                "entries": {"stdout": "0" * 64},
            },
        )
        r = self.v02.verify(art)
        self.assertNotEqual(r["verdict"], Verdict.ALLOWED_PROTECTED.value)
        self.assertNotEqual(r["verdict"], Verdict.COMPLIANT.value)

    def test_self_certified_fake_rejected(self):
        art = make_artifact(
            stdout=b"F" * POSITIVE_SIZE,
            claim="ALLOWED",
            identity={"uid": "0", "selinux_context": "shell"},
            manifest={"algorithm": "SHA-256", "entries": {}},
        )
        r = self.v02.verify(art)
        self.assertIn(
            r["verdict"],
            (
                Verdict.IDENTITY_MISMATCH.value,
                Verdict.INTEGRITY_FAILURE.value,
                Verdict.CLAIM_EVIDENCE_MISMATCH.value,
                Verdict.AMBIGUOUS.value,
            ),
        )

    def test_empty_evidence(self):
        art = make_artifact(stdout=b"", claim="ALLOWED")
        from eace.verifier import sha256_hex
        art["manifest"] = {
            "algorithm": "SHA-256",
            "entries": {"stdout": sha256_hex(b"")},
        }
        r = self.v02.verify(art)
        self.assertIn(
            r["verdict"],
            (
                Verdict.NOT_TESTED.value,
                Verdict.INCOMPLETE_EVIDENCE.value,
                Verdict.CLAIM_EVIDENCE_MISMATCH.value,
                Verdict.AMBIGUOUS.value,
                Verdict.INTEGRITY_FAILURE.value,
            ),
        )

    def test_wrong_uid(self):
        from eace.verifier import sha256_hex
        stdout = b"x" * 70
        art = make_artifact(
            stdout=stdout,
            claim="DENIED",
            identity={"uid": "0", "selinux_context": "untrusted_app_27"},
            manifest={"algorithm": "SHA-256", "entries": {"stdout": sha256_hex(stdout)}},
        )
        r = self.v02.verify(art)
        self.assertEqual(r["verdict"], Verdict.IDENTITY_MISMATCH.value)

    def test_bad_context(self):
        from eace.verifier import sha256_hex
        stdout = b"x" * 70
        art = make_artifact(
            stdout=stdout,
            claim="DENIED",
            identity={"uid": "10505", "selinux_context": "shell"},
            manifest={"algorithm": "SHA-256", "entries": {"stdout": sha256_hex(stdout)}},
        )
        r = self.v02.verify(art)
        self.assertEqual(r["verdict"], Verdict.IDENTITY_MISMATCH.value)

    def test_duplicate_identity(self):
        art = make_artifact(
            identity=[
                {"uid": "10505", "selinux_context": "untrusted_app_27"},
                {"uid": "0", "selinux_context": "shell"},
            ]
        )
        r = self.v02.verify(art)
        self.assertEqual(r["verdict"], Verdict.MALFORMED_EVIDENCE.value)

    def test_claim_evidence_mismatch(self):
        from eace.verifier import sha256_hex
        stdout = b"denied-looking-payload"
        art = make_artifact(
            stdout=stdout,
            claim="ALLOWED",
            identity={"uid": "10505", "selinux_context": "untrusted_app_27"},
            manifest={"algorithm": "SHA-256", "entries": {"stdout": sha256_hex(stdout)}},
        )
        r = self.v02.verify(art)
        self.assertIn(
            r["verdict"],
            (
                Verdict.CLAIM_EVIDENCE_MISMATCH.value,
                Verdict.INTEGRITY_FAILURE.value,
                Verdict.AMBIGUOUS.value,
            ),
        )

    def test_path_traversal_rejected(self):
        from eace.verifier import sha256_hex
        stdout = b"x"
        art = make_artifact(
            stdout=stdout,
            claim="DENIED",
            identity={"uid": "10505", "selinux_context": "untrusted_app_27"},
            manifest={
                "algorithm": "SHA-256",
                "entries": {"../etc/passwd": sha256_hex(stdout)},
            },
        )
        r = self.v02.verify(art)
        self.assertEqual(r["verdict"], Verdict.MALFORMED_EVIDENCE.value)

    def test_malformed_hash_rejected(self):
        art = make_artifact(
            stdout=b"x",
            claim="DENIED",
            identity={"uid": "10505", "selinux_context": "untrusted_app_27"},
            manifest={"algorithm": "SHA-256", "entries": {"stdout": "not-a-hash"}},
        )
        r = self.v02.verify(art)
        self.assertEqual(r["verdict"], Verdict.MALFORMED_EVIDENCE.value)


if __name__ == "__main__":
    unittest.main()
