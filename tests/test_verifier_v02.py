"""Unit tests for VerifierV02 claim parsing, identity, and fail-closed behavior."""

import unittest
from eace.verifier import VerifierV02, parse_claim, Verdict, Contract, sha256_hex


class TestClaimParsing(unittest.TestCase):
    def test_closed_enum(self):
        self.assertEqual(parse_claim("DENIED"), "DENIED")
        self.assertEqual(parse_claim("ALLOWED"), "ALLOWED")
        self.assertEqual(parse_claim("NOT_TESTED"), "NOT_TESTED")
        self.assertEqual(parse_claim("AMBIGUOUS"), "AMBIGUOUS")

    def test_not_allowed_does_not_match_allowed(self):
        self.assertEqual(parse_claim("NOT ALLOWED"), "DENIED")
        self.assertEqual(parse_claim("NOT_ALLOWED"), "DENIED")

    def test_garbage_is_ambiguous(self):
        self.assertEqual(parse_claim("YES"), "AMBIGUOUS")
        self.assertEqual(parse_claim(""), "AMBIGUOUS")


class TestV02Basics(unittest.TestCase):
    def setUp(self):
        self.v = VerifierV02()

    def test_missing_fields(self):
        r = self.v.verify({})
        self.assertEqual(r["verdict"], Verdict.INCOMPLETE_EVIDENCE.value)

    def test_missing_identity(self):
        r = self.v.verify({
            "stdout": b"x",
            "claim": "DENIED",
            "manifest": {"algorithm": "SHA-256", "entries": {}},
        })
        self.assertEqual(r["verdict"], Verdict.INCOMPLETE_EVIDENCE.value)

    def test_not_tested_propagates(self):
        stdout = b""
        r = self.v.verify({
            "stdout": stdout,
            "claim": "NOT_TESTED",
            "identity": {"uid": "10505", "selinux_context": "untrusted_app_27"},
            "manifest": {"algorithm": "SHA-256", "entries": {"stdout": sha256_hex(stdout)}},
        })
        self.assertEqual(r["verdict"], Verdict.NOT_TESTED.value)


if __name__ == "__main__":
    unittest.main()
