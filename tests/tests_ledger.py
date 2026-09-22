"""Unit and adversarial tests for EvidenceLedger."""

import unittest
from eace.ledger import EvidenceLedger, EvidenceEvent, GENESIS, sha256_hex, canonical_json


class TestLedger(unittest.TestCase):
    def _event(self, t: int, action: str = "test") -> EvidenceEvent:
        return EvidenceEvent(
            t=t, action=action, tool="service", target="public", operation="read",
            parameters={}, authorized=True, outcome="OK",
        )

    def test_genesis(self):
        ledger = EvidenceLedger()
        self.assertEqual(ledger.head, GENESIS)
        self.assertEqual(ledger.length, 0)

    def test_append_and_chain(self):
        ledger = EvidenceLedger()
        e1 = self._event(1)
        h1 = ledger.append(e1)
        self.assertNotEqual(h1, GENESIS)
        self.assertTrue(ledger.verify_chain())
        e2 = self._event(2)
        h2 = ledger.append(e2)
        self.assertNotEqual(h2, h1)
        self.assertTrue(ledger.verify_chain())

    def test_canonical_determinism(self):
        a = {"b": 1, "a": 2}
        s1 = canonical_json(a)
        s2 = canonical_json(a)
        self.assertEqual(s1, s2)
        self.assertEqual(s1, '{"a":2,"b":1}')

    def test_sha256(self):
        h = sha256_hex(b"hello")
        self.assertEqual(len(h), 64)
        self.assertEqual(h, sha256_hex("hello"))

    def test_mutation_detected(self):
        ledger = EvidenceLedger()
        e = self._event(1)
        ledger.append(e)
        ledger._events[0].outcome = "TAMPERED"
        self.assertFalse(ledger.verify_chain())

    def test_deletion_detected(self):
        ledger = EvidenceLedger()
        ledger.append(self._event(1))
        ledger.append(self._event(2))
        del ledger._hashes[1]
        self.assertFalse(ledger.verify_chain())

    def test_reordering_detected(self):
        ledger = EvidenceLedger()
        e1 = self._event(1, "a")
        e2 = self._event(2, "b")
        ledger.append(e1)
        ledger.append(e2)
        ledger._events[0], ledger._events[1] = ledger._events[1], ledger._events[0]
        self.assertFalse(ledger.verify_chain())


if __name__ == "__main__":
    unittest.main()
