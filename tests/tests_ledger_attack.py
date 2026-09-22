"""Adversarial tests against the evidence ledger."""

import unittest
from eace.ledger import EvidenceLedger, EvidenceEvent, sha256_hex


class TestLedgerAttack(unittest.TestCase):
    def _ev(self, t, action="a"):
        return EvidenceEvent(
            t=t, action=action, tool="t", target="x", operation="o",
            parameters={}, authorized=True, outcome="OK",
        )

    def test_hash_forgery_fails(self):
        ledger = EvidenceLedger()
        ledger.append(self._ev(1))
        ledger._hashes[-1] = "f" * 64
        self.assertFalse(ledger.verify_chain())

    def test_event_deletion_fails(self):
        ledger = EvidenceLedger()
        ledger.append(self._ev(1))
        ledger.append(self._ev(2))
        ledger._events.pop(0)
        self.assertFalse(ledger.verify_chain())

    def test_payload_mutation_fails(self):
        ledger = EvidenceLedger()
        e = self._ev(1)
        ledger.append(e)
        ledger._events[0].parameters["injected"] = "evil"
        self.assertFalse(ledger.verify_chain())


if __name__ == "__main__":
    unittest.main()
