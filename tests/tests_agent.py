"""Tests for SyntheticAgent."""

import unittest
from eace.clock import DeterministicClock
from eace.ledger import EvidenceLedger
from eace.governor import ToolGovernor, Capability
from eace.synthetic_services import SyntheticWorld
from eace.agent import SyntheticAgent, AgentAction


class TestAgent(unittest.TestCase):
    def setUp(self):
        self.clock = DeterministicClock()
        self.ledger = EvidenceLedger()
        self.world = SyntheticWorld()
        self.gov = ToolGovernor()
        self.gov.add_capability(Capability("service", "public", "read"))
        self.agent = SyntheticAgent(self.world, self.gov, self.ledger, self.clock)

    def test_authorized_action(self):
        action = AgentAction("service", "public", "read", {"key": "greeting"}, claim="ALLOWED")
        rec = self.agent.act(action)
        self.assertTrue(rec["decision"].allowed)
        self.assertEqual(rec["response"].status, "OK")
        self.assertEqual(self.ledger.length, 1)
        self.assertTrue(self.ledger.verify_chain())

    def test_unauthorized_action(self):
        action = AgentAction("service", "protected", "dump", {}, claim="DENIED")
        rec = self.agent.act(action)
        self.assertFalse(rec["decision"].allowed)
        self.assertEqual(rec["response"].status, "DENIED")


if __name__ == "__main__":
    unittest.main()
