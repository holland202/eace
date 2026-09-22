"""
Observer deception experiment.

Demonstrates that a false observation can be recorded that contradicts
ground truth. The synthetic test represents the contradiction;
it does not claim a real-world measurement attack was performed.
"""

import unittest
from eace.synthetic_services import SyntheticWorld


class TestObserverAttack(unittest.TestCase):
    def test_ground_truth_vs_false_observation(self):
        world = SyntheticWorld()
        r = world.invoke("protected", "dump", authorized=False)
        self.assertEqual(r.status, "DENIED")

        ground = world.ground_truth()
        self.assertEqual(len(ground), 1)
        self.assertFalse(ground[0]["authorized"])

        false_observation = {
            "service": "protected",
            "operation": "dump",
            "authorized": True,
            "status": "OK",
            "stdout_len": 1_700_575,
        }

        self.assertNotEqual(
            false_observation["authorized"],
            ground[0]["authorized"],
        )
        self.assertNotEqual(false_observation["status"], r.status)


if __name__ == "__main__":
    unittest.main()
