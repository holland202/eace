"""Tests for synthetic world and services."""

import unittest
from eace.synthetic_services import SyntheticWorld, SyntheticService


class TestWorld(unittest.TestCase):
    def setUp(self):
        self.world = SyntheticWorld()

    def test_public_read(self):
        r = self.world.invoke("public", "read", key="greeting", authorized=True)
        self.assertTrue(r.success)
        self.assertEqual(r.data, "hello-eace")

    def test_protected_denied_without_auth(self):
        r = self.world.invoke("protected", "dump", authorized=False)
        self.assertFalse(r.success)
        self.assertEqual(r.status, "DENIED")

    def test_protected_allowed_with_auth(self):
        r = self.world.invoke("protected", "dump", authorized=True)
        self.assertTrue(r.success)
        self.assertEqual(r.status, "OK")
        self.assertIsInstance(r.data, (bytes, bytearray))
        self.assertGreater(len(r.data), 1_000_000)

    def test_unknown_service(self):
        r = self.world.invoke("nope", "read", authorized=True)
        self.assertEqual(r.status, "NO_SERVICE")

    def test_ground_truth_logged(self):
        self.world.invoke("public", "read", key="greeting", authorized=True)
        gt = self.world.ground_truth()
        self.assertEqual(len(gt), 1)
        self.assertEqual(gt[0]["service"], "public")


if __name__ == "__main__":
    unittest.main()
