"""Integration tests for containment and replay."""

import unittest
from eace.experiment import run_integrated_replay, run_three_replays, KNOWN_REPLAY_HASH


class TestContainment(unittest.TestCase):
    def test_integrated_replay_chain_valid(self):
        result = run_integrated_replay()
        self.assertTrue(result.chain_valid)
        self.assertGreater(result.n_events, 0)
        self.assertGreater(result.authorized_count, 0)
        self.assertGreater(result.denied_count, 0)

    def test_three_replays_identical(self):
        hashes = run_three_replays()
        self.assertEqual(len(hashes), 3)
        self.assertEqual(hashes[0], hashes[1])
        self.assertEqual(hashes[1], hashes[2])

    def test_replay_hash_matches_known(self):
        result = run_integrated_replay(seed=0)
        hashes = run_three_replays()
        self.assertEqual(hashes[0], result.final_hash)


if __name__ == "__main__":
    unittest.main()
