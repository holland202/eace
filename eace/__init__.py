"""
EACE — Evidence-Anchored Agent Containment Evaluation

A local research framework for testing agent capability boundaries,
evidence integrity, reproducibility, and verifier validity.

This package is NOT a proof of AI containment or AI safety.
It is an experimental instrument for adversarial evaluation.
"""

__version__ = "0.2.0-dev"
__status__ = "research"

from eace.clock import DeterministicClock
from eace.ledger import EvidenceLedger
from eace.governor import ToolGovernor
from eace.synthetic_services import SyntheticWorld, SyntheticService
from eace.agent import SyntheticAgent
from eace.verifier import VerifierV01, VerifierV02

__all__ = [
    "DeterministicClock",
    "EvidenceLedger",
    "ToolGovernor",
    "SyntheticWorld",
    "SyntheticService",
    "SyntheticAgent",
    "VerifierV01",
    "VerifierV02",
]
