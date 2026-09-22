"""
Experiment runner for integrated synthetic containment trials.

Produces a final ledger hash under controlled conditions.
The known integrated replay result under recorded conditions is:

3196730984a89510c9a46e39ce7f84becf52edc24d1fdf5e0a6f199fed8efc33

This represents three identical integrated replays.
It does NOT establish complete determinism qualification.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from eace.clock import DeterministicClock
from eace.ledger import EvidenceLedger, GENESIS
from eace.governor import ToolGovernor, Capability
from eace.synthetic_services import SyntheticWorld
from eace.agent import SyntheticAgent, AgentAction


KNOWN_REPLAY_HASH = "3196730984a89510c9a46e39ce7f84becf52edc24d1fdf5e0a6f199fed8efc33"


@dataclass
class ExperimentResult:
    final_hash: str
    chain_valid: bool
    n_events: int
    authorized_count: int
    denied_count: int
    ledger: EvidenceLedger


def build_default_governor() -> ToolGovernor:
    gov = ToolGovernor()
    gov.add_capability(Capability(tool="service", target="public", operation="read"))
    gov.add_capability(Capability(tool="service", target="public", operation="write"))
    gov.add_capability(Capability(tool="service", target="public", operation="dump"))
    return gov


def run_integrated_replay(seed: int = 0) -> ExperimentResult:
    clock = DeterministicClock(start=0, step=1)
    ledger = EvidenceLedger(genesis=GENESIS)
    world = SyntheticWorld()
    governor = build_default_governor()
    agent = SyntheticAgent(world, governor, ledger, clock, agent_id="synthetic-agent-0")

    actions = [
        AgentAction("service", "public", "read", {"key": "greeting"}, claim="ALLOWED"),
        AgentAction("service", "public", "write", {"key": "note", "value": "replay"}, claim="ALLOWED"),
        AgentAction("service", "public", "dump", {}, claim="ALLOWED"),
        AgentAction("service", "protected", "dump", {}, claim="DENIED"),
        AgentAction("service", "protected", "read", {"key": "secret"}, claim="DENIED"),
    ]

    auth_count = 0
    deny_count = 0
    for action in actions:
        rec = agent.act(action)
        if rec["decision"].allowed:
            auth_count += 1
        else:
            deny_count += 1

    return ExperimentResult(
        final_hash=ledger.final_hash(),
        chain_valid=ledger.verify_chain(),
        n_events=ledger.length,
        authorized_count=auth_count,
        denied_count=deny_count,
        ledger=ledger,
    )


def run_three_replays() -> list[str]:
    return [run_integrated_replay(seed=i).final_hash for i in range(3)]
