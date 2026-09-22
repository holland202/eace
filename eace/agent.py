"""Synthetic agent that interacts with the world under governor control."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from eace.governor import ToolGovernor, AuthorizationDecision
from eace.ledger import EvidenceEvent, EvidenceLedger
from eace.clock import DeterministicClock
from eace.synthetic_services import SyntheticWorld, ServiceResponse
from eace.ledger import sha256_hex


@dataclass
class AgentAction:
    tool: str
    target: str
    operation: str
    parameters: dict
    claim: str = "NOT_TESTED"


class SyntheticAgent:
    """
    An agent whose tool invocations are mediated by a ToolGovernor
    and recorded in an EvidenceLedger.
    """

    def __init__(
        self,
        world: SyntheticWorld,
        governor: ToolGovernor,
        ledger: EvidenceLedger,
        clock: DeterministicClock,
        agent_id: str = "synthetic-agent-0",
    ) -> None:
        self.world = world
        self.governor = governor
        self.ledger = ledger
        self.clock = clock
        self.agent_id = agent_id
        self._history: list[dict] = []

    def act(self, action: AgentAction) -> dict:
        t = self.clock.tick()
        decision: AuthorizationDecision = self.governor.authorize(
            tool=action.tool,
            target=action.target,
            operation=action.operation,
            parameters=action.parameters,
        )

        response: ServiceResponse
        if decision.allowed:
            response = self.world.invoke(
                service_name=action.target,
                operation=action.operation,
                key=action.parameters.get("key", ""),
                value=action.parameters.get("value"),
                authorized=True,
            )
        else:
            response = self.world.invoke(
                service_name=action.target,
                operation=action.operation,
                key=action.parameters.get("key", ""),
                value=action.parameters.get("value"),
                authorized=False,
            )

        stdout_bytes = b""
        if isinstance(response.data, (bytes, bytearray)):
            stdout_bytes = bytes(response.data)
        elif response.data is not None:
            stdout_bytes = str(response.data).encode("utf-8")

        stdout_hash = sha256_hex(stdout_bytes) if stdout_bytes else None

        outcome = response.status
        event = EvidenceEvent(
            t=t,
            action=f"{action.tool}:{action.operation}",
            tool=action.tool,
            target=action.target,
            operation=action.operation,
            parameters=action.parameters,
            authorized=decision.allowed,
            outcome=outcome,
            stdout_hash=stdout_hash,
            identity={"agent_id": self.agent_id, "uid": "synthetic"},
            metadata={
                "claim": action.claim,
                "reason": decision.reason,
                "message": response.message,
                "stdout_len": len(stdout_bytes),
            },
        )
        head = self.ledger.append(event)

        record = {
            "t": t,
            "decision": decision,
            "response": response,
            "event": event,
            "ledger_head": head,
        }
        self._history.append(record)
        return record

    def history(self) -> list[dict]:
        return list(self._history)
