"""
Evidence ledger with hash chaining.

HASH INTEGRITY != TRUTH

A valid hash chain proves artifact integrity under the recorded
serialization. It does NOT prove:
  - that the artifact was honestly produced;
  - that the correct process generated it;
  - that the command was what the operator intended;
  - that the artifact represents the claimed external state;
  - that the interpretation is causally correct.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from typing import Any, Optional


GENESIS = "0" * 64


def canonical_json(obj: Any) -> str:
    """Deterministic JSON serialization for hashing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


@dataclass
class EvidenceEvent:
    """Single evidence event recorded in the ledger."""

    t: int
    action: str
    tool: str
    target: str
    operation: str
    parameters: dict
    authorized: bool
    outcome: str
    stdout_hash: Optional[str] = None
    stderr_hash: Optional[str] = None
    identity: Optional[dict] = None
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    def digest(self) -> str:
        """d_t = SHA256(Canonical(E_t))"""
        return sha256_hex(canonical_json(self.to_dict()))


class EvidenceLedger:
    """
    Append-only evidence ledger with hash chaining.

    H_t = SHA256(H_{t-1} || d_t)
    GENESIS = "0" * 64
    """

    def __init__(self, genesis: str = GENESIS) -> None:
        self._events: list[EvidenceEvent] = []
        self._hashes: list[str] = [genesis]
        self._genesis = genesis

    @property
    def head(self) -> str:
        return self._hashes[-1]

    @property
    def length(self) -> int:
        return len(self._events)

    def append(self, event: EvidenceEvent) -> str:
        """Append event and return new head hash."""
        d_t = event.digest()
        h_prev = self._hashes[-1]
        h_t = sha256_hex(h_prev + d_t)
        self._events.append(event)
        self._hashes.append(h_t)
        return h_t

    def events(self) -> list[EvidenceEvent]:
        return list(self._events)

    def hashes(self) -> list[str]:
        return list(self._hashes)

    def verify_chain(self) -> bool:
        """Recompute the entire chain and check integrity."""
        if not self._hashes or self._hashes[0] != self._genesis:
            return False
        prev = self._genesis
        for i, event in enumerate(self._events):
            d_t = event.digest()
            expected = sha256_hex(prev + d_t)
            if expected != self._hashes[i + 1]:
                return False
            prev = expected
        return True

    def final_hash(self) -> str:
        return self.head

    def to_dict(self) -> dict:
        return {
            "genesis": self._genesis,
            "events": [e.to_dict() for e in self._events],
            "hashes": self._hashes,
            "final_hash": self.final_hash(),
            "chain_valid": self.verify_chain(),
        }

    def export_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_events(cls, events: list[EvidenceEvent], genesis: str = GENESIS) -> "EvidenceLedger":
        ledger = cls(genesis=genesis)
        for e in events:
            ledger.append(e)
        return ledger
