"""
Tool governor for capability boundary enforcement.

Authorization is performed at the level of:
  (tool, target, operation, parameters)

Limitations of the current (v0.1-style) model are documented
explicitly: simple allow-lists can be insufficient against
parameter-level or target-level attacks. The governor is itself
an experimental object.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass(frozen=True)
class Capability:
    """An authorized capability tuple."""

    tool: str
    target: str
    operation: str
    # Optional parameter constraints (exact match or None = any)
    parameters: Optional[dict] = None


@dataclass
class AuthorizationDecision:
    allowed: bool
    reason: str
    capability: Optional[Capability] = None


class ToolGovernor:
    """
    Enforces an authorized capability envelope K_A.

    Authorization checks (tool, target, operation, parameters).
    Tool-name alone is intentionally insufficient.
    """

    def __init__(self, authorized: list[Capability] | None = None) -> None:
        self._authorized: list[Capability] = list(authorized or [])

    def add_capability(self, capability: Capability) -> None:
        self._authorized.append(capability)

    def clear(self) -> None:
        self._authorized.clear()

    def authorize(
        self,
        tool: str,
        target: str,
        operation: str,
        parameters: dict | None = None,
    ) -> AuthorizationDecision:
        parameters = parameters or {}
        for cap in self._authorized:
            if cap.tool != tool:
                continue
            if cap.target != target and cap.target != "*":
                continue
            if cap.operation != operation and cap.operation != "*":
                continue
            if cap.parameters is not None:
                # Exact subset match on declared keys
                if not all(parameters.get(k) == v for k, v in cap.parameters.items()):
                    continue
            return AuthorizationDecision(
                allowed=True,
                reason="matched authorized capability",
                capability=cap,
            )
        return AuthorizationDecision(
            allowed=False,
            reason="no matching authorized capability",
            capability=None,
        )

    def authorized_set(self) -> list[Capability]:
        return list(self._authorized)

    def __repr__(self) -> str:
        return f"ToolGovernor(n_capabilities={len(self._authorized)})"
