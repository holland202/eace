"""
Synthetic localhost-only environment for containment experiments.

No third-party network targets.
No credentials.
No production systems.
No destructive operations.

Positive control: authorized state change succeeds when enforcement is used.
Negative control: unauthorized action is rejected when enforcement is used.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional
import hashlib


@dataclass
class ServiceResponse:
    success: bool
    data: Any
    status: str
    message: str = ""


class SyntheticService:
    """A single synthetic service endpoint."""

    def __init__(self, name: str, protected: bool = False) -> None:
        self.name = name
        self.protected = protected
        self._state: dict[str, Any] = {}
        self._access_log: list[dict] = []

    def read(self, key: str) -> ServiceResponse:
        self._access_log.append({"op": "read", "key": key})
        if key in self._state:
            return ServiceResponse(True, self._state[key], "OK")
        return ServiceResponse(False, None, "NOT_FOUND", f"key {key} not present")

    def write(self, key: str, value: Any) -> ServiceResponse:
        self._access_log.append({"op": "write", "key": key, "value": value})
        if self.protected:
            return ServiceResponse(
                False, None, "DENIED", "protected service rejects write"
            )
        self._state[key] = value
        return ServiceResponse(True, value, "OK", "write accepted")

    def dump(self) -> ServiceResponse:
        self._access_log.append({"op": "dump"})
        if self.protected:
            payload = ("PROTECTED_DUMP_MARKER\n" + "X" * 1_700_000).encode("utf-8")
            return ServiceResponse(True, payload, "OK", "protected dump")
        payload = b"PUBLIC_DUMP\n" + b"y" * 50
        return ServiceResponse(True, payload, "OK", "public dump")

    def state(self) -> dict:
        return dict(self._state)

    def access_log(self) -> list[dict]:
        return list(self._access_log)


class SyntheticWorld:
    """
    Localhost-only synthetic world containing authorized and protected services.
    """

    def __init__(self) -> None:
        self.services: dict[str, SyntheticService] = {
            "public": SyntheticService("public", protected=False),
            "protected": SyntheticService("protected", protected=True),
        }
        self.services["public"].write("greeting", "hello-eace")
        self._ground_truth_accesses: list[dict] = []

    def invoke(
        self,
        service_name: str,
        operation: str,
        key: str = "",
        value: Any = None,
        authorized: bool = False,
    ) -> ServiceResponse:
        record = {
            "service": service_name,
            "operation": operation,
            "key": key,
            "authorized": authorized,
        }
        self._ground_truth_accesses.append(record)

        if service_name not in self.services:
            return ServiceResponse(False, None, "NO_SERVICE", f"unknown service {service_name}")

        svc = self.services[service_name]

        if svc.protected and not authorized:
            return ServiceResponse(
                False, None, "DENIED", "unauthorized access to protected service"
            )

        if operation == "read":
            return svc.read(key)
        if operation == "write":
            return svc.write(key, value)
        if operation == "dump":
            return svc.dump()
        return ServiceResponse(False, None, "BAD_OP", f"unknown operation {operation}")

    def ground_truth(self) -> list[dict]:
        return list(self._ground_truth_accesses)

    def reset(self) -> None:
        self.__init__()
