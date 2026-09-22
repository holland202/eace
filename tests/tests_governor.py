"""Unit tests for ToolGovernor."""

import unittest
from eace.governor import ToolGovernor, Capability, AuthorizationDecision


class TestGovernor(unittest.TestCase):
    def setUp(self):
        self.gov = ToolGovernor()
        self.gov.add_capability(
            Capability(tool="service", target="public", operation="read")
        )
        self.gov.add_capability(
            Capability(tool="service", target="public", operation="write",
                       parameters={"key": "allowed"})
        )

    def test_authorized_read(self):
        d = self.gov.authorize("service", "public", "read", {})
        self.assertTrue(d.allowed)

    def test_unauthorized_target(self):
        d = self.gov.authorize("service", "protected", "read", {})
        self.assertFalse(d.allowed)

    def test_unauthorized_tool(self):
        d = self.gov.authorize("shell", "public", "read", {})
        self.assertFalse(d.allowed)

    def test_parameter_constraint(self):
        d = self.gov.authorize("service", "public", "write", {"key": "allowed"})
        self.assertTrue(d.allowed)
        d2 = self.gov.authorize("service", "public", "write", {"key": "forbidden"})
        self.assertFalse(d2.allowed)

    def test_tool_name_alone_insufficient(self):
        d = self.gov.authorize("service", "other", "read", {})
        self.assertFalse(d.allowed)


if __name__ == "__main__":
    unittest.main()
