"""
VerifierV02 guard probe, v2.

WHY v1 WAS WRONG
----------------
v1 ran full verify() and read the terminal verdict. Every case came back
AMBIGUOUS and v1 reported "holds". That was wrong.

VerifierV02.verify() runs _check_identity (step 3) and _check_manifest
(step 4) BEFORE the semantic stage (step 7). With stdout matching neither
POSITIVE_CONTROL_HASH nor DENIED_BASELINE_HASH, _infer_observed_outcome
returns "AMBIGUOUS" and verify() returns AMBIGUOUS regardless of what the
earlier guards did. So the terminal verdict cannot distinguish

    guard fired and rejected
    guard passed the artifact
    guard skipped itself

v1 could not tell those apart and called all three "holds". Same shadowing
defect this session has now found six times, this instance in the probe
rather than in the subject.

WHAT v2 DOES
------------
Calls the guards DIRECTLY. _check_manifest and _check_identity each return
None (nothing objected) or a result dict (rejected). That is an unambiguous
signal and needs no control artifact.

This couples to private method names. Acceptable for a diagnostic; it is
not a regression guard and should not become one.

Read-only, synthetic artifacts, writes nothing. Run from repo root:
    python3 probe_v02_guards.py
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    from eace import verifier as V
except Exception as exc:
    print("cannot import eace.verifier: %s" % exc)
    sys.exit(2)


def sha(b):
    return hashlib.sha256(b if isinstance(b, bytes) else b.encode()).hexdigest()


def man(algorithm="sha256", stdout=b"x", stdout_entry=True, extra=None):
    entries = {"stdout": sha(stdout)} if stdout_entry else {}
    if extra:
        entries.update(extra)
    m = {"entries": entries}
    if algorithm is not None:
        m["algorithm"] = algorithm
    return {"stdout": stdout, "manifest": m}


def probe_manifest(label, artifact):
    try:
        r = V.VerifierV02(None)._check_manifest(artifact)
    except Exception as exc:
        return "PROBE_ERROR", "%s: %s" % (type(exc).__name__, exc)
    return ("PASSED" if r is None else "REJECTED",
            "" if r is None else r.get("reason", ""))


def probe_identity(label, identity):
    try:
        r = V.VerifierV02(None)._check_identity(identity)
    except Exception as exc:
        return "PROBE_ERROR", "%s: %s" % (type(exc).__name__, exc)
    return ("PASSED" if r is None else "REJECTED",
            "" if r is None else r.get("reason", ""))


print("=" * 84)
print("VerifierV02 GUARD PROBE v2 -- guards called directly")
print("=" * 84)
print("POSITIVE_CONTROL_HASH : %s" % getattr(V, "POSITIVE_CONTROL_HASH", "ABSENT"))
print("DENIED_BASELINE_HASH  : %s" % getattr(V, "DENIED_BASELINE_HASH", "ABSENT"))
print()
print("%-6s %-48s %-10s %s" % ("ITEM", "INPUT", "GUARD", "ASSESSMENT"))
print("-" * 84)

rows = []

# --- _check_manifest -------------------------------------------------------
cases_m = [
    ("M1", "algorithm key absent entirely", man(algorithm=None), "REJECTED"),
    ("M2", "algorithm is empty string", man(algorithm=""), "REJECTED"),
    ("M3", "algorithm is md5", man(algorithm="md5"), "REJECTED"),
    ("M4", "entries omit stdout (nothing to compare)",
     man(stdout=b"FORGED", stdout_entry=False), "REJECTED"),
    ("M5", "CONTROL declared hash wrong",
     {"stdout": b"FORGED", "manifest": {"algorithm": "sha256",
                                        "entries": {"stdout": "0" * 64}}},
     "REJECTED"),
    ("M6", "CONTROL well-formed manifest", man(), "PASSED"),
    ("M7", "path traversal in entries",
     man(extra={"../../etc/passwd": "a" * 64}), "REJECTED"),
]
for tag, desc, art, want in cases_m:
    got, why = probe_manifest(tag, art)
    ok = got == want
    rows.append((tag, ok, got, want))
    print("%-6s %-48s %-10s %s" % (
        tag, desc, got,
        "as expected" if ok else "DEFECT: expected %s" % want))
    if why:
        print("       %s" % why[:90])

print()

# --- _check_identity -------------------------------------------------------
cases_i = [
    ("I1", "uid='synthetic-attacker'", {"uid": "synthetic-attacker"}, "REJECTED"),
    ("I2", "uid='not-a-number'", {"uid": "not-a-number"}, "REJECTED"),
    ("I3", "malformed selinux_context",
     {"uid": "10505", "selinux_context": "CORRUPTED"}, "REJECTED"),
    ("I4", "duplicate identity declarations",
     [{"uid": "10505"}, {"uid": "2000"}], "REJECTED"),
    ("I5", "CONTROL well-formed identity",
     {"uid": "10505", "selinux_context": "u:r:untrusted_app_27:s0"}, "PASSED"),
]
for tag, desc, ident, want in cases_i:
    got, why = probe_identity(tag, ident)
    ok = got == want
    rows.append((tag, ok, got, want))
    print("%-6s %-48s %-10s %s" % (
        tag, desc, got,
        "as expected" if ok else "DEFECT: expected %s" % want))
    if why:
        print("       %s" % why[:90])

print()
print("=" * 84)
defects = [t for t, ok, _, _ in rows if not ok]
controls = [t for t, ok, _, _ in rows if t in ("M5", "M6", "I5") and not ok]
print("guards behaving unexpectedly : %s" % (", ".join(defects) or "none"))
if controls:
    print()
    print("CONTROLS FAILED (%s). The probe's model of the guard is wrong;" % ", ".join(controls))
    print("treat every other row above as NOT TESTED rather than as a finding.")
print()
print("Terminal-verdict note: with no control artifact in the tree, verify()")
print("returns AMBIGUOUS for all of these regardless of guard behaviour.")
print("That is why the guards are probed directly here.")
