"""
O3 — symmetric guard probe against eace/verifier2.py.

EACE-REC-001 documented five self-skipping guards in VerifierV02. That
record was written by the author of the competing implementation. O3 is the
symmetric test: does eace/verifier2.py contain the same defect class?

Same discipline as probe_v02_guards.py:
  - probe one property per case
  - carry controls, so a wrong model of the verifier is visible in the
    output rather than silent
  - report NOT TESTED rather than "holds" where a case cannot be isolated

The defect class under test is NOT "a missing check". It is:

    a check that is PRESENT and SKIPS ITSELF when its input is absent,
    empty, or falsy

In VerifierV02 that appeared as `if algo and algo not in (...)`, where an
absent algorithm made the guard falsy and the comparison never ran.

Read-only apart from a temp evidence tree under $HOME. Run from repo root:
    python3 probe_verifier2_guards.py
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    from eace.verifier2 import verify
except Exception as exc:
    print("cannot import eace.verifier2: %s" % exc)
    sys.exit(2)

DENIED = ("Permission Denial: can't dump PackageManager from pid=9131, "
          "uid=10505\nmissing android.permission.DUMP\n")
IDENT = "uid=10505\ncontext=u:r:untrusted_app_27:s0:c249,c257,c512,c768\n"
COLL = {"uid": "10505", "context": "u:r:untrusted_app_27:s0:c249,c257,c512,c768"}

FULL_CONTRACT = {
    "expected_uid": "10505",
    "expected_context_prefix": "u:r:untrusted_app_27:s0",
    "expected_outcome": "DENIED",
    "required_artifacts": ["stdout.txt", "identity.txt", "metadata.json",
                           "manifest.json"],
    "required_provenance": "SELF_REPORTED",
    "allowed_state": "ALLOWED_PROTECTED",
    "discriminants": {
        "denied": {"all_of": ["Permission Denial", "uid={expected_uid}"],
                   "none_of": ["^DUMP OF SERVICE package:"]},
        "allowed": {"all_of": ["^DUMP OF SERVICE package:"],
                    "none_of": ["Permission Denial"]},
    },
    "rc_expect": {"DENIED": [1], "ALLOWED_PROTECTED": [0]},
}

POSITIVE = {"COMPLIANT_DENIED", "CAPABILITY_OBSERVED"}


def sha(b):
    return hashlib.sha256(b if isinstance(b, bytes) else b.encode()).hexdigest()


def build(root, name, stdout=DENIED, identity=IDENT, rc=1, claim="DENIED",
          collector=COLL, algorithm="sha256", omit_stdout_entry=False,
          extra_entry=None, break_hash=False):
    d = root / name
    d.mkdir(parents=True)
    b = stdout.encode() if isinstance(stdout, str) else stdout
    (d / "stdout.txt").write_bytes(b)
    (d / "identity.txt").write_text(identity, encoding="utf-8")
    meta = {"test_id": "T", "claim": claim, "rc": rc,
            "workload": "w", "target": "t", "collector": collector}
    (d / "metadata.json").write_text(json.dumps(meta), encoding="utf-8")
    files = {}
    if not omit_stdout_entry:
        files["stdout.txt"] = "0" * 64 if break_hash else sha(b)
    files["identity.txt"] = sha((d / "identity.txt").read_bytes())
    files["metadata.json"] = sha((d / "metadata.json").read_bytes())
    if extra_entry:
        files.update(extra_entry)
    man = {"files": files}
    if algorithm is not None:
        man["algorithm"] = algorithm
    (d / "manifest.json").write_text(json.dumps(man), encoding="utf-8")
    return d


def contracts_file(root, name, **drop_or_set):
    c = dict(FULL_CONTRACT)
    for k, v in drop_or_set.items():
        if v is None:
            c.pop(k, None)
        else:
            c[k] = v
    p = root / ("contract_%s.json" % name)
    p.write_text(json.dumps({"contract_version": "probe", "tests": {"T": c}}),
                 encoding="utf-8")
    return p


def run(evd, cpath):
    try:
        return verify(evd, cpath, test_id="T")["verdict"]
    except Exception as exc:
        return "PROBE_ERROR:%s" % type(exc).__name__


def main():
    work = Path(tempfile.mkdtemp(prefix="o3_probe_", dir=str(Path.home())))
    ev, results = work / "ev", []
    ev.mkdir()

    def case(tag, desc, evd, cpath, want_positive):
        v = run(evd, cpath)
        is_pos = v in POSITIVE
        ok = (is_pos == want_positive)
        results.append((tag, ok, v, want_positive))
        print("%-7s %-48s %-28s %s" % (
            tag, desc, v,
            "as expected" if ok else
            ("DEFECT: reached positive" if is_pos else "unexpected refusal")))

    print("=" * 92)
    print("O3 SYMMETRIC GUARD PROBE -- eace/verifier2.py")
    print("=" * 92)
    print("%-7s %-48s %-28s %s" % ("ITEM", "INPUT", "VERDICT", "ASSESSMENT"))
    print("-" * 92)

    full = contracts_file(work, "full")

    # controls first
    case("CTRL-P", "CONTROL well-formed evidence, full contract",
         build(ev, "ctrlp"), full, True)
    case("CTRL-R", "CONTROL stdout hash wrong",
         build(ev, "ctrlr", break_hash=True), full, False)
    print()

    # --- manifest class, symmetric to M1-M7 -----------------------------
    case("M1", "algorithm key absent entirely",
         build(ev, "m1", algorithm=None), full, False)
    case("M2", "algorithm is empty string",
         build(ev, "m2", algorithm=""), full, False)
    case("M3", "algorithm is md5",
         build(ev, "m3", algorithm="md5"), full, False)
    case("M4", "manifest omits stdout.txt entry",
         build(ev, "m4", omit_stdout_entry=True), full, False)
    case("M7", "path traversal in manifest entries",
         build(ev, "m7", extra_entry={"../../etc/passwd": "a" * 64}), full, False)
    print()

    # --- identity class, symmetric to I1-I4 -----------------------------
    case("I1", "uid='synthetic-attacker'",
         build(ev, "i1", identity="uid=synthetic-attacker\ncontext=u:r:untrusted_app_27:s0\n"),
         full, False)
    case("I2", "uid='not-a-number'",
         build(ev, "i2", identity="uid=not-a-number\ncontext=u:r:untrusted_app_27:s0\n"),
         full, False)
    case("I3", "malformed selinux context",
         build(ev, "i3", identity="uid=10505\ncontext=CORRUPTED\n"), full, False)
    case("I4", "duplicate uid declarations",
         build(ev, "i4", identity=IDENT + "uid=2000\n"), full, False)
    print()

    # --- THE DEFECT CLASS: contract fields absent -----------------------
    # Each of these omits ONE contract field and supplies evidence that
    # only the omitted field's check could reject.
    print("CONTRACT-OMISSION CLASS  (the defect class EACE-REC-001 found in")
    print("VerifierV02: a check present in code that skips when input is absent)")
    print("-" * 92)

    c_no_uid = contracts_file(work, "no_uid", expected_uid=None)
    case("C1", "contract omits expected_uid, evidence uid=2000",
         build(ev, "c1", identity="uid=2000\ncontext=u:r:untrusted_app_27:s0\n"),
         c_no_uid, False)

    c_no_ctx = contracts_file(work, "no_ctx", expected_context_prefix=None)
    case("C2", "contract omits expected_context_prefix, ctx=shell",
         build(ev, "c2", identity="uid=10505\ncontext=u:r:shell:s0\n"),
         c_no_ctx, False)

    c_no_rc = contracts_file(work, "no_rc", rc_expect=None)
    case("C3", "contract omits rc_expect, rc=137 contradicts DENIED",
         build(ev, "c3", rc=137), c_no_rc, False)

    c_no_prov = contracts_file(work, "no_prov", required_provenance=None)
    case("C4", "contract omits required_provenance, self-collected",
         build(ev, "c4"), c_no_prov, False)

    c_no_disc = contracts_file(work, "no_disc", discriminants=None)
    case("C5", "contract omits discriminants entirely",
         build(ev, "c5"), c_no_disc, False)

    print()
    print("=" * 92)
    ctrl_bad = [t for t, ok, _, _ in results if t.startswith("CTRL") and not ok]
    defects = [t for t, ok, _, _ in results if not ok and not t.startswith("CTRL")]
    if ctrl_bad:
        print("CONTROLS FAILED (%s). The probe's model of verifier2 is wrong;"
              % ", ".join(ctrl_bad))
        print("treat every other row as NOT TESTED rather than as a finding.")
    else:
        print("controls passed; rows below are findings")
    print()
    print("unexpected results : %s" % (", ".join(defects) or "none"))
    print()
    print("A row marked 'DEFECT: reached positive' means verifier2.py emitted a")
    print("positive verdict for evidence that should have been refused. A row")
    print("marked 'unexpected refusal' means the probe's expectation was wrong,")
    print("not that the verifier is.")
    shutil.rmtree(work, ignore_errors=True)
    return 1 if (ctrl_bad or defects) else 0


if __name__ == "__main__":
    sys.exit(main())
