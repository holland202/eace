"""
EACE VERIFIER v0.2 ROBUSTNESS REGRESSION SUITE

Preserves all 19 v0.1 attacks verbatim in intent, adds 15 more, and adds an
anti-vacuity coverage check proving every verifier stage can actually halt.

Synthetic evidence only. No Android command is executed. No network. No writes
outside the working directory.

Working directory defaults to $HOME (device /tmp is not writable).
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from eace.verifier2 import verify  # noqa: E402

# ------------------------------------------------------------------ fixtures

DENIED_TEXT = (
    "Permission Denial: can't dump PackageManager from pid=9131, uid=10505\n"
    "missing android.permission.DUMP\n"
)
DENIED_TEXT_SHELL = DENIED_TEXT.replace("uid=10505", "uid=2000")

ALLOWED_TEXT = (
    "DUMP OF SERVICE package:\n"
    "Activity Resolver Table:\n"
    "  Full MIME Types:\n"
    "    com.termux/.app.api.file.FileShareReceiverActivity\n"
    "  Non-Data Actions:\n"
    "    android.intent.action.MAIN:\n"
    "      com.termux/.app.TermuxActivity\n"
)

IDENT_APP = "uid=10505\ncontext=u:r:untrusted_app_27:s0:c249,c257,c512,c768\n"
IDENT_SHELL = "uid=2000\ncontext=u:r:shell:s0\n"

COLLECTOR_APP = {"uid": "10505", "context": "u:r:untrusted_app_27:s0:c249,c257,c512,c768", "channel": "self"}
COLLECTOR_SHELL = {"uid": "2000", "context": "u:r:shell:s0", "channel": "self"}
COLLECTOR_RISH = {"uid": "2000", "context": "u:r:shell:s0", "channel": "rish"}

APP_TEST = "T-APP-DENIED"
SHELL_TEST = "T-SHELL-ALLOWED"
INDEP_TEST = "T-SHELL-NEEDS-INDEPENDENT"

DISC = {
    "denied": {
        "all_of": ["Permission Denial", "can't dump PackageManager",
                   "uid={expected_uid}", "android\\.permission\\.DUMP"],
        "none_of": ["^DUMP OF SERVICE package:"],
    },
    "allowed": {
        "all_of": ["^DUMP OF SERVICE package:", "Activity Resolver Table:", "com\\.termux"],
        "none_of": ["Permission Denial"],
    },
}
REQUIRED = ["stdout.txt", "identity.txt", "metadata.json", "manifest.json"]
RC_EXPECT = {"DENIED": [0, 1], "ALLOWED_PROTECTED": [0]}


def make_contracts(path: Path):
    base = {
        "required_artifacts": REQUIRED,
        "allowed_state": "ALLOWED_PROTECTED",
        "discriminants": DISC,
        "rc_expect": RC_EXPECT,
        "target": "com.termux",
    }
    doc = {
        "contract_version": "test-1.0.0",
        "tests": {
            APP_TEST: dict(base, expected_uid="10505",
                           expected_context_prefix="u:r:untrusted_app_27:s0",
                           expected_outcome="DENIED", required_provenance="SELF_REPORTED",
                           negative_reference_sha256=hashlib.sha256(
                               DENIED_TEXT.encode()).hexdigest()),
            SHELL_TEST: dict(base, expected_uid="2000",
                             expected_context_prefix="u:r:shell:s0",
                             expected_outcome="ALLOWED_PROTECTED",
                             required_provenance="SELF_REPORTED"),
            INDEP_TEST: dict(base, expected_uid="2000",
                             expected_context_prefix="u:r:shell:s0",
                             expected_outcome="ALLOWED_PROTECTED",
                             required_provenance="INDEPENDENT"),
        },
    }
    path.write_text(json.dumps(doc, indent=2), encoding="utf-8")


def build(root: Path, name, stdout=DENIED_TEXT, identity=IDENT_APP, *,
          test_id=APP_TEST, claim="DENIED", rc=1, collector=None,
          omit=(), manifest=None, extra_files=None, target="com.termux"):
    d = root / name
    if d.exists():
        shutil.rmtree(d)
    d.mkdir(parents=True)
    meta = {"test_id": test_id, "claim": claim, "rc": rc, "workload": "cmd package dump com.termux",
            "target": target, "collector": collector if collector is not None else COLLECTOR_APP}
    written = {}
    if "stdout.txt" not in omit:
        (d / "stdout.txt").write_bytes(stdout if isinstance(stdout, bytes) else stdout.encode())
        written["stdout.txt"] = (d / "stdout.txt")
    if "identity.txt" not in omit:
        (d / "identity.txt").write_text(identity, encoding="utf-8")
        written["identity.txt"] = (d / "identity.txt")
    if "metadata.json" not in omit:
        (d / "metadata.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
        written["metadata.json"] = (d / "metadata.json")
    for fn, content in (extra_files or {}).items():
        (d / fn).write_text(content, encoding="utf-8")
    if "manifest.json" not in omit:
        if manifest is None:
            manifest = {"algorithm": "sha256",
                        "files": {n: hashlib.sha256(p.read_bytes()).hexdigest()
                                  for n, p in written.items()}}
        if isinstance(manifest, str):
            (d / "manifest.json").write_text(manifest, encoding="utf-8")
        else:
            (d / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return d


# ------------------------------------------------------------------ cases
# expectation = set of acceptable v0.2 verdicts. A case PASSES only if the
# verdict is in the set AND is never a bare positive when it must not be.

FORBIDDEN_POSITIVE = {"CAPABILITY_OBSERVED"}


def cases(root: Path):
    C = []
    add = C.append

    # ---- the original 19 -------------------------------------------------
    add(("01_PRISTINE_DENIED", build(root, "c01"), {"COMPLIANT_DENIED"}, "COMPLIANT"))

    filler_1700575 = b"A" * 1700575
    add(("02_HISTORICAL_SIZE_FAKE",
         build(root, "c02", stdout=filler_1700575, claim="ALLOWED_PROTECTED", rc=0),
         {"UNCLASSIFIED_EVIDENCE"}, "ALLOWED_PROTECTED"))

    add(("03_ALTERED_PAYLOAD_SAME_SIZE",
         build(root, "c03", stdout=b"B" * 1700575, claim="ALLOWED_PROTECTED", rc=0),
         {"UNCLASSIFIED_EVIDENCE"}, "ALLOWED_PROTECTED"))

    add(("04_71_BYTE_OUTPUT",
         build(root, "c04", stdout=b"X" * 71, claim="ALLOWED_PROTECTED", rc=0),
         {"UNCLASSIFIED_EVIDENCE"}, "ALLOWED_PROTECTED"))

    add(("05_ARBITRARY_2MB",
         build(root, "c05", stdout=b"Z" * 2000000, claim="ALLOWED_PROTECTED", rc=0),
         {"UNCLASSIFIED_EVIDENCE"}, "ALLOWED_PROTECTED"))

    add(("06_EMPTY_STDOUT",
         build(root, "c06", stdout=b"", claim="NOT_TESTED", rc=0),
         {"NOT_TESTED"}, "ALLOWED_PROTECTED"))

    add(("07_MISSING_IDENTITY",
         build(root, "c07", omit=("identity.txt",)),
         {"INCOMPLETE_EVIDENCE"}, "INCOMPLETE_EVIDENCE"))

    add(("08_MALFORMED_IDENTITY",
         build(root, "c08", identity="uid=NOTANUMBER\ncontext=u:r:untrusted_app_27:s0\n"),
         {"IDENTITY_MALFORMED"}, "AMBIGUOUS"))

    d09 = build(root, "c09")
    (d09 / "stdout.txt").write_text("tampered after hashing\n", encoding="utf-8")
    add(("09_ALTERED_MANIFEST", d09, {"INTEGRITY_FAILURE"}, "INTEGRITY_FAILURE"))

    d10 = build(root, "c10", stdout=filler_1700575, claim="ALLOWED_PROTECTED", rc=0)
    m10 = json.loads((d10 / "manifest.json").read_text())
    m10["state_classification"] = "ALLOWED_PROTECTED"     # self-certification
    m10["verdict"] = "ALLOWED_PROTECTED"
    (d10 / "manifest.json").write_text(json.dumps(m10, indent=2), encoding="utf-8")
    add(("10_SELF_CERTIFIED_FAKE", d10, {"UNCLASSIFIED_EVIDENCE"}, "ALLOWED_PROTECTED"))

    add(("11_DENIED_CLAIM_LARGE_OUTPUT",
         build(root, "c11", stdout=ALLOWED_TEXT, identity=IDENT_SHELL, test_id=SHELL_TEST,
               claim="DENIED", rc=0, collector=COLLECTOR_SHELL),
         {"CLAIM_EVIDENCE_MISMATCH"}, "STATE_CHANGE"))

    add(("12_ALLOWED_CLAIM_DENIED_OUTPUT",
         build(root, "c12", claim="ALLOWED_PROTECTED"),
         {"CLAIM_EVIDENCE_MISMATCH"}, "AMBIGUOUS"))

    add(("13_NOT_ALLOWED_CLAIM",
         build(root, "c13", claim="NOT ALLOWED"),
         {"CLAIM_MALFORMED"}, "AMBIGUOUS"))

    add(("14_MISSING_STDOUT", build(root, "c14", omit=("stdout.txt",)),
         {"INCOMPLETE_EVIDENCE"}, "INCOMPLETE_EVIDENCE"))
    add(("15_MISSING_METADATA", build(root, "c15", omit=("metadata.json",)),
         {"INCOMPLETE_EVIDENCE"}, "INCOMPLETE_EVIDENCE"))
    add(("16_MISSING_MANIFEST", build(root, "c16", omit=("manifest.json",)),
         {"INCOMPLETE_EVIDENCE"}, "INCOMPLETE_EVIDENCE"))

    add(("17_WRONG_UID",
         build(root, "c17", identity=IDENT_SHELL, collector=COLLECTOR_SHELL),
         {"IDENTITY_MISMATCH"}, "COMPLIANT"))

    add(("18_BAD_CONTEXT",
         build(root, "c18", identity="uid=10505\ncontext=CORRUPTED\n"),
         {"IDENTITY_MALFORMED"}, "COMPLIANT"))

    add(("19_DUPLICATE_IDENTITY",
         build(root, "c19", identity=IDENT_APP + "uid=2000\n"),
         {"IDENTITY_MALFORMED"}, "COMPLIANT"))

    # ---- new in v0.2 -----------------------------------------------------
    d20 = build(root, "c20")
    m20 = json.loads((d20 / "manifest.json").read_text())
    m20["files"]["ghost.txt"] = hashlib.sha256(b"nothing").hexdigest()
    (d20 / "manifest.json").write_text(json.dumps(m20), encoding="utf-8")
    add(("20_MANIFEST_DANGLING_ENTRY", d20, {"MANIFEST_INVALID"}, "-"))

    add(("21_UNACCOUNTED_FILE",
         build(root, "c21", extra_files={"real_stdout.txt": ALLOWED_TEXT}),
         {"MANIFEST_INVALID"}, "-"))

    d22 = build(root, "c22")
    m22 = json.loads((d22 / "manifest.json").read_text())
    m22["files"]["../../escape.txt"] = hashlib.sha256(b"x").hexdigest()
    (d22 / "manifest.json").write_text(json.dumps(m22), encoding="utf-8")
    add(("22_MANIFEST_PATH_TRAVERSAL", d22, {"MANIFEST_INVALID"}, "-"))

    d23 = build(root, "c23")
    h = hashlib.sha256((d23 / "stdout.txt").read_bytes()).hexdigest()
    raw23 = ('{"algorithm":"sha256","files":{"stdout.txt":"%s",'
             '"stdout.txt":"%s"}}' % (h, "0" * 64))
    add(("23_DUPLICATE_MANIFEST_KEYS",
         build(root, "c23b", manifest=raw23), {"MANIFEST_INVALID"}, "-"))

    d24 = build(root, "c24")
    m24 = json.loads((d24 / "manifest.json").read_text())
    m24["files"]["stdout.txt"] = m24["files"]["stdout.txt"].upper()
    (d24 / "manifest.json").write_text(json.dumps(m24), encoding="utf-8")
    add(("24_BAD_HASH_FORMAT", d24, {"MANIFEST_INVALID"}, "-"))

    d25 = build(root, "c25")
    m25 = json.loads((d25 / "manifest.json").read_text())
    m25["algorithm"] = "md5"
    (d25 / "manifest.json").write_text(json.dumps(m25), encoding="utf-8")
    add(("25_ALGORITHM_SWAP", d25, {"MANIFEST_INVALID"}, "-"))

    add(("26_NO_TEST_ID", build(root, "c26", test_id=None),
         {"CONTRACT_UNRESOLVED"}, "-"))
    add(("27_UNKNOWN_TEST_ID", build(root, "c27", test_id="T-DOES-NOT-EXIST"),
         {"CONTRACT_UNRESOLVED"}, "-"))

    add(("28_WRONG_TARGET_PACKAGE",
         build(root, "c28", stdout=ALLOWED_TEXT.replace("com.termux", "com.example.other"),
               identity=IDENT_SHELL, test_id=SHELL_TEST, claim="ALLOWED_PROTECTED",
               rc=0, collector=COLLECTOR_SHELL),
         {"UNCLASSIFIED_EVIDENCE"}, "-"))

    add(("29_AMBIGUITY_INJECTION",
         build(root, "c29", stdout=ALLOWED_TEXT + DENIED_TEXT_SHELL, identity=IDENT_SHELL,
               test_id=SHELL_TEST, claim="ALLOWED_PROTECTED", rc=0, collector=COLLECTOR_SHELL),
         {"AMBIGUOUS"}, "-"))

    add(("30_CLAIM_ZEROWIDTH_SPOOF",
         build(root, "c30", claim="ALLOWED\u200b_PROTECTED"), {"CLAIM_MALFORMED"}, "-"))
    add(("31_CLAIM_WHITESPACE_SPOOF",
         build(root, "c31", claim=" allowed_protected "), {"CLAIM_MALFORMED"}, "-"))

    add(("32_RC0_WITH_ALLOWED_TEXT_BUT_RC_CONFLICT",
         build(root, "c32", stdout=ALLOWED_TEXT, identity=IDENT_SHELL, test_id=SHELL_TEST,
               claim="ALLOWED_PROTECTED", rc=137, collector=COLLECTOR_SHELL),
         {"AMBIGUOUS"}, "-"))

    add(("33_INSUFFICIENT_PROVENANCE",
         build(root, "c33", stdout=ALLOWED_TEXT, identity=IDENT_SHELL, test_id=INDEP_TEST,
               claim="ALLOWED_PROTECTED", rc=0, collector=COLLECTOR_SHELL),
         {"CAPABILITY_CLAIMED_INSUFFICIENT_PROVENANCE"}, "-"))

    add(("34_NO_COLLECTOR_DECLARED",
         build(root, "c34", stdout=ALLOWED_TEXT, identity=IDENT_SHELL, test_id=SHELL_TEST,
               claim="ALLOWED_PROTECTED", rc=0, collector={}),
         {"CAPABILITY_CLAIMED_INSUFFICIENT_PROVENANCE"}, "-"))

    # 36/37 exist because mutation_check.py showed case 17 does NOT isolate
    # the uid guard: it swaps uid AND context together, so the context check
    # catches it either way and the uid check is inert. Each of these moves
    # exactly one identity field.
    add(("36_UID_ONLY_MISMATCH",
         build(root, "c36",
               identity="uid=99999\ncontext=u:r:untrusted_app_27:s0:c249,c257,c512,c768\n"),
         {"IDENTITY_MISMATCH"}, "-"))

    add(("37_CONTEXT_ONLY_MISMATCH",
         build(root, "c37", identity="uid=10505\ncontext=u:r:shell:s0\n"),
         {"IDENTITY_MISMATCH"}, "-"))

    # anti-vacuity: the ONLY case that may legitimately reach a positive.
    add(("35_GENUINE_SHELL_POSITIVE",
         build(root, "c35", stdout=ALLOWED_TEXT, identity=IDENT_SHELL, test_id=SHELL_TEST,
               claim="ALLOWED_PROTECTED", rc=0, collector=COLLECTOR_SHELL),
         {"CAPABILITY_OBSERVED"}, "-"))

    return C


def main():
    work = Path(tempfile.mkdtemp(prefix="eace_v2_attack_", dir=str(Path.home())))
    contracts = work / "contracts_test.json"
    make_contracts(contracts)
    root = work / "evidence"
    root.mkdir()

    print("=" * 78)
    print("EACE VERIFIER v0.2 ROBUSTNESS REGRESSION")
    print("Target : eace/verifier2.py")
    print("Mode   : synthetic evidence only, no Android command executed")
    print("Workdir: %s" % work)
    print("=" * 78)
    print()
    print("%-38s %-24s %-22s %s" % ("CASE", "v0.1 VERDICT", "v0.2 VERDICT", "RESULT"))
    print("-" * 100)

    results, stages_hit, failures = [], set(), []
    for name, path, expected, v01 in cases(root):
        v = verify(path, contracts, test_id=None)
        verdict = v["verdict"]
        ok = verdict in expected
        if not ok:
            failures.append((name, expected, verdict, v["reasons"]))
        # record which stage was the last to succeed (coverage)
        stages_hit.add(verdict)
        results.append((name, v01, verdict, ok, v))
        print("%-38s %-24s %-22s %s" % (name, v01, verdict, "PASS" if ok else "FAIL"))

    print()
    print("=" * 78)
    print("ANTI-VACUITY COVERAGE")
    print("=" * 78)
    positives = [r for r in results if r[2] in FORBIDDEN_POSITIVE]
    print("cases reaching CAPABILITY_OBSERVED : %d" % len(positives))
    for p in positives:
        print("  %s" % p[0])
    print()
    must_be_reachable = {
        "COMPLIANT_DENIED", "CAPABILITY_OBSERVED", "CAPABILITY_CLAIMED_INSUFFICIENT_PROVENANCE",
        "INCOMPLETE_EVIDENCE", "MANIFEST_INVALID", "INTEGRITY_FAILURE",
        "IDENTITY_MALFORMED", "IDENTITY_MISMATCH", "CLAIM_MALFORMED",
        "CLAIM_EVIDENCE_MISMATCH", "AMBIGUOUS", "UNCLASSIFIED_EVIDENCE",
        "NOT_TESTED", "CONTRACT_UNRESOLVED",
    }
    unreached = sorted(must_be_reachable - stages_hit)
    print("verdict states exercised : %d / %d" % (
        len(must_be_reachable & stages_hit), len(must_be_reachable)))
    if unreached:
        print("NOT EXERCISED (vacuous branches): %s" % ", ".join(unreached))
    else:
        print("every declared verdict state was reached by at least one case")

    print()
    print("=" * 78)
    print("SUMMARY")
    print("=" * 78)
    npass = sum(1 for r in results if r[3])
    print("cases        : %d" % len(results))
    print("passed       : %d" % npass)
    print("failed       : %d" % (len(results) - npass))
    print("false positives (illegitimate CAPABILITY_OBSERVED) : %d"
          % len([p for p in positives if p[0] != "35_GENUINE_SHELL_POSITIVE"]))
    for name, exp, got, reasons in failures:
        print()
        print("FAIL %s" % name)
        print("  expected one of : %s" % sorted(exp))
        print("  got             : %s" % got)
        for r in reasons:
            print("  reason          : %s" % r)

    print()
    print("v0.1 comparison: 6 of 19 original attacks obtained ALLOWED_PROTECTED "
          "and 3 obtained COMPLIANT on bad identity.")
    ok_all = not failures and len(positives) == 1 and unreached == []
    print()
    print("REGRESSION SUITE: %s" % ("PASS" if ok_all else "FAIL"))
    shutil.rmtree(work, ignore_errors=True)
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
