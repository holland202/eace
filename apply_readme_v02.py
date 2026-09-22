"""
apply_readme_v02.py — bring README.md into line with the tree.

FAIL-CLOSED BY DESIGN
---------------------
Every anchor is located BEFORE anything is written. If any anchor is
missing or ambiguous, the script writes nothing and reports which. A
partially applied patch to a claims document is worse than none.

Run from repo root:
    python3 apply_readme_v02.py            # dry run, reports only
    python3 apply_readme_v02.py --write    # apply

WHAT IT CHANGES AND WHY
-----------------------
The README was written before v0.2 existed and still says v0.2 is the next
development target. That staleness caused commit 1991750: an agent built
against the summary instead of the files and produced a second component
claiming the same version number. The fix is not only to tick boxes but to
say plainly that two implementations exist.

Eight of the ten v0.2 roadmap items are device-verified (37/37 regression,
9/9 mutation, aarch64/py3.14). Two are NOT: the ground-truth corpus and
TP/FP/TN/FN evaluation exist only as container runs of P6 and have never
been executed on device. Those two stay unticked.

Four NEW unticked items are added, opened by EACE-REC-001 and -002. A
roadmap that only grows shorter is not tracking the work.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

README = Path("README.md")

# --- exact-string replacements -------------------------------------------

TICK = [
    "External test contracts",
    "Strict identity validation",
    "Semantic evidence predicates",
    "Provenance binding",
    "Exact claim parsing",
    "Fail-closed verdict model",
    "v0.1 regression suite",
    "Novel adversarial attack suite",
]

# left unticked on purpose; P6 is container-only
LEAVE = ["Ground-truth corpus", "TP/FP/TN/FN evaluation"]

NEW_ITEMS = """- [ ] Ground-truth corpus (exists; container-only, not run on device)
- [ ] TP/FP/TN/FN evaluation (exists; container-only, not run on device)
- [ ] Contract completeness validation (EACE-REC-002: four gates skip
      silently when the contract omits a field)
- [ ] Reachable, tested positive verdict for VerifierV02 (EACE-REC-001
      Finding 2: neither control artifact is committed and the suite
      asserts COMPLIANT zero times)
- [ ] Resolve the two components claiming version 0.2
- [ ] Symmetric adversarial probe written by someone other than the
      implementation author (EACE-REC-002 O5)
"""

STATUS_OLD = "The next development target is a fail-closed verifier"
STATUS_NEW = """Two fail-closed verifier implementations now exist, and they are not
reconciled:

- `VerifierV02` in `eace/verifier.py` — dict interface, covered by the
  existing test suite.
- `eace/verifier2.py` — on-disk evidence-bundle interface, 37-case
  regression suite, mutation-checked.

The second was added by commit `1991750`, built against an earlier version
of this README that listed v0.2 as an unstarted development target. It was
not. That is itself a recorded finding: a stale summary produced a
duplicate component. See commit `8f6b0e3`.

Both have been probed and both carry defects. Neither is designated
canonical. See `records/EACE-REC-001.md` and `records/EACE-REC-002.md`.

The original next development target was a fail-closed verifier"""

# NOTE: README.md uses CRLF and a three-space indent under the box-drawing
# pipe. The first version of this script built these anchors from GitHub's
# RENDERING, which collapses both, so the anchor matched 0 times and the
# script correctly refused to write. Same defect class as commit 1991750:
# built against the summary instead of the file. Anchors below are taken
# from `cat -A` output and the line ending is applied at match time.
STRUCT_OLD_LINES = ["\u2502   \u251c\u2500\u2500 synthetic_services.py",
                    "\u2502   \u2514\u2500\u2500 verifier.py"]
STRUCT_NEW_LINES = ["\u2502   \u251c\u2500\u2500 synthetic_services.py",
                    "\u2502   \u251c\u2500\u2500 verifier.py          # VerifierV01 + VerifierV02",
                    "\u2502   \u2514\u2500\u2500 verifier2.py         # second v0.2, unreconciled (REC-002)"]

TESTSDIR_OLD_LINES = ["\u251c\u2500\u2500 tests/"]
TESTSDIR_NEW_LINES = ["\u251c\u2500\u2500 tests/",
                      "\u2502",
                      "\u251c\u2500\u2500 probe_v02_guards.py            # REC-001 reproduction",
                      "\u251c\u2500\u2500 probe_verifier2_guards.py      # REC-002 reproduction",
                      "\u251c\u2500\u2500 test_verifier_robustness_v2.py # 37-case regression",
                      "\u251c\u2500\u2500 mutation_check.py              # guard mutation check"]

TESTS_OLD = "The exact test inventory will expand as the verifier qualification work progresses."
TESTS_NEW = """Additional suites, runnable from a clean clone with no configuration:

    python3 test_verifier_robustness_v2.py   # 37 cases, 0 false positives
    python3 mutation_check.py                # 9/9 guards load-bearing
    python3 probe_v02_guards.py              # EACE-REC-001 reproduction
    python3 probe_verifier2_guards.py        # EACE-REC-002 reproduction

The two probes carry controls. If a control row does not read "as
expected", the probe's model of the verifier is wrong and every other row
in that run is NOT TESTED rather than a finding.

The exact test inventory will expand as the verifier qualification work
progresses."""


def locate(text):
    """Find every anchor. Returns (plan, problems)."""
    plan, problems = [], []

    for item in TICK:
        old = "- [ ] %s" % item
        if text.count(old) != 1:
            problems.append("roadmap item %r found %d times (want 1)"
                            % (item, text.count(old)))
        else:
            plan.append((old, "- [x] %s" % item))

    for item in LEAVE:
        if text.count("- [ ] %s" % item) != 1:
            problems.append("unticked item %r found %d times (want 1)"
                            % (item, text.count("- [ ] %s" % item)))

    if text.count(STATUS_OLD) != 1:
        problems.append("status sentence found %d times (want 1)" % text.count(STATUS_OLD))
    else:
        plan.append((STATUS_OLD, STATUS_NEW))

    eol = "\r\n" if "\r\n" in text else "\n"
    for label, oldl, newl in (("repository-structure eace/ subtree",
                               STRUCT_OLD_LINES, STRUCT_NEW_LINES),
                              ("repository-structure tests/ line",
                               TESTSDIR_OLD_LINES, TESTSDIR_NEW_LINES)):
        old = eol.join(oldl)
        if text.count(old) != 1:
            problems.append("%s found %d times (want 1)" % (label, text.count(old)))
        else:
            plan.append((old, eol.join(newl)))

    if text.count(TESTS_OLD) != 1:
        problems.append("test-inventory sentence found %d times (want 1)" % text.count(TESTS_OLD))
    else:
        plan.append((TESTS_OLD, TESTS_NEW))

    # replace the two unticked items with the expanded block
    eol2 = "\r\n" if "\r\n" in text else "\n"
    block_old = eol2.join(["- [ ] Ground-truth corpus",
                           "- [ ] TP/FP/TN/FN evaluation"])
    if text.count(block_old) != 1:
        problems.append("trailing roadmap block found %d times (want 1)" % text.count(block_old))
    else:
        plan.append((block_old, eol2.join(NEW_ITEMS.rstrip().split("\n"))))

    # status table row, tolerant of table formatting
    m = re.search(r"\|?\s*Verifier v0\.2\s*\|\s*Development target\s*\|?", text)
    if not m:
        problems.append("status-table row 'Verifier v0.2 | Development target' not found")
    else:
        plan.append((m.group(0),
                     m.group(0).replace(
                         "Development target",
                         "Two unreconciled implementations; see records/EACE-REC-001.md, -002.md")))
    return plan, problems


def main():
    write = "--write" in sys.argv
    if not README.is_file():
        print("README.md not found. Run from repo root.")
        return 2
    # read_text() applies universal newlines and silently converts CRLF to
    # LF, so the CRLF detection added for exactly this problem could never
    # fire: `"\r\n" in text` was always False. Confirmed on README.md --
    # 1208 CRLF, 0 bare LF, read_text() reported False. Reading bytes and
    # decoding explicitly is the only way the line ending survives.
    raw = README.read_bytes()
    text = raw.decode("utf-8")
    plan, problems = locate(text)

    print("=" * 74)
    print("README v0.2 PATCH  (%s)" % ("WRITE" if write else "DRY RUN"))
    print("=" * 74)
    print("line endings    : %s  (%d CRLF, %d bare LF)"
          % ("CRLF" if b"\r\n" in raw else "LF",
             raw.count(b"\r\n"), raw.count(b"\n") - raw.count(b"\r\n")))
    print("anchors located : %d" % len(plan))
    print("problems        : %d" % len(problems))
    for p in problems:
        print("  ! %s" % p)
    print()
    for old, new in plan:
        head = old.splitlines()[0][:58]
        print("  %-60s -> %d chars" % (head, len(new)))

    if problems:
        print()
        print("REFUSING TO WRITE. %d anchor(s) unresolved." % len(problems))
        print("A partially applied patch to a claims document is worse than none.")
        return 1

    if not write:
        print()
        print("Dry run only. Re-run with --write to apply.")
        return 0

    eol_out = "\r\n" if b"\r\n" in raw else "\n"
    out = text
    for old, new in plan:
        # every replacement, however constructed, is normalised to the
        # file's own line ending. Built per-anchor this produced a file
        # with mixed endings: eol.join() replacements carried CRLF,
        # triple-quoted ones carried LF.
        new = eol_out.join(new.replace("\r\n", "\n").split("\n"))
        out = out.replace(old, new, 1)
    README.write_bytes(out.encode("utf-8"))
    print()
    print("WROTE README.md  (%d -> %d bytes, %s preserved)"
          % (len(raw), len(out.encode("utf-8")),
             "CRLF" if "\r\n" in out else "LF"))
    print("Review with: git diff README.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
