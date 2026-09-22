# EACE-REC-001 — Two measured defects in VerifierV02

**Status:** Draft, device-measured
**Date:** 2026-09-22
**Component:** `eace/verifier.py` — `VerifierV02`
**Device:** Samsung Galaxy S25 Ultra, Termux, aarch64, Python 3.14
**Author:** Claude (Opus 4.6), directed by Chad Edward Holland

---

## Disclosure of motive

These findings were produced while the author was defending a duplicate
implementation it had pushed by mistake.

Commit `1991750` added `eace/verifier2.py`, a second component claiming
version 0.2, built against a stale README that listed v0.2 as an unstarted
development target. `VerifierV02` already existed. On discovering the
collision the author first recommended reverting its own commit, then
investigated `VerifierV02` and found defects in it.

That ordering gives the author a motive to find fault with the incumbent. A
hostile reviewer would notice it, so it is stated here rather than left to
be noticed. Both findings below are reproducible by a third party in one
command each and do not depend on the author's judgement. They should be
checked on that basis, not accepted on the author's.

---

## Finding 1 — Five guards that skip themselves

`VerifierV02._check_manifest` and `_check_identity` each contain checks that
pass silently when their input is absent, empty, or falsy. The logic is
present. It does not run.

Measured by calling the guards directly, so the result does not depend on
the surrounding pipeline:

| Item | Input | Guard result | Expected |
|------|-------|--------------|----------|
| M1 | `algorithm` key absent entirely | PASSED | REJECTED |
| M2 | `algorithm` is the empty string | PASSED | REJECTED |
| M4 | `entries` omits `stdout` | PASSED | REJECTED |
| I1 | `uid="synthetic-attacker"` | PASSED | REJECTED |
| I3 | `selinux_context="CORRUPTED"` | PASSED | REJECTED |

Controls, which establish the probe's model of the guards is correct:

| Item | Input | Guard result | Expected |
|------|-------|--------------|----------|
| M5 | declared hash wrong | REJECTED | REJECTED |
| M6 | well-formed manifest | PASSED | PASSED |
| I5 | well-formed identity | PASSED | PASSED |

Guards confirmed working: M3 (`md5` rejected), M7 (path traversal
rejected), I2 (non-numeric uid rejected), I4 (duplicate identity
declarations rejected).

### Mechanism

**M1, M2** — `algo = manifest.get("algorithm", "").upper()` followed by
`if algo and algo not in ("SHA256", "SHA-256")`. An absent key yields `""`,
an empty string stays `""`, and `if algo` is false in both cases, so the
comparison never executes. A manifest that declares no algorithm is
accepted.

**M4** — `declared = entries.get("stdout") or entries.get("./stdout") or
entries.get("stdout.bin")` followed by `if declared and ...`. A manifest
that does not list stdout under one of those three keys produces
`declared = None`, and the integrity comparison is skipped. The check that
catches a forged stdout is disabled by omitting stdout from the manifest.

**I1** — `if not (uid.isdigit() or uid.startswith("synthetic"))`. The
`synthetic` branch is a test affordance reachable on the production path.
Note: it is probably load-bearing for the existing 48-test suite. The
repair is to gate it behind an explicit flag the production path does not
set, not to delete it. Check what breaks first.

**I3** — `_check_identity` reads `uid` and never reads `selinux_context`.
Context is compared only at step 5 of `verify()`, inside
`if self.contract is not None`. On the no-contract path it is never
examined, and on every path its grammar is never validated.

### Reproduction

```
python3 probe_v02_guards.py
```

Controls M5, M6 and I5 must read "as expected". If any control fails, the
probe's model of the guard is wrong and every other row is NOT TESTED
rather than a finding.

---

## Finding 2 — The positive verdict is unreachable and untested

`VerifierV02` can return `COMPLIANT` only when `_infer_observed_outcome`
returns a definite outcome, and that function compares the stdout hash
against two module-level constants:

```
POSITIVE_CONTROL_HASH = 3ef5aa9cf4eac22347ffd803a3a13b28926e0d8089e82db8edd6f3dc92c84389
DENIED_BASELINE_HASH  = eebdb9a0b9d5ecab937189eea69435235e71bb56c38b065bc835340b24f02c14
```

Any other output returns `"AMBIGUOUS"`, and `verify()` returns `AMBIGUOUS`.

Two measurements:

1. A recursive scan of the working tree found **0 files** matching either
   hash. Neither control artifact is committed.
2. `grep -c "COMPLIANT" tests/test_verifier_v02.py` returns **0**. The test
   suite never asserts the positive verdict.

Therefore, from a clean clone, no input a third party can construct reaches
`COMPLIANT`, and nothing in the 48-test suite attempts it. The suite
exercises refusal branches only.

### Why this is a finding and not a style note

A verifier that refuses everything scores zero false positives. So does a
correct one. The score does not distinguish them, and the anti-vacuity
control is what separates the two — the instrument must be shown capable of
returning a value.

This is the same shape as the `FAILCLOSED_NO_WITNESS` configuration
measured in ADV-002 P6, which scored 0 FP and 0 FN by emitting one constant
verdict and refusing the honest runs along with the forged ones. It is also
the same shape as the inert `identity_uid_guard` found by mutation testing
in the v0.2 suite: a check that exists and does not run.

### Secondary consequence

Hash equality against a stored artifact recognises **replays**, not new
crossings. A genuine new capability crossing will not match a stored hash
by definition, so this semantic model can only ever confirm something
already recorded. This was predicted before measurement and is the reason
`contracts/eace_contracts_v1.json` treats negative and positive reference
hashes asymmetrically.

### Reproduction

```
python3 -c "
import hashlib,pathlib
H={'eebdb9a0b9d5ecab937189eea69435235e71bb56c38b065bc835340b24f02c14':'DENIED',
   '3ef5aa9cf4eac22347ffd803a3a13b28926e0d8089e82db8edd6f3dc92c84389':'POSITIVE'}
f=0
for p in sorted(pathlib.Path('.').rglob('*')):
    if p.is_file() and p.stat().st_size < 5000000:
        try: h=hashlib.sha256(p.read_bytes()).hexdigest()
        except Exception: continue
        if h in H: print(H[h], p); f+=1
print('found', f)"
grep -c "COMPLIANT" tests/test_verifier_v02.py
```

---

## What is NOT established

- **No claim that `VerifierV02` is worse than `eace/verifier2.py`.** The
  two have different interfaces — dict versus on-disk bundle — and
  `verifier2.py` has not been subjected to an equivalent independent probe.
  Its 37-case suite was written by the same author as the implementation.
- **No claim about which should be canonical.** That is a decision about
  the repository, not a measurement.
- **Finding 1 lists repairs, not repairs made.** Nothing in
  `eace/verifier.py` has been modified.
- **The 48-test suite has not been audited** beyond the single `COMPLIANT`
  grep. Whether it exercises other positive-shaped verdicts under different
  names is NOT TESTED.

---

## Method note

Both findings were produced by instruments that failed first and were
repaired.

The first probe (`test_v02_hardening.py`) read the terminal verdict of
`verify()` and reported M1–M4 and I1 as "holds". That was wrong.
`_infer_observed_outcome` returns `AMBIGUOUS` for any stdout not matching a
control hash, so the terminal verdict could not distinguish *guard
rejected* from *guard passed* from *guard skipped*. The probe was shadowed
by a downstream stage — the same defect class it was built to detect.

`probe_v02_guards.py` calls the guards directly and carries three controls
so that a wrong model of the guard is visible in the output rather than
silent.

During this session the same shadowing pattern was found six times: once in
the v0.2 regression suite (`identity_uid_guard`), twice in the P6
adjudicator, once as a guard so subsumed no probe could reach it, twice in
the hardening tests, and once in this probe. In every case it was found by
mutation or by a control, never by reading.

The generalisation, offered as a hypothesis rather than a result:

> A test that changes two fields at once tests neither.

---

## Open

- **O1** Does the 48-test suite reach any positive-shaped verdict under
  another name? NOT TESTED.
- **O2** Does repairing I1 break the existing suite, and by how much? NOT
  TESTED.
- **O3** Would an equivalent direct-guard probe against `eace/verifier2.py`
  find the same class of defect? NOT TESTED. It should be run before that
  component is preferred on the strength of this record.

O3 is the one that matters. This record documents defects in the component
the author did not write. The symmetric test has not been performed.
