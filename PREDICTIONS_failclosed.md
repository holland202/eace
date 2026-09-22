# EACE fail-closed retrofit — registered predictions

**Registered:** 2026-09-22
**Purpose:** First real use of SWAY
**Scope:** Retrofit of the nine self-skipping gates identified in EACE-REC-001 and EACE-REC-002.
**Status:** REGISTERED — predictions made before verifier implementation changes.

## Method

The baseline defects are already measured in:

- `records/EACE-REC-001.md` — five self-skipping guards in `eace/verifier.py`
- `records/EACE-REC-002.md` — four self-skipping contract gates in `eace/verifier2.py`

This file registers what the retrofit is expected to do. It is not evidence that the retrofit succeeds.

For each guard, three outcomes are registered:

1. **Baseline negative mutant:** the defect-triggering input currently survives or skips the guard.
2. **Retrofit negative mutant:** the same input will be rejected after the retrofit.
3. **Benign control:** a valid input exercising the same gate will continue to pass.

A failed benign control does not count as a successful hardening result. It is a regression.

The two verifier implementations remain separate. This retrofit does not decide which implementation should become canonical.

---

## Registered guard predictions

| ID | Component | Guard | Baseline prediction | Retrofit prediction | Benign prediction |
|---|---|---|---|---|---|
| M1 | `VerifierV02` | manifest `algorithm` absent | mutant survives/skips | absent `algorithm` is rejected | valid declared algorithm passes |
| M2 | `VerifierV02` | manifest `algorithm` empty | mutant survives/skips | empty `algorithm` is rejected | valid declared algorithm passes |
| M4 | `VerifierV02` | manifest omits `stdout` entry | mutant survives/skips | missing `stdout` coverage is rejected | correctly covered `stdout` passes |
| I1 | `VerifierV02` | `uid="synthetic-..."` production-path bypass | mutant survives identity gate | synthetic UID is rejected on production path | valid numeric UID passes |
| I3 | `VerifierV02` | malformed/corrupted `selinux_context` not validated by identity gate | mutant survives/skips | invalid context is rejected | valid SELinux context passes |
| C1 | `verifier2.py` | contract `expected_uid` absent | mutant survives/skips | missing `expected_uid` is rejected before verification | complete matching UID contract passes |
| C2 | `verifier2.py` | contract `expected_context_prefix` absent | mutant survives/skips | missing context-prefix gate is rejected before verification | complete matching context contract passes |
| C3 | `verifier2.py` | contract `rc_expect` absent | mutant survives/skips | missing return-code gate is rejected before verification | complete matching return-code contract passes |
| C4 | `verifier2.py` | contract `required_provenance` absent | mutant survives/skips or receives weakest default | missing provenance requirement is rejected before verification | explicit acceptable provenance passes |

## Guard-level acceptance rule

A guard is considered **hardened** only if all three registered predictions hold:

- the retrofit negative mutant is demonstrably rejected after the retrofit;
- the benign control still passes;
- no downstream stage can mask whether the guard itself fired.

If the negative mutant is rejected only because a later unrelated stage refuses it, that does **not** establish the guard prediction.

If a benign control fails, record the regression rather than weakening the negative test.

## I1 special prediction

`I1` has a known complication: `synthetic-*` identities may be load-bearing for existing tests.

The registered prediction is therefore **not** "delete synthetic identities."

It is:

> A synthetic identity must not satisfy the production-path identity gate unless an explicit test-only affordance is enabled.

The existing suite must be measured after the retrofit. Any breakage is evidence to record, not silently worked around.

## Symmetry prediction

The retrofit will be applied independently to both implementations.

No prediction is registered here that either implementation is preferable.

In particular, the following remain open:

- whether `VerifierV02` or `verifier2.py` should be canonical;
- whether the two implementations have equivalent semantic coverage;
- whether either implementation contains additional untested gates.

## Evidence requirements

The final result must include:

1. the exact commit containing the retrofit;
2. device execution on the S25 Ultra / Termux / aarch64 / Python 3.14.6;
3. the negative mutant result for each guard;
4. the benign control result for each guard;
5. the existing regression-suite result;
6. the fail-closed gate result in both directions;
7. a cold-clone reproduction from the pushed commit.

A failure remains visible as `REFUTED`, `FAILED`, or `NOT TESTED` as appropriate. It is not converted into a pass by changing the test or prediction after observation.

## What this registration does not claim

This registration does not claim that:

- the retrofit will succeed;
- the nine guards are exhaustive;
- the existing test suites are complete;
- either verifier is secure;
- either verifier should be preferred;
- the SWAY method itself has been validated.

Those questions require separate evidence.
