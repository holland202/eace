# EACE-REC-002 — The same defect class is present in verifier2.py

**Status:** Draft, device-measured
**Date:** 2026-09-22
**Component:** `eace/verifier2.py`
**Closes:** EACE-REC-001 open item O3
**Author:** Claude (Opus 4.6), directed by Chad Edward Holland

---

## Why this record exists

EACE-REC-001 documented five self-skipping guards in `VerifierV02`, a
component this author did not write, and disclosed that the finding was
produced while defending a duplicate implementation the author had pushed
by mistake. O3 was left open:

> Would an equivalent direct-guard probe against `eace/verifier2.py` find
> the same class of defect? NOT TESTED. It should be run before that
> component is preferred on the strength of this record.

It was run. It found the same class. REC-001 was accurate and selective.

---

## Result

Probe: `probe_verifier2_guards.py`. Both controls passed — a well-formed
bundle reaches `COMPLIANT_DENIED`, a wrong stdout hash reaches
`INTEGRITY_FAILURE` — so the rows below are findings rather than artifacts
of a wrong model.

### The defect class, present

Each case omits exactly one contract field and supplies evidence that only
that field's check could reject.

| Item | Contract omits | Evidence | Verdict |
|------|----------------|----------|---------|
| C1 | `expected_uid` | uid=2000 | COMPLIANT_DENIED |
| C2 | `expected_context_prefix` | ctx=u:r:shell:s0 | COMPLIANT_DENIED |
| C3 | `rc_expect` | rc=137, contradicts DENIED | COMPLIANT_DENIED |
| C4 | `required_provenance` | self-collected | COMPLIANT_DENIED |

Mechanism, identical in shape to M1/M2/M4 in REC-001:

```python
exp_uid = str(contract.get("expected_uid", ""))
if exp_uid and uid != exp_uid:        # absent field -> falsy -> never runs
```

```python
exp_ctx_prefix = contract.get("expected_context_prefix", "")
if exp_ctx_prefix and not ctx.startswith(exp_ctx_prefix):
```

```python
allowed_rc = (contract.get("rc_expect") or {}).get(state)
if allowed_rc is not None and rc not in allowed_rc:
```

C4 differs slightly: `required_provenance` defaults to `SELF_REPORTED`, the
weakest tier above UNKNOWN. A contract that says nothing about provenance
silently receives the weakest gate rather than being refused.

### Held

| Item | Input | Verdict |
|------|-------|---------|
| M1 | algorithm key absent | MANIFEST_INVALID |
| M2 | algorithm empty string | MANIFEST_INVALID |
| M3 | algorithm md5 | MANIFEST_INVALID |
| M4 | manifest omits stdout.txt | MANIFEST_INVALID |
| M7 | path traversal | MANIFEST_INVALID |
| I1 | uid synthetic | IDENTITY_MALFORMED |
| I2 | uid non-numeric | IDENTITY_MALFORMED |
| I3 | malformed context | IDENTITY_MALFORMED |
| I4 | duplicate uid | IDENTITY_MALFORMED |
| C5 | discriminants absent | UNCLASSIFIED_EVIDENCE |

The evidence-side guards hold. The contract-side guards do not.

---

## The distinction that matters, offered without using it as a defence

The two components skip on different inputs.

`VerifierV02` skips on **evidence** fields — an absent manifest algorithm,
a manifest that omits stdout. Evidence is produced by the subject under
test, so those skips are **attacker-triggerable**.

`verifier2.py` skips on **contract** fields. The contract is external and
operator-authored, so an attacker cannot omit a contract field. These are
**operator footguns**, not attack surface.

That is a real difference in exploitability and it should be recorded. It
is not a reason to rank the components, for two reasons:

1. `verifier2.py`'s entire stated thesis is that success criteria live
   outside attacker control. A contract that silently disables four gates
   by omission defeats that thesis at the operator's expense rather than
   the attacker's. The failure mode is an evaluator that reports
   COMPLIANT_DENIED while checking less than the operator believes.
2. REC-001 Finding 2 — the unreachable, untested positive path — has no
   counterpart here. `verifier2.py`'s CTRL-P control reaches
   `COMPLIANT_DENIED`, and its suite contains `35_GENUINE_SHELL_POSITIVE`,
   mutation-confirmed load-bearing. That asymmetry is real and is not
   addressed by this record.

Both components have the same defect class. They are not therefore equal,
and this record does not claim they are.

---

## Repair

Contract completeness validation: refuse to run against a contract that
omits any gating field, rather than silently skipping the gate. This is the
same logic as the `ContractIncomplete` check in `eace/hardening.py`, applied
one level down — a mandatory contract is worth little if the contract may
be arbitrarily incomplete.

Not implemented. No file was modified by this record.

---

## Reproduction

```
python3 probe_verifier2_guards.py
```

Controls CTRL-P and CTRL-R must read "as expected". If either fails, the
probe's model of the verifier is wrong and every other row is NOT TESTED.

---

## What is NOT established

- **Reproduced on device** (aarch64/py3.14) and in container (x86_64/py3.12). C1-C4 identical, controls passed in both.
- **The probe is not exhaustive.** It tests the contract fields the author
  knew to look for, having written the file. A third party probing without
  that knowledge would likely construct different cases.
- **Self-audit.** REC-001 probed a component the author did not write. This
  record probes one the author did. The asymmetry in familiarity runs the
  other way and is not corrected by symmetry in method.

---

## Open

- **O4** Does contract completeness validation, once implemented, break any
  of the 37 regression cases? NOT TESTED.
- **O5** Are there gating fields not covered by C1–C5? NOT TESTED. The
  probe was written from the author's memory of the implementation, which
  is the weakest possible search strategy for finding what the author
  forgot.
