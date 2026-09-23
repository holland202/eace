# EACE Note — Instrument Validity, PLUMB (Speculative), and Veritas Post-Check

**Status:** Working note / draft  
**Date:** 2026-09-22  
**Scope:** Captures the recurring instrument-failure pattern, the proposed PLUMB checks (explicitly *not* validated or promoted), the concrete Veritas post-execution verifier, and the current state of `eprocess.py`.  
**Relationship:** Does not modify or replace any existing METHOD_*.md. Does not claim PLUMB as a method.  
**Decision rule applied:** Measure the archive first; do not invent another acronym until the failure-mode count justifies it.

---

## 1. Observed pattern (the real phenomenon)

Many measured failures in the archive were not wrong hypotheses.  
They were broken instruments:

- empty-scan exit 0 counted as “clean”
- masked crashes treated as verdicts
- 0/1 reported as “0.0 %” with an enormous interval
- unseeded / non-deterministic gates that flipped under repeated runs
- container results that did not hold on device
- artifacts that existed only in a sandbox or under an untracked path
- claims made about file contents without a fresh read in the current session

The recurring meta-problem is:

> The experiment appears to produce an answer, but something underneath the experiment means the answer is not trustworthy.

Investigation of the instrument then reveals the real failure mode.

---

## 2. PLUMB — Speculative layer only

**Working name:** PLUMB  
**Status:** Speculative. NOT VALIDATED. Not yet a method.

**Core premise:** Certify the instrument before any result can count.

### The eight checks (each tied to a measured failure)

1. **Two-sided certification**  
   Instrument must return null on a clean fixture and non-null on a defect fixture.  
   Exit codes: 0 = looked, clean; 1 = looked, found; 2 = could not look.  
   A crash is never a verdict.  
   *Origin:* empty-scan exit 0; mutation_probe masked crash.

2. **Denominator + interval**  
   Every rate is reported as k/n with the eligible unit defined and a Clopper-Pearson 95 % interval.  
   No interval → no claim.  
   *Origin:* 0/1 reported as “0.0 %”.

3. **Verdict stability**  
   Gate runs K times in fresh processes. Any flip is FAIL.  
   Every RNG is seeded and the seed is printed.  
   *Origin:* quasar `assert n>=40` ranging 31–62 across 60 runs.

4. **Cross-substrate decision check**  
   Run on aarch64 device and x86_64 container; compare *decisions*, not just values.  
   Tie-breaks must be explicit.  
   *Origin:* argsort tie (1/82 vs 4/82); note054 spearman bug.

5. **Environment as a variable**  
   Log thermal and load state with every run.  
   Anything that moves with it is reported as a distribution, not a point.  
   *Origin:* reachability 25/45/46 on device vs stable 44 in container.

6. **Provenance closure**  
   Every artifact in the claim chain sits at a pinned public hash + md5.  
   Sandbox-only or unnamed artifacts count as history, not baseline.  
   *Origin:* note052 0/347 control arm; note060 in /sdcard.

7. **Read before assert**  
   Any statement about a file’s contents cites command output from the current session.  
   *Origin:* note057 error; proposing already-existing notes.

8. **Calibration ledger**  
   Every registered prediction carries a probability; Brier score tracked per contributor.  
   *Origin:* two refuted vacuity predictions.

### Anti-vacuity tests for PLUMB itself (registered before any run)

- **P1 (circular by construction):** Applied blind to the pre-fix states of six known defects, checks 1–6 flag ≥ 5 of 6.  
  Passing only shows the checks are implemented correctly.
- **P2 (anti-vacuity):** On the post-fix states, flags ≤ 1. More than that = always-alarm.
- **P3 (the unrun door):** Does it catch anything in a repo it was not derived from?  
  This is the real generalization test and remains open.

**Cost note:** Check 3 multiplies runtime by K. At K=20, long gates become expensive on device; scale K with runtime or run long gates in the container.

**Explicit decision (2026-09-22):**  
Do **not** create METHOD_PLUMB.md or a full harness yet.  
First classify the existing failure archive:

```
hypothesis failure
instrument failure
implementation failure
provenance failure
environment failure
statistical / reporting failure
```

Only if instrument-validity failures dominate does PLUMB earn the right to exist as a named layer.  
Otherwise the insight stays distributed across SWAY / Veritas / EACE / SENTINEL.

---

## 3. Concrete artifact: Veritas post-execution verifier

This is the only new code produced today.  
It implements the most important fail-closed rules for any Veritas gate run.

**File:** `veritas_postcheck.py` (to be added)

```python
import sys

def verify_veritas_output(stdout: str, stderr: str, returncode: int) -> bool:
    """
    Fail-closed post-execution check for the Veritas gate.
    Never treats a crash, empty run, or missing pipeline stage as a PASS.
    """
    violations = []

    # 1. Exit-code discipline (0 = looked and clean)
    if returncode != 0:
        violations.append(
            f"VERITAS_FAIL: non-zero exit ({returncode}). "
            f"stderr={stderr.strip()[:400]!r}"
        )

    # 2. Masked crash / exception leakage (even on exit 0)
    crash_markers = (
        "Traceback (most recent call last)",
        "Exception:",
        "Error:",
        "AssertionError",
        "RuntimeError",
    )
    for marker in crash_markers:
        if marker in stdout or marker in stderr:
            violations.append(
                f"VERITAS_FAIL: crash/exception marker present ({marker!r})"
            )
            break

    # 3. Vacuity / pipeline-execution check
    required_tokens = (
        "STATE_VECTOR_MAPPING",
        "DETERMINISTIC_COLLAPSE",
    )
    for token in required_tokens:
        if token not in stdout:
            violations.append(
                f"VERITAS_FAIL: mandatory pipeline token missing ({token!r})"
            )

    # 4. Zero-output success is not success
    if returncode == 0 and not stdout.strip():
        violations.append(
            "VERITAS_FAIL: empty stdout on exit 0 (no evidence of work)"
        )

    if violations:
        print("\n".join(violations), file=sys.stderr)
        sys.exit(1)

    print("VERITAS_POST_CHECK: PASS")
    return True


if __name__ == "__main__":
    print("veritas_postcheck.py loaded. "
          "Import and call verify_veritas_output(stdout, stderr, rc)")
```

**Usage (after the real gate has run):**

```python
from veritas_postcheck import verify_veritas_output

# rc, out, err = run_veritas_gate()   # existing runner
# verify_veritas_output(out, err, rc)
```

**What it covers today**

| Rule                         | Covered |
|------------------------------|---------|
| Exit-code discipline         | yes     |
| Crash ≠ verdict              | yes     |
| Vacuity (pipeline actually ran) | yes  |
| Empty success rejected       | yes     |
| Fail-closed                  | yes     |

It does **not** yet implement K-run stability, cross-arch comparison, artifact md5, or thermal logging. Those remain future work if the archive count warrants them.

---

## 4. Current state of `eprocess.py` (untracked)

Observed on 2026-09-22 (first 50 lines + trailing logic):

```python
"""Betting e-process for H0: success rate <= p0 (anytime-valid).
Validity (analytic): for lam in [0, 1/p0], every factor is >= 0 and
E[factor | p <= p0] = 1 + lam*(p - p0) <= 1, so wealth is a nonnegative
supermartingale; Ville gives P(ever >= 1/alpha) <= alpha.
Gate (simulation): implementation check only, not the proof."""
import random, sys

def check_domain(p0, lam):
    if not (0 < p0 < 1 and 0 <= lam <= 1 / p0):
        raise ValueError(f"lam={lam} outside [0, 1/p0] for H0: p <= p0={p0}")

def e_process(xs, p0, lam=0.5):
    check_domain(p0, lam)            # eager: fires on call, not on first iteration
    def run():
        w = 1.0
        for x in xs:                 # x in {0,1}
            w *= 1 + lam * (x - p0)
            yield w
    return run()

def rejects(xs, p0, alpha=0.05, lam=0.5):
    return any(w >= 1 / alpha for w in e_process(xs, p0, lam))  # peek every step

def rate(p_true, p0=0.5, n=200, trials=2000, seed=0):
    rng = random.Random(seed)
    hits = sum(rejects([rng.random() < p_true for _ in range(n)], p0)
               for _ in range(trials))
    return hits / trials

def guard_fires(p0, lam):
    try:
        e_process([], p0, lam)
        return False
    except ValueError:
        return True

print("python:", sys.version.split()[0])
if "--sabotage" in sys.argv:          # must exit 1: bad lam has to be refused
    ok = not guard_fires(0.5, -0.5)
    print("sabotage lam=-0.5 accepted:", ok)
    print("GATE:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)

null = rate(0.5)   # anti-vacuity: H0 true, peeking at all 200 steps
alt  = rate(0.7)   # real effect
guard = guard_fires(0.5, -0.5) and guard_fires(0.5, 2.5) and not guard_fires(0.5, 0.5)
print(f"null rejection rate (must be <= 0.05): {null:.4f}")
print(f"alt  rejection rate (must be high):    {alt:.4f}")
print(f"domain guard (bad lam refused, good lam accepted): {guard}")
ok = null <= 0.05 and alt >= 0.8 and guard
```

**Notes on this file**

- Already contains a two-sided / sabotage path (`--sabotage`).
- Already performs an anti-vacuity check (null rejection rate under H0).
- Domain guard is eager.
- Still untracked (`?? eprocess.py`).
- The Veritas-style post-check above can be applied to any future gate that wraps this logic.

Also untracked: `tests/test_v02_hardening.py`.

---

## 5. Fresh device record (already committed)

`records/EACE-P0-FRESH-2026-09-22.md` was committed and pushed as:

```
[main e668b47] android: record fresh 2026-09-22 capability differential
```

It is a separate observation from the frozen Android-bound record and does not replace it.

---

## 6. Immediate next actions (ordered)

1. Place `veritas_postcheck.py` under version control (or fold the function into an existing module).
2. Decide whether `eprocess.py` and `tests/test_v02_hardening.py` should be committed together with it.
3. **Do the archive classification experiment** before any further PLUMB implementation:
   - Collect the known serious failures.
   - Tag each as hypothesis / instrument / implementation / provenance / environment / statistical.
   - Count.
4. Only if instrument failures dominate, promote the relevant subset of checks into a thin harness that SWAY (or Veritas) can call.
5. Keep the rest of the insight distributed; resist method proliferation.

---

## 7. Explicit non-claims

- PLUMB is not a method.
- No new METHOD_*.md has been created.
- The post-check is a local, fail-closed utility, not a certification of any scientific claim.
- Container results remain container results until repeated on device with environment logged.

---

*End of note.*
