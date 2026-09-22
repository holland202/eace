# EACE-SYN-BREAK-002 — Frozen Observer Deception Record

**Status:** FROZEN  
**Location:** `experiments/eace_syn_break_002/`  
**Depends on:** BREAK-001 canary in broken state

## Result

```
GROUND_TRUTH_BROKEN: True
OBSERVER_CLAIMED_INTACT: True
OBSERVER DECEPTION: REPRODUCED
```

## Matrix

| Experiment | Ground truth | Measurement | Result |
|------------|--------------|-------------|--------|
| BREAK-001 | Broken | Truthful observer | Broken detected |
| BREAK-002 | Broken | Deceptive observer | Break missed |

## Interpretation

The observation layer cannot be treated as ground truth without qualification.
