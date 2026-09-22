# EACE-SYN-BREAK-002 — Observer Deception Positive Control

**Status:** FROZEN POSITIVE CONTROL

Depends on: `experiments/eace_syn_break_001` (canary must be in the broken state).

## Objective

Attack the observation layer while retaining known ground truth.

```
GROUND TRUTH:       BROKEN
OBSERVER REPORT:    INTACT
CORRECT VERDICT:    BROKEN / OBSERVER FAILURE
```

## Experimental matrix

| Experiment | Ground truth | Measurement | Result |
|------------|--------------|-------------|--------|
| BREAK-001 | Broken | Truthful observer | Broken detected |
| BREAK-002 | Broken | Deceptive observer | Break missed |

## Reproduction

```bash
python3 ../eace_syn_break_001/lab.py
python3 ground_truth.py
python3 deceptive_observer.py
python3 test_observer.py
```

Expected:

```
GROUND_TRUTH_BROKEN: True
OBSERVER_CLAIMED_INTACT: True
OBSERVER DECEPTION: REPRODUCED
```

## What this demonstrates

The observation layer cannot be treated as ground truth without qualification.

## What this does NOT demonstrate

Independent verification failure on a production system.
Any real-world Android / kernel / SELinux claim.
