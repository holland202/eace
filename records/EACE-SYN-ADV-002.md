# EACE-SYN-ADV-002 — Frozen Temporal / Replay Record

**Status:** FROZEN (container-confirmed; device re-run pending)

**Evidence class:** CONTAINER ONLY until aarch64 re-run.
See `reports/adv002_results.txt`.

**Location:** `experiments/eace_syn_adv_002/`  
**Module:** `eace/temporal.py`  
**Module SHA-256:** `617922bed8bbba877a1ea86999d78e3b13cb25ba0049aebf48c3c788e991bb2b`

## Result

Predictions P1–P5: **CONFIRMED**  
P6 (coherent-rewrite false positive): **NOT TESTED**

Key cell:

```
7_COHERENT_REWRITE + A2_FULL_REWRITE → ACCEPTED
7_COHERENT_REWRITE + A2P_PRECOMMIT   → CAUGHT (V8_PRECOMMIT)
```

## Interpretation

```
Internal chain  →  stops A1 only
Semantic checks →  stop partial A2 edits only
External precommit (V8) →  stops full rewrite when head left the forger's control
```

## Open door

Whether a coherent rewrite can **fabricate** a break that never happened
(false positive) is the next experiment (P6).
