# EACE-SYN-ADV-002 — Frozen Temporal / Replay Record

**Status:** FROZEN  
**Location:** `experiments/eace_syn_adv_002/`  
**Module:** `eace/temporal.py`

## Result

Predictions P1–P5: **CONFIRMED**  
P6 (coherent-rewrite false positive): **NOT TESTED**

Key cell:

```
7_COHERENT_REWRITE + A2_FULL_REWRITE → ACCEPTED
7_COHERENT_REWRITE + A2P_PRECOMMIT   → CAUGHT (V8_PRECOMMIT)
```

Honest chain head prefix: `574a7c9931cc2d7b`

## Interpretation

```
Internal chain  →  stops A1 only
Semantic checks →  stop partial A2 edits only
External precommit (V8) →  stops full rewrite when head left the forger's control
```

## Open door

Whether a coherent rewrite can **fabricate** a break that never happened
(false positive) is the next experiment (P6).
