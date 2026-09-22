# EACE-SYN-ADV-002 — Temporal / Replay Attack

**Status:** FROZEN POSITIVE CONTROL (predictions P1–P5 confirmed)

Synthetic event streams only. No Android command executed.

## What this tests

```
content integrity  ≠  provenance integrity  ≠  causal validity
```

## Adversary models

| Model | Capability |
|-------|------------|
| **A1** PAYLOAD_ONLY | Edit event content; cannot recompute `d`/`h` |
| **A2** FULL_REWRITE | Edit content and re-seal the whole chain |
| **A2P** PRECOMMIT | A2, but validator holds a chain head committed *before* the forgery window |

## Attack matrix (frozen)

| Attack | A1 | A2 | A2P |
|--------|----|----|-----|
| 1_REPLAY | CAUGHT (V1_CHAIN) | CAUGHT (V4_FRESHNESS) | CAUGHT (V4_FRESHNESS) |
| 2_REORDER | CAUGHT (V1_CHAIN) | CAUGHT (V2_DAG) | CAUGHT (V2_DAG) |
| 3_STALE | CAUGHT (V1_CHAIN) | CAUGHT (V4_FRESHNESS) | CAUGHT (V4_FRESHNESS) |
| 4_FUTURE | CAUGHT (V1_CHAIN) | CAUGHT (V4_FRESHNESS) | CAUGHT (V4_FRESHNESS) |
| 5_DUPLICATE | CAUGHT (V1_CHAIN) | CAUGHT (V4_FRESHNESS) | CAUGHT (V4_FRESHNESS) |
| 6_GAP | CAUGHT (V1_CHAIN) | CAUGHT (V6_STATE_CONTINUITY) | CAUGHT (V6_STATE_CONTINUITY) |
| 7_COHERENT_REWRITE | CAUGHT (V1_CHAIN) | **ACCEPTED** | CAUGHT (V8_PRECOMMIT) |

Externally committed chain head (honest): `574a7c9931cc2d7b…`

## Predictions

| ID | Claim | Outcome |
|----|-------|--------|
| P1 | A1 catches all six partial attacks at V1_CHAIN | CONFIRMED |
| P2 | A2 defeats V1_CHAIN in every case | CONFIRMED |
| P3 | Coherent rewrite passes every internal check under A2 | CONFIRMED |
| P4 | A2P catches every attack | CONFIRMED |
| P5 | Honest run validates clean under all models | CONFIRMED |
| P6 | Coherent-rewrite false positive (fabricate a break) | **NOT TESTED** |

## Bottom line

Internal chaining defends against an adversary who cannot re-seal.
It defends against nothing once the adversary can.

**V8 works**, and V8 is not an internal check: it needs a commitment that left
the forger's control before the forgery window.

## Reproduction

```bash
python3 experiments/eace_syn_adv_002/run_attacks.py
```

## Non-claims

- No Android / kernel / SELinux claim
- No production verifier qualification
- P6 deliberately left unrun
