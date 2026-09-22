# EACE-SYN-ADV-002 — Temporal / Replay Attack Class (Documented)

**Status:** DOCUMENTED — design for subsequent implementation

## Goal

Make evidence **temporally wrong** while remaining internally hash-valid.

## Event model (recommended)

```
event_id
parent_event
tick          # monotonic sequence, not wall-clock alone
run_id
scenario
state_before
action
state_after
observation
```

## Attack variants

1. **Replay** — present a valid T1 (unchanged) observation as the observation at T3 (post-break).
2. **Reordering** — move T1 observation after the T3 state change.
3. **Stale observation** — valid hash, but older than the transition it claims to describe.
4. **Future observation** — attach a T4 observation to T2.
5. **Duplicate observation** — reuse one valid observation for multiple transitions.
6. **Gap attack** — remove the event containing the actual transition.

## Critical invariant

For observations that claim to describe the post-transition state:

```
t_observation ≥ t_transition
```

Prefer monotonic `tick` / `event_id` graphs over wall-clock timestamps.

## Target verifier response

```
PROVENANCE: VALID
TEMPORAL_ORDER: INVALID
OBSERVATION_FRESHNESS: INVALID
STATE_TRANSITION_SUPPORT: INVALID
VERDICT: REJECTED
```
