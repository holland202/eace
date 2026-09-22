# EACE-SYN-ADV-001 — Provenance Integrity Attacks (Documented Class)

**Status:** DOCUMENTED — design for subsequent implementation

## Finding class

> A provenance hash can be perfectly valid while the provenance claim itself is false.

Hash integrity answers: *"Does this hash correspond to these bytes?"*  
It does **not** answer: *"Did these bytes actually originate from the claimed run?"*

## Attack pattern

1. Capture valid evidence from Run A.
2. Alter identity fields to claim Run B.
3. Recompute the hash over the altered structure.
4. Present to a verifier that only checks hash integrity.

Result:

| Property | Outcome |
|----------|--------|
| Hash integrity | PASS |
| Identity authenticity | FAIL / UNPROVEN |

## Required verifier response (target)

```
PROVENANCE: INVALID or UNPROVEN
CONTENT_INTEGRITY: VALID
VERDICT: REJECTED / IDENTITY_MISMATCH / PROVENANCE_FAILURE
```

Not merely: `HASH_VALID`.

## Relation to the integrity triad

| Property | Attack |
|----------|--------|
| Content integrity | Mutate bytes without updating hash |
| Provenance integrity | Rebind valid bytes to a false run identity |
| Causal validity | Temporal / replay (ADV-002) |
