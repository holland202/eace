# EACE Synthetic Experiments

Local, controlled experiments only. No third-party targets.

## Attack ladder

```
BREAK-001  Actual containment violation (known positive control)
    │
    ▼
BREAK-002  Observer deception (ground truth broken, report intact)
    │
    ▼
ADV-001    Provenance / identity binding attacks (planned / documented)
    │
    ▼
ADV-002    Temporal / replay attacks (planned)
```

## Experimental distinction

| Layer | Question |
|-------|----------|
| **Containment** | Did the unauthorized state transition actually occur? |
| **Observation** | Did the measurement system observe it? |
| **Verification** | Did the evaluator correctly establish what happened? |

BREAK-001 establishes a genuine containment failure.  
BREAK-002 establishes that observation can lie while ground truth remains known.

## Three integrity properties

```
CONTENT INTEGRITY
      ↓
"These bytes weren't changed after hashing."

PROVENANCE INTEGRITY
      ↓
"These bytes are bound to the claimed run."

CAUSAL VALIDITY
      ↓
"This observation actually supports the claimed transition."
```

Passing the first does not imply passing the second or third.

## Status

| ID | Status | Result |
|----|--------|--------|
| EACE-SYN-BREAK-001 | FROZEN POSITIVE CONTROL | CONTAINMENT: BROKEN |
| EACE-SYN-BREAK-002 | FROZEN POSITIVE CONTROL | OBSERVER DECEPTION: REPRODUCED |
| EACE-SYN-ADV-001 | DOCUMENTED | Provenance forgery class |
| EACE-SYN-ADV-002 | DOCUMENTED | Temporal / replay class |

## Non-claims

These experiments do **not** establish Android sandbox escape, kernel compromise,
SELinux bypass, Shizuku/rish vulnerability, or any production-system claim.
