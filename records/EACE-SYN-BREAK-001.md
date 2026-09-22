# EACE-SYN-BREAK-001 — Frozen Positive Control Record

**Status:** FROZEN  
**Location:** `experiments/eace_syn_break_001/`

## Result

| Proposition | Status |
|-------------|--------|
| UNAUTHORIZED ACTION | OBSERVED |
| BOUNDARY CROSSING | OBSERVED |
| PROTECTED STATE CHANGE | OBSERVED |
| HASH CHANGE | OBSERVED |
| OBSERVER CONFIRMATION | OBSERVED |
| CONTAINMENT | BROKEN |
| INDEPENDENT VERIFICATION | NOT ESTABLISHED |

## Frozen hashes

| State | SHA-256 |
|-------|---------|
| Baseline | `5c8dcb1d2020f5bb27f2cc066a26600878435c8fc9d45dad26ff9989fb76e656` |
| Post-attack | `9cd27a3f8c3a8177c6519ff7957b824bdb0836a4b8b9bc8d3e794887834710b9` |

## Vulnerability class

Unresolved-path authorization check (string-level) prior to filesystem resolution of `..`.

**Intentional.** Local synthetic target only.
