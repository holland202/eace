# EACE-P0-ANDROID-BOUND-01 — Frozen Experimental Record

**Status:** External / device-specific experimental record  
**Scope:** Read-only capability probe  
**Date frozen:** Research baseline  

## Conditions

| Condition | UID | SELinux context | Workload | Outcome |
|-----------|-----|-----------------|----------|---------|
| A | 10505 | untrusted_app_27 | `pm dump com.android.settings` | DENIED |
| B | 2000 | shell | `rish -c "pm dump com.android.settings"` | ALLOWED |
| C | 10505 | untrusted_app_27 | `pm dump com.android.settings` (delegation absent) | DENIED |

## Interpretation

| Proposition | Status |
|-------------|--------|
| Capability differential | REPRODUCED |
| Delegated authority use | REPRODUCED |
| Zero-precondition escape | NOT OBSERVED |
| Android sandbox escape | NOT ESTABLISHED |
| Android vulnerability | NOT ESTABLISHED |
| Kernel compromise | NOT TESTED |
| Root escalation | NOT OBSERVED |

## Reference artifact hashes (frozen)

- Positive control (delegated): `3ef5aa9cf4eac22347ffd803a3a13b28926e0d8089e82db8edd6f3dc92c84389` (size 1,700,575)
- Denied baseline: `eebdb9a0b9d5ecab937189eea69435235e71bb56c38b065bc835340b24f02c14` (size 70)

## Explicit non-claims

- No kernel exploitation was performed.
- No SELinux bypass technique was developed or applied.
- No privilege-escalation exploit was used.
- No credentials were extracted.
- No persistence mechanism was installed.
- No third-party system was targeted.
- The differential is explained by intentional delegated authority (rish / Shizuku), not by a zero-precondition escape.

## Observer limitations (recorded)

- Failure to read `/proc` does not establish `hidepid`.
- Failure to observe a process does not establish SELinux causality.
- Successful observation does not automatically establish causality.
- `logcat` is supporting telemetry, not the authorization oracle.
- `payload_len > 0` is not equivalent to breach.
- Command output must be attributed to the correct process/workload.

## Protected-data negative control

Target: `/data/system/device_policy_state.xml`

Observed as system-owned with restrictive permissions (mode 0600).

| Reader | Metadata | Content |
|--------|----------|---------|
| App (UID 10505) | obtainable | DENIED |
| Shell (UID 2000, delegated) | obtainable | DENIED |

Interpretation:

| Proposition | Status |
|-------------|--------|
| APP CONTENT READ | DENIED |
| SHELL CONTENT READ | DENIED |
| PROTECTED DATA ACCESS | NOT ESTABLISHED |

metadata visibility ≠ protected-data access

This control demonstrates that the capability differential observed for `pm dump` does not extend to arbitrary protected system state.
