# Android Scope

## Strict scope

The Android experiments are **read-only capability probes**.

No instructions are provided for:

- kernel exploitation  
- SELinux bypass  
- privilege escalation  
- credential extraction  
- persistence  
- destructive modification  
- third-party targeting  

## P0 experiment summary

| Label | UID | SELinux | Command | Result |
|-------|-----|---------|---------|--------|
| A | 10505 | untrusted_app_27 | pm dump com.android.settings | DENIED |
| B | 2000 | shell | rish -c "pm dump com.android.settings" | ALLOWED |
| C | 10505 | untrusted_app_27 | pm dump (delegation absent) | DENIED |

## Interpretation

| Claim | Status |
|-------|--------|
| Capability differential | REPRODUCED |
| Delegated authority use | REPRODUCED |
| Zero-precondition escape | NOT OBSERVED |
| Android sandbox escape | NOT ESTABLISHED |
| Android vulnerability | NOT ESTABLISHED |

Do not overstate the result.
