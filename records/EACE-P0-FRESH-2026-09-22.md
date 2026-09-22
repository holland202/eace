# EACE-P0-FRESH-2026-09-22 — Fresh Device Capability Differential

**Status:** Fresh device observation
**Date:** 2026-09-22
**Scope:** Read-only capability probe
**Relationship to frozen record:** Separate fresh run; does not modify or replace `records/EACE-P0-ANDROID-BOUND-01.md`

## Device environment

| Field | Observation |
|---|---|
| Timestamp | 2026-09-22T18:23:44-05:00 |
| Model | SM-S938U |
| Android release | 16 |
| Android SDK | 36 |
| Kernel | 6.6.98-android15-8-pd6ff1cd-abogkiS938USQSCCZF9-4k |
| Architecture | aarch64 |
| Python | 3.14.6 |
| rish version | Not obtained; `rish --version` returned an Android shell argument error |

## Delegated condition

Command:

    rish -c 'id; echo "---SELINUX---"; id -Z; echo "---PM DUMP---"; pm dump com.android.settings >/tmp/eace_rish_pm_dump.txt 2>&1; rc=$?; echo "RC=$rc"; wc -c /tmp/eace_rish_pm_dump.txt; head -20 /tmp/eace_rish_pm_dump.txt; exit $rc'

Observed identity:

    uid=2000(shell)
    context=u:r:shell:s0

Observed result:

    RC=0
    output size=3095106 bytes

The captured output began with package-manager service data including `com.android.settings` entries.

## Ordinary application condition

A first attempt redirected output to `/tmp/eace_app_pm_dump.txt`. That attempt was discarded because the ordinary application context did not have permission to create that output file. It is not treated as a workload result.

The valid follow-up command was:

    id; echo "---SELINUX---"; id -Z; echo "---PM DUMP---"; pm dump com.android.settings 2>&1 | head -20; rc=${PIPESTATUS[0]}; echo "PM_DUMP_RC=$rc"; exit "$rc"

Observed identity:

    uid=10505(u0_a505)
    context=u:r:untrusted_app_27:s0:c249,c257,c512,c768

Observed result:

    PM_DUMP_RC=2

Observed output:

    cmd: Failure calling service package: Failed transaction (2147483646)

## Fresh observation

Under the tested conditions, the same `pm dump com.android.settings` workload produced a successful package-manager dump through the delegated `rish` shell context and a failed transaction from the ordinary Termux application context.

This is a fresh observation of a capability differential between the two tested execution contexts.

## Explicit non-claims

This record does not establish:

- an Android sandbox escape;
- an Android vulnerability;
- kernel compromise;
- SELinux bypass;
- unauthorized privilege escalation;
- access to protected data;
- a zero-precondition escape;
- that `rish` itself is evidence of an exploit.

The delegated condition intentionally changes execution authority to the Android shell context. The observation therefore does not distinguish intentional delegation from an unrelated mechanism beyond the measured context and workload differential.

## Provenance and limitations

- The observations were made directly on the device on 2026-09-22.
- The delegated and ordinary conditions were run as separate commands.
- The ordinary-app identity was directly observed before the workload invocation.
- The first ordinary-app collection attempt is explicitly discarded because its output path was not writable.
- No protected-data access or exploit attempt was performed.
- This record is an observation record, not an independent security certification.
