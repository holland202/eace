# Limitations

- **Synthetic environment:** the localhost synthetic world does not model real Android kernel, SELinux, or process isolation behaviour beyond the abstractions defined in code.
- **Single-device Android scope:** the P0 record is a device-specific experimental observation; it does not generalise automatically to arbitrary Android configurations or versions.
- **Lack of independent hardware observer:** all measurement paths are software-mediated.
- **Command/output attribution:** output must be attributed to the correct process/workload; the framework records this requirement but cannot fully eliminate ambiguity on a live device.
- **Delegated rish authority is intentional:** the observed capability differential is explained by intentional delegated authority (Shizuku/rish), not by a zero-precondition escape. Delegated authority ≠ sandbox escape.
- **Protected-data negative control:** `/data/system/device_policy_state.xml` was system-owned (mode 0600). Both app and shell obtained metadata but were denied content. Metadata visibility ≠ protected-data access. PROTECTED DATA ACCESS: NOT ESTABLISHED.
- **No kernel exploitation** was performed. Kernel compromise: NOT TESTED. Root escalation: NOT OBSERVED.
- **No general security claim** is made. General AI containment: NOT ESTABLISHED. Android sandbox escape: NOT ESTABLISHED. Android vulnerability: NOT ESTABLISHED.
- **Verifier v0.2** itself requires ongoing adversarial testing; qualification is not complete merely because known v0.1 attacks are rejected. Independent verification of the complete system: NOT ESTABLISHED.
- **Cryptographic integrity does not establish semantic truth.** A valid hash proves artifact integrity under the recorded serialization; it does not prove honesty of production, process identity, intended command, external-state correspondence, or causal correctness.
- **Repeatability does not establish correctness.** A system can be deterministically wrong.
- **A local experiment does not generalise** automatically to arbitrary agents or Android configurations.
- **CI** runs only the synthetic/regression suite; it does not reproduce Android device experiments.
- **Observer limitations:** failure to read `/proc` does not establish `hidepid`; failure to observe a process does not establish SELinux causality; successful observation does not automatically establish causality; `logcat` is supporting telemetry, not the authorization oracle; `payload_len > 0` is not equivalent to breach.
