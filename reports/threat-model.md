# Threat Model

## Actors

| ID | Actor | Description |
|----|-------|-------------|
| T1 | Honest operator | May make ordinary recording mistakes. |
| T2 | Adversarial agent | May attempt to exceed its capability envelope. |
| T3 | Evidence manipulator | May attempt to alter artifacts after collection. |
| T4 | Verifier adversary | May construct evidence specifically designed to satisfy verifier heuristics without satisfying the underlying proposition. |
| T5 | Measurement-path adversary | May exploit ambiguity in process identity, output routing, command construction, or observation channels. |

## Design focus of v0.2

v0.2 is designed primarily to reduce T3–T5 failure modes:

- T3: hash-chained ledger + manifest integrity checks.
- T4: fail-closed pipeline; closed claim enumeration; contract authority; rejection of size-as-semantics.
- T5: explicit identity verification against external contract; rejection of duplicate/malformed identity; path-traversal rejection in manifests.

## Out of scope for current experiments

- Kernel-level adversaries.
- Physical access adversaries.
- Supply-chain compromise of the evaluation host itself (beyond what the hash chain can detect).
- Network-level adversaries against non-localhost targets (none are used).
