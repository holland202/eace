# Changelog

## [0.2.0-dev] — under adversarial qualification

- Add full rigorous research document (`docs/EACE_RIGOROUS_RESEARCH_DOCUMENT.md`).
- Align v0.1 attack-result record with precise assessment table from experimental handoff.
- Cross-link frozen records, contract, and design reports from README.
- Implement verifier v0.2 fail-closed contract model.
- Add external test contract `EACE-P0-ANDROID-BOUND-01`.
- Add semantic verification against trusted reference artifacts.
- Add closed claim enumeration and identity verification.
- Add regression suite for all known v0.1 attacks (must fail closed).
- Add CI workflow for synthetic/regression tests.
- Document threat model, limitations, and reproducibility.

## [0.1.0] — historical baseline

- Synthetic containment model (governor, world, agent).
- Evidence ledger with hash chaining.
- Deterministic replay experiment.
- Ledger adversarial tests.
- Observer deception experiment (synthetic).
- Frozen Android P0 experimental record.
- Intentionally vulnerable verifier v0.1.
- 19-case verifier attack corpus and recorded failures.

**Note:** v0.1 verifier is retained as historical research evidence. It is known to be broken by design for the purpose of studying verifier deception.
