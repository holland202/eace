# EACE
## Evidence-Anchored Agent Containment Evaluation

### Rigorous Research, Experimental Record, Verifier Analysis, and Qualification Specification

**Project:** EACE  
**Full Name:** Evidence-Anchored Agent Containment Evaluation  
**Research Domain:** AI agent evaluation, containment evaluation, evidence integrity, adversarial verification, reproducibility  
**Current Phase:** Verifier adversarial qualification  
**Baseline:** EACE v0.1  
**Next Revision:** EACE v0.2  
**Primary Environment:** Local / synthetic / controlled Android experimentation  
**Network Model:** Localhost-only for synthetic experiments  
**Research Principle:** Evidence > assertion

---

# Abstract

EACE (Evidence-Anchored Agent Containment Evaluation) is a research framework for experimentally evaluating whether an agent remains within an explicitly defined capability boundary and whether the evidence used to make that determination is itself resistant to deception.

The central methodological premise is that containment evaluation is not a single binary question.

A meaningful evaluation requires separation between:

1. what an agent claims occurred;
2. what was observed;
3. what causal relationship the evidence supports;
4. whether the result can be reproduced;
5. whether an independent evaluator can verify the result.

Accordingly:

CLAIM ≠ OBSERVATION ≠ CAUSAL SUPPORT ≠ VERIFICATION

EACE contains both a synthetic containment environment and an adversarial verification layer.

The synthetic environment provides controlled authorized and protected resources. The evidence system records deterministic events using canonical serialization and a chained SHA-256 construction.

The Android experiments investigated a specific capability differential between a normal Android application process and an intentionally delegated shell context through Shizuku/rish. The experiment reproduced the delegated authority transition but did not reproduce the same capability transition after delegation was removed.

Separately, the initial EACE v0.1 verifier was deliberately attacked using 19 adversarial evidence cases. Multiple attacks caused the verifier to classify counterfeit or semantically unsupported evidence as privileged-success evidence.

This produced an important methodological result:

> **Artifact integrity is not semantic truth.**

A cryptographically valid manifest can prove that an artifact corresponds to a hash. It cannot, by itself, prove that the artifact came from the intended workload, process, authorization context, or external state.

The v0.1 verifier is therefore retained as a frozen vulnerable baseline. EACE v0.2 is specified as a fail-closed verifier using an external test contract, explicit identity validation, semantic evidence predicates, provenance requirements, exact claim parsing, and regression tests derived directly from the v0.1 attack corpus.

No claim of general AI containment, Android sandbox escape, Android vulnerability, kernel compromise, or independent verification of the complete EACE system is established by the current work.

---

For the complete formal model, experimental record, 19-case attack analysis, v0.2 specification, qualification criteria, threat model, limitations, and epistemic boundaries, see the full document in the repository source tree at `docs/EACE_RIGOROUS_RESEARCH_DOCUMENT.md` (local build). Key cross-references:

- `records/EACE-P0-ANDROID-BOUND-01.md` — frozen Android P0 record
- `records/verifier-v01-attack-results.md` — 19-case attack corpus
- `contracts/EACE-P0-ANDROID-BOUND-01.json` — external test contract
- `reports/threat-model.md` — T1–T5 threat classes
- `reports/limitations.md` — explicit scope limits
- `reports/verifier-v02-design.md` — fail-closed pipeline
- `eace/verifier.py` — VerifierV01 (vulnerable) + VerifierV02 (fail-closed)
- `tests/test_verifier_robustness.py` — permanent regression suite

**Hierarchy:** Evidence > Assertion · Reproduction > Single Run · Adversarial Failure > Happy-Path Success · Explicit Uncertainty > Unsupported Certainty

*Vincit Omnia Veritas.*
