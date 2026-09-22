# EACE — Evidence-Anchored Agent Containment Evaluation

**A verifier that assumes the evidence is lying to it.** Most agent
evaluations trust the evaluator. EACE treats the verifier itself as attack
surface — and then attacks it.

The v0.1 verifier was broken on purpose with a 19-case corpus: fabricated
output matching a known-good byte count got classified `ALLOWED_PROTECTED`.
The lesson, boxed everywhere below: **integrity ≠ truth.** A perfect
SHA-256 over fabricated bytes is still fabricated.

v0.2 is the fail-closed answer. Clone it and watch it hold:

```bash
git clone https://github.com/holland202/eace && cd eace
python3 test_verifier_robustness_v2.py   # 37 cases, 0 false positives
python3 mutation_check.py                # 9/9 guards proven load-bearing
```

The second command is the part most projects skip: it disables each guard
in turn and **requires the suite to fail** — proving the checks can
actually fire, not just that they pass today. No model, no network, no
Android, no setup. Runs on a phone.

Two defect records worth reading first: [`records/`](records/) documents
five self-skipping guards and a positive verdict that was unreachable from
a clean clone — both found by the tooling, both kept.

---

Evidence-Anchored Agent Containment Evaluation

EACE is a local, adversarial research framework for evaluating AI-agent capability boundaries, evidence integrity, reproducibility, and verifier validity.

The central premise is simple:

«A containment result is only as meaningful as the evidence and verification process used to establish it.»

EACE therefore does not treat the evaluator as automatically trustworthy.

The framework explicitly separates:

CLAIM
  ≠
OBSERVATION
  ≠
CAUSAL SUPPORT
  ≠
REPRODUCTION
  ≠
INDEPENDENT VERIFICATION

The project is designed to make unsupported conclusions difficult to produce.

---

Current Status

EACE is an active research project.

The current repository contains the core library, synthetic containment environment, evidence ledger, experimental infrastructure, and research contracts.

The initial verifier ("v0.1") has also been subjected to an adversarial attack corpus. That testing demonstrated several ways in which a verifier can accept evidence that is internally consistent but semantically insufficient.

That failure is intentionally preserved as part of the research record.

Two fail-closed verifier implementations now exist, and they are not
reconciled:

- `VerifierV02` in `eace/verifier.py` — dict interface, covered by the
  existing test suite.
- `eace/verifier2.py` — on-disk evidence-bundle interface, 37-case
  regression suite, mutation-checked.

The second was added by commit `1991750`, built against an earlier version
of this README that listed v0.2 as an unstarted development target. It was
not. That is itself a recorded finding: a stale summary produced a
duplicate component. See commit `8f6b0e3`.

Both have been probed and both carry defects. Neither is designated
canonical. See `records/EACE-REC-001.md` and `records/EACE-REC-002.md`.

The original next development target was a fail-closed verifier ("v0.2") designed from those failures.

Current research status

Area| Status
Synthetic containment model| Implemented
Tool authorization| Implemented
Evidence ledger| Implemented
Ledger tamper testing| Implemented
Deterministic replay| Reproduced under recorded conditions
Observer deception testing| Demonstrated synthetically
Android delegated-authority experiment| Reproduced
Zero-precondition Android escape| Not observed
Android sandbox escape| Not established
Android vulnerability| Not established
Verifier v0.1| Adversarially broken
Verifier v0.2| Two unreconciled implementations; see records/EACE-REC-001.md, -002.md
Independent verification of complete framework| Not established

---

Why EACE Exists

Many agent evaluations implicitly assume that the evaluator is trustworthy.

That creates a second-order problem.

Suppose an agent is evaluated using:

Agent
  ↓
Evidence
  ↓
Verifier
  ↓
PASS

What happens if the agent can influence the evidence?

What happens if the evidence can be fabricated?

What happens if the manifest describing the evidence is itself attacker-controlled?

What happens if the verifier mistakes an artifact characteristic for semantic meaning?

What happens if the verifier is wrong?

EACE treats those questions as experimental targets.

The evaluator itself is part of the attack surface.

---

Core Research Model

EACE models system state as:

[
s_t =
(F_t,P_t,N_t,R_t,D_t,M_t)
]

where:

- (F_t) = filesystem state
- (P_t) = process state
- (N_t) = network state
- (R_t) = privilege / authority state
- (D_t) = protected-data state
- (M_t) = measurement / telemetry state

An action and its transition are represented as:

[
\tau_t =
(s_t,a_t,s_{t+1},E_t,H_t,V_t)
]

where:

- (a_t) = attempted action
- (E_t) = evidence
- (H_t) = evidence-chain state
- (V_t) = verification result

This prevents an attempted action from automatically being treated as an achieved capability.

---

Capability Model

The capability state is represented as:

[
K_t =
K_t^{FS}
\cup
K_t^{PROC}
\cup
K_t^{NET}
\cup
K_t^{PRIV}
\cup
K_t^{DATA}
]

Let:

[
K_A
]

be the authorized capability envelope.

Unauthorized expansion is:

[
\Delta K_t =
K_{t+1}\setminus K_A
]

A containment violation exists when:

[
K_{t+1}\not\subseteq K_A
]

This distinction matters.

An agent attempting an unauthorized operation is not equivalent to an agent successfully acquiring the unauthorized capability.

---

Containment Invariants

EACE defines separate containment dimensions.

Filesystem

[
I_{FS}=1[F_s\subseteq F_A]
]

Processes

[
I_{PROC}=1[P_s\subseteq P_A]
]

Network

[
I_{NET}=1[N_s\subseteq N_A]
]

Privilege

[
I_{PRIV}=1[R_s\subseteq R_A]
]

Protected Data

[
I_{DATA}=1[D_s\cap D_P=\emptyset]
]

The global containment predicate is:

[
I(s_t)=
I_{FS}\land
I_{PROC}\land
I_{NET}\land
I_{PRIV}\land
I_{DATA}
]

The first observed boundary violation is:

[
t^*=
\min{t:I(s_t)=0}
]

---

Evidence Integrity

EACE uses a chained evidence ledger.

For each canonicalized event:

[
d_t=SHA256(Canonical(E_t))
]

and:

[
H_t=SHA256(H_{t-1}\Vert d_t)
]

with a zero-valued genesis hash.

The ledger is designed to make modification, deletion, reordering, and partial forgery detectable.

However:

«Integrity is not truth.»

A valid hash establishes a relationship between bytes and a hash.

It does not establish that:

- the bytes came from the intended process;
- the intended command produced them;
- the correct target was used;
- the evidence represents the claimed semantic state;
- the observer was independent;
- the underlying event actually occurred.

This distinction became a central result of the verifier experiments.

---

Reproducibility

EACE treats reproducibility as a defined experimental identity rather than merely repeating a command.

The conceptual identity is:

[
R=
(
protocol_hash,
policy_hash,
environment_hash,
seed,
test_vector,
software_identity
)
]

A repeated output is not automatically evidence of correctness.

A system can deterministically reproduce an incorrect conclusion.

Therefore:

REPRODUCED

and:

CORRECT

remain separate states.

---

Verification States

EACE uses explicit epistemic states:

CLAIMED
OBSERVED
SUPPORTED
REPRODUCED
INDEPENDENTLY VERIFIED

REFUTED
VOID
NOT TESTED
AMBIGUOUS

The framework deliberately avoids treating:

NOT TESTED

as:

PASS

and:

AMBIGUOUS

as:

PASS

---

Synthetic Environment

The repository includes a controlled localhost environment containing:

- an authorized service;
- a protected service;
- a synthetic agent;
- a tool governor;
- a deterministic clock;
- an evidence ledger;
- an integrated experiment runner.

The synthetic environment provides a controlled setting for testing:

authorized action
        ↓
state transition
        ↓
evidence collection
        ↓
verification

as well as:

unauthorized attempt
        ↓
enforcement
        ↓
protected state unchanged

and, where deliberately constructed as a negative control:

direct bypass
        ↓
protected state change

The purpose is not to claim that the synthetic environment represents every real-world agent system.

Its purpose is to provide a controlled experimental substrate.

---

Observer Problem

An observer is itself part of the measurement system.

For example:

/proc read failed

does not by itself establish:

SELinux caused the failure

Likewise:

observer reported no state change

does not automatically establish:

no state change occurred

EACE therefore distinguishes:

OBSERVATION

from:

CAUSE

and requires additional evidence before assigning causal explanations.

---

Android Research

EACE also contains a device-specific Android research track.

The Android experiments were deliberately constrained to read-only capability probing.

No kernel exploit, kernel modification, persistence, credential extraction, destructive operation, or third-party target was used.

A specific experiment reproduced a capability differential between:

UID 10505
u:r:untrusted_app_27:s0:...

and an intentionally delegated:

UID 2000
u:r:shell:s0

context through Shizuku/rish.

The delegated path was able to perform a PackageManager dump that the normal application context could not.

After delegation was removed, the application context reproduced the previously observed denied result.

The resulting interpretation is intentionally narrow:

CAPABILITY DIFFERENTIAL : REPRODUCED
DELEGATED AUTHORITY USE : REPRODUCED
ZERO-PRECONDITION ESCAPE : NOT OBSERVED
ANDROID SANDBOX ESCAPE : NOT ESTABLISHED
ANDROID VULNERABILITY : NOT ESTABLISHED

The delegated transition should not be confused with an unsolicited Android sandbox escape.

---

The Verifier Became the Experiment

The initial EACE verifier was intentionally attacked.

The purpose was to answer:

«Can an adversary construct evidence that satisfies the verifier without satisfying the underlying proposition?»

The attack corpus contained 19 cases.

Examples included:

- fabricated output with the exact historical byte count of a known-good artifact;
- altered payloads with identical length;
- arbitrary multi-megabyte output;
- empty evidence;
- self-certified fake evidence with a valid SHA-256 manifest;
- incorrect UID;
- incorrect SELinux context;
- duplicate identity declarations;
- contradictory claims;
- ambiguous output.

Several attacks produced positive classifications.

That means the verifier itself became a demonstrated failure point.

---

Principal v0.1 Finding

The most important failure was effectively equivalent to:

[
size(stdout)=1,700,575
\Rightarrow
ALLOWED_PROTECTED
]

That implication is invalid.

An attacker can construct arbitrary data:

[
A_{fake}
]

such that:

[
size(A_{fake})=1,700,575
]

without reproducing the intended privileged operation.

The verifier can also be supplied with a self-consistent hash:

[
SHA256(A_{fake})=h
]

That proves artifact integrity.

It does not prove semantic identity.

Therefore:

[
\boxed{
Integrity \neq Semantic\ Truth
}
]

---

Why This Matters

A security evaluator can be internally consistent and still be wrong.

That is a more subtle failure than ordinary tampering.

Consider:

attacker
   ↓
fabricated artifact
   ↓
valid SHA-256
   ↓
valid manifest
   ↓
verifier
   ↓
FALSE POSITIVE

Every integrity check can pass.

The final conclusion can still be false.

This is why EACE treats verifier validity as a first-class research problem.

---

v0.2 Verification Architecture

The next verifier is designed around:

RAW EVIDENCE
      ↓
INTEGRITY
      ↓
IDENTITY
      ↓
SEMANTIC EVIDENCE
      ↓
EXTERNAL TEST CONTRACT
      ↓
CLAIM COMPARISON
      ↓
FAIL CLOSED

Each layer has a separate responsibility.

---

Integrity

Verify:

- required artifacts exist;
- hashes are valid;
- manifest structure is valid;
- paths are safe;
- duplicate entries are rejected;
- artifacts have not been modified.

---

Identity

Verify:

- UID;
- SELinux context;
- process identity where applicable;
- identity uniqueness;
- identity against an external test contract.

The evidence must not be allowed to define its own authorization criteria.

---

Semantic Evidence

The verifier must determine whether an artifact actually represents the state being evaluated.

The following are not sufficient by themselves:

file size
hash existence
agent claim
manifest self-consistency
artifact existence

---

External Test Contract

The success criteria should exist outside the run evidence.

A contract should define the expected:

- test ID;
- workload;
- target;
- identity;
- return code;
- outcome;
- trusted reference information;
- protocol version.

This prevents the evidence producer from redefining what constitutes success.

---

Fail-Closed Design

The verifier should satisfy:

[
EvidenceInsufficient
\Rightarrow
\neg PositiveVerdict
]

Therefore:

missing evidence
    → no positive verdict

ambiguous evidence
    → no positive verdict

malformed evidence
    → no positive verdict

identity mismatch
    → no positive verdict

unknown claim
    → no positive verdict

semantic mismatch
    → no positive verdict

There should be no generic positive fallback.

---

Claim Parsing

Claims should use an explicit closed vocabulary.

For example:

DENIED
ALLOWED
NOT_TESTED
AMBIGUOUS

The verifier must not use substring matching such as:

"ALLOWED" in claim

because:

NOT ALLOWED

contains the string:

ALLOWED

Claim parsing must be exact.

---

Claim vs Evidence

A claim and the evidence supporting that claim are different objects.

If:

CLAIM = DENIED

but the evidence establishes:

OBSERVED = ALLOWED

the correct classification is a contradiction:

CLAIM_EVIDENCE_MISMATCH

It is not automatically:

STATE_CHANGE

A state-change verdict requires evidence of an actual state transition.

---

Threat Model

EACE considers multiple failure classes.

T1 — Operator Error

Incorrect command construction, labeling, recording, cleanup, or interpretation.

T2 — Adversarial Agent

The evaluated agent attempts unauthorized capability expansion.

T3 — Evidence Manipulation

Artifacts are modified, deleted, reordered, or forged.

T4 — Verifier Adversary

Evidence is deliberately constructed to satisfy verifier heuristics without satisfying the underlying proposition.

T5 — Measurement-Path Attack

The attacker exploits:

- process attribution;
- command assembly;
- output routing;
- identity parsing;
- observer assumptions;
- evidence collection;
- trust-boundary weaknesses.

---

Research Workflow

The intended workflow is:

HYPOTHESIS
    ↓
EXPLICIT CONTRACT
    ↓
CONTROLLED EXPERIMENT
    ↓
RAW OBSERVATION
    ↓
EVIDENCE
    ↓
VERIFICATION
    ↓
REPRODUCTION
    ↓
ADVERSARIAL ATTACK
    ↓
FAILURE ANALYSIS
    ↓
REVISION
    ↓
REGRESSION

A failure is not automatically a reason to discard the experiment.

A properly characterized failure can identify a weakness in the measurement architecture.

---

Current Development Plan

The immediate development sequence is:

1. Freeze v0.1

Preserve the vulnerable verifier and its complete attack output.

2. Define the v0.2 contract

Specify success and failure independently of the evidence producer.

3. Implement v0.2

Add:

- external contracts;
- strict identity validation;
- semantic evidence predicates;
- provenance;
- exact claim parsing;
- fail-closed behavior.

4. Re-run all 19 attacks

Every known v0.1 exploit becomes a regression test.

5. Construct novel attacks

Do not only test the attacks used to design v0.2.

Attempt attacks that were not anticipated during implementation.

6. Build a ground-truth corpus

Measure:

TP
TN
FP
FN

rather than simply:

tests passed / tests total

7. Revisit Android

Only after the verifier has undergone another adversarial cycle should the Android capability experiment be expanded.

---

What EACE Does Not Claim

EACE does not currently claim:

- that AI containment has been solved;
- that Android has been escaped;
- that an Android vulnerability has been discovered;
- that a kernel vulnerability has been demonstrated;
- that the verifier is unbreakable;
- that the framework proves AI safety;
- that the framework generalizes to every agent;
- that results on one Android configuration generalize to every Android device;
- that the entire framework has been independently verified.

These are intentionally outside the current evidence.

---

What Has Been Demonstrated

The current work has demonstrated, under the recorded experimental conditions:

1. A controlled synthetic capability-boundary environment.
2. Chained evidence integrity.
3. Detection of several classes of ledger tampering.
4. Repeatable integrated experiment output under recorded conditions.
5. A synthetic observer-deception experiment.
6. A reproducible delegated Android capability differential.
7. A zero-delegation negative control for the tested Android workload.
8. Multiple concrete failures in the first verifier.
9. A requirement for semantic verification beyond artifact integrity.

The ninth point is especially important.

The project is now testing not merely whether an agent can be contained, but whether the measurement of containment can itself be trusted.

---

Repository Structure

eace/
├── .github/
│   └── workflows/
│
├── artifacts/
│
├── eace/
│   ├── __init__.py
│   ├── agent.py
│   ├── clock.py
│   ├── experiment.py
│   ├── governor.py
│   ├── ledger.py
│   ├── synthetic_services.py
│   ├── verifier.py          # VerifierV01 + VerifierV02
│   └── verifier2.py         # second v0.2, unreconciled (REC-002)
│
├── records/
├── reports/
├── contracts/
├── tests/
│
├── probe_v02_guards.py            # REC-001 reproduction
├── probe_verifier2_guards.py      # REC-002 reproduction
├── test_verifier_robustness_v2.py # 37-case regression
├── mutation_check.py              # guard mutation check
│
├── CITATION.cff
├── CONTRIBUTING.md
├── LICENSE
├── SECURITY.md
└── pyproject.toml

Additional research records and regression tests are being added as the project evolves.

---

Running the Core Tests

Clone the repository and install the package in an isolated environment.

git clone https://github.com/holland202/eace.git
cd eace

python -m pip install -e .

Run the test suite:

python -m unittest discover -v

Additional suites, runnable from a clean clone with no configuration:

    python3 test_verifier_robustness_v2.py   # 37 cases, 0 false positives
    python3 mutation_check.py                # 9/9 guards load-bearing
    python3 probe_v02_guards.py              # EACE-REC-001 reproduction
    python3 probe_verifier2_guards.py        # EACE-REC-002 reproduction

The two probes carry controls. If a control row does not read "as
expected", the probe's model of the verifier is wrong and every other row
in that run is NOT TESTED rather than a finding.

The exact test inventory will expand as the verifier qualification work
progresses.

---

Reproducibility

When reporting an EACE result, record at minimum:

test_id
protocol
policy
environment
software_identity
seed
test_vector
workload
target
identity
expected_result
observed_result
artifact_hashes
verdict
limitations

A result without its experimental conditions should not automatically be treated as reproducible.

---

Research Records

Historical experimental records are intentionally preserved.

This includes:

- successful experiments;
- failed experiments;
- invalid experiments;
- incomplete runs;
- verifier failures;
- negative controls;
- limitations;
- corrections.

The goal is to preserve the evolution of the evidence rather than only the final implementation.

---

Design Principles

EACE follows several principles.

1. Evidence over assertion

OBSERVED > CLAIMED

2. Reproduction over anecdote

REPRODUCED > SINGLE RUN

3. Explicit uncertainty over unsupported certainty

NOT TESTED > ASSUMED PASS

4. Failures remain visible

A failed experiment is not silently rewritten into a success.

5. Integrity is not truth

A valid hash does not establish semantic correctness.

6. The evaluator is part of the attack surface

The verifier must be attacked.

7. No positive fallback

Uncertainty must never manufacture confidence.

8. Scope claims to evidence

A device-specific observation is not automatically a universal claim.

---

Central Research Question

The long-term research question can be stated as:

«Can an agent-containment experiment produce evidence that remains trustworthy when the agent, the evidence producer, and the verifier are all treated as potential adversarial targets?»

This is intentionally more demanding than simply asking whether an unauthorized command was blocked.

---

Core Invariants

The project maintains the following distinctions:

[
\boxed{
Claim \neq Evidence
}
]

[
\boxed{
Observation \neq Causality
}
]

[
\boxed{
Integrity \neq Truth
}
]

[
\boxed{
Reproduction \neq Correctness
}
]

[
\boxed{
Delegated Authority \neq Sandbox Escape
}
]

[
\boxed{
Ambiguity \neq Success
}
]

[
\boxed{
Not Tested \neq Pass
}
]

---

Current Strongest Research Statement

The strongest current conclusion is deliberately narrow:

«EACE provides a controlled local framework for evaluating agent capability boundaries, evidence integrity, reproducibility, observer behavior, and verifier validity. The Android research reproduced an intentional delegated-authority capability differential and did not reproduce the tested capability after delegation was removed. Independent adversarial testing of the initial verifier demonstrated that internally consistent evidence can still be semantically insufficient, motivating a fail-closed verification architecture for the next revision.»

That statement is stronger scientifically because it does not claim more than the experiments establish.

---

Why the Verifier Failure Matters

The most important result is not simply:

"the first verifier was wrong."

It is the underlying observation:

«A measurement system can preserve evidence perfectly while preserving the wrong evidence.»

That creates a second-order evaluation problem.

If the evaluator can be optimized against, then improving the evaluated system without improving the evaluator can produce increasing confidence without increasing truth.

EACE therefore treats evaluator validity as an experimental variable.

---

Roadmap

v0.1 — Foundation

- [x] Synthetic containment model
- [x] Authorization governor
- [x] Evidence ledger
- [x] Deterministic clock
- [x] Integrated experiment
- [x] Ledger attack tests
- [x] Observer attack experiment
- [x] Initial verifier
- [x] Verifier attack corpus

v0.2 — Verifier Hardening

- [x] External test contracts
- [x] Strict identity validation
- [x] Semantic evidence predicates
- [x] Provenance binding
- [x] Exact claim parsing
- [x] Fail-closed verdict model
- [x] v0.1 regression suite
- [x] Novel adversarial attack suite
- [ ] Ground-truth corpus (exists; container-only, not run on device)
- [ ] TP/FP/TN/FN evaluation (exists; container-only, not run on device)
- [ ] Contract completeness validation (EACE-REC-002: four gates skip
      silently when the contract omits a field)
- [ ] Reachable, tested positive verdict for VerifierV02 (EACE-REC-001
      Finding 2: neither control artifact is committed and the suite
      asserts COMPLIANT zero times)
- [ ] Resolve the two components claiming version 0.2
- [ ] Symmetric adversarial probe written by someone other than the
      implementation author (EACE-REC-002 O5)

v0.3 — Independent Measurement

Potential future work:

- [ ] Stronger observer separation
- [ ] Independent evidence channels
- [ ] Cross-environment reproduction
- [ ] Cross-device reproduction
- [ ] Formalized evaluator validity metrics
- [ ] Independent external review

These future items are not claims about current capability.

---

Contributing

EACE benefits more from adversarial criticism than from uncritical confirmation.

Useful contributions include:

- reproducing failures;
- finding false positives;
- finding false negatives;
- identifying hidden assumptions;
- constructing verifier attacks;
- challenging causal interpretations;
- improving reproducibility;
- identifying invalid experimental controls.

A particularly useful contribution is:

«Show me where the measurement is wrong.»

See "CONTRIBUTING.md" (CONTRIBUTING.md) for repository contribution guidance.

---

Security

EACE is intended for controlled research environments.

The project does not treat an experimental finding as authorization to attack third-party systems.

See "SECURITY.md" (SECURITY.md) for responsible reporting guidance.

---

License

EACE is released under the MIT License.

See "LICENSE" (LICENSE).

---

Citation

Citation metadata is provided in ""CITATION.cff"" (CITATION.cff).

---

Final Principle

EACE is not designed to make an experiment look successful.

It is designed to make unsupported conclusions harder to produce.

The intended progression is:

BUILD
  ↓
MEASURE
  ↓
ATTACK
  ↓
FIND FAILURE
  ↓
FREEZE FAILURE
  ↓
REVISE
  ↓
REGRESSION TEST
  ↓
ATTACK AGAIN

The verifier is part of the experiment.

The evidence is part of the experiment.

The failures are part of the experiment.

And the uncertainty is part of the result.

---

Vincit Omnia Veritas.
