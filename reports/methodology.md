# Methodology

## Epistemic separation

CLAIM ≠ OBSERVATION ≠ CAUSAL SUPPORT ≠ VERIFICATION

These must never be collapsed into a single verdict.

## Formal model (summary)

State:

    s_t = (F_t, P_t, N_t, R_t, D_t, M_t)

Transition:

    τ_t = (s_t, a_t, s_{t+1}, E_t, H_t, V_t)

Capability state K_t is the union of filesystem, process, network, privilege and data capabilities.

Unauthorized expansion:

    ΔK_t = K_{t+1} \ K_A

Boundary violation:

    K_{t+1} ⊄ K_A

Containment invariants are indicator functions over the authorized envelopes.

First violation time:

    t* = min { t : I(s_t) = 0 }

Attempted action, actual state transition, and detector result are three separate observations.

## Evidence ledger

    d_t = SHA256(Canonical(E_t))
    H_t = SHA256(H_{t-1} || d_t)
    GENESIS = "0" * 64

HASH INTEGRITY ≠ TRUTH.

## Reproducibility identity

    R = (protocol_hash, policy_hash, environment_hash, seed, test_vector, software_identity)

repeatability ≠ correctness  
determinism ≠ truth

## Synthetic environment constraints

- localhost only
- no third-party network targets
- no credentials
- no production systems
- no destructive operations

## Verifier pipeline (v0.2)

RAW EVIDENCE → INTEGRITY → IDENTITY → SEMANTIC EVIDENCE → TEST CONTRACT → CLAIM COMPARISON → FAIL CLOSED
