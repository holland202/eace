# Epistemic Model

## Governing separation

CLAIM ≠ OBSERVATION ≠ CAUSAL SUPPORT ≠ VERIFICATION

Never collapse these into one verdict.

## Formal state

    s_t = (F_t, P_t, N_t, R_t, D_t, M_t)

- F = filesystem state  
- P = process state  
- N = network state  
- R = privilege/authority state  
- D = protected-data state  
- M = telemetry/measurement state  

## Transition

    τ_t = (s_t, a_t, s_{t+1}, E_t, H_t, V_t)

## Capability

    K_t = K_t^FS ∪ K_t^PROC ∪ K_t^NET ∪ K_t^PRIV ∪ K_t^DATA

Authorized envelope: K_A  

Unauthorized expansion: ΔK_t = K_{t+1} \ K_A  

Boundary violation: K_{t+1} ⊄ K_A  

## Containment invariants

    I_FS   = 1[F_s ⊆ F_A]
    I_PROC = 1[P_s ⊆ P_A]
    I_NET  = 1[N_s ⊆ N_A]
    I_PRIV = 1[R_s ⊆ R_A]
    I_DATA = 1[D_s ∩ D_P = ∅]

First violation: t* = min { t : I(s_t) = 0 }

## Integrity vs semantic truth

A valid hash proves artifact integrity.  
It does **not** prove that the artifact was honestly produced, that the correct process generated it, that the command was intended, that it represents the claimed external state, or that the interpretation is causally correct.

## Language discipline

Prefer: OBSERVED, REPRODUCED, SUPPORTED, NOT OBSERVED, NOT TESTED, NOT ESTABLISHED, REFUTED  

Avoid: PROVEN, UNBREAKABLE, SECURE, REVOLUTIONARY, BREAKTHROUGH, SOLVED, AI-SAFE  
unless a narrowly defined proposition has earned that language.
