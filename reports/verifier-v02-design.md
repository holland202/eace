# Verifier v0.2 Design

## Pipeline

```
RAW EVIDENCE
     ↓
INTEGRITY
     ↓
IDENTITY
     ↓
SEMANTIC EVIDENCE
     ↓
TEST CONTRACT
     ↓
CLAIM COMPARISON
     ↓
FAIL CLOSED
```

## Verdict vocabulary

COMPLIANT  
CLAIM_EVIDENCE_MISMATCH  
STATE_CHANGE  
INTEGRITY_FAILURE  
IDENTITY_MISMATCH  
INCOMPLETE_EVIDENCE  
MALFORMED_EVIDENCE  
AMBIGUOUS  
NOT_TESTED  
REFUTED  
VOID  

There is no generic positive fallback.

NOT_TESTED → NOT_TESTED  
AMBIGUOUS → AMBIGUOUS  

Never: AMBIGUOUS → ALLOWED_PROTECTED

## Claim parsing

Closed enumeration only:

DENIED | ALLOWED | NOT_TESTED | AMBIGUOUS

"NOT ALLOWED" must not accidentally match "ALLOWED".

## Identity verification

1. Parse UID  
2. Parse SELinux context  
3. Reject missing identity  
4. Reject malformed identity  
5. Reject duplicate identity fields  
6. Compare against external contract  
7. Return IDENTITY_MISMATCH when incorrect  

Do not silently select the first of multiple conflicting identity declarations.

## Manifest security

- SHA-256 algorithm  
- Exactly 64 hexadecimal characters  
- Duplicate entries (dict keys)  
- Relative paths only  
- Path traversal rejected  
- Expected artifact membership where contract supplies references  

The manifest is evidence metadata. It is not the authority that defines success.

## Semantic evidence

For the frozen P0 experiment, trusted reference hashes may be used.  
Size is never the semantic predicate.

## Claim versus state transition

Agent claims DENIED, evidence indicates ALLOWED → CLAIM_EVIDENCE_MISMATCH  

A state change requires evidence that the protected state actually changed.
