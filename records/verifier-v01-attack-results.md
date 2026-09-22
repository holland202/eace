# Historical v0.1 — Intentionally Vulnerable Baseline

**This record is immutable research evidence.**  
Do not rewrite history. The 19-case attack corpus remains part of the scientific record.

Implementation: `eace/verifier.py` (`VerifierV01`)  
Regression suite: `tests/test_verifier_robustness.py`

---

## Attack corpus (19 cases)

| ID | Name | v0.1 observed verdict | Assessment |
|----|------|-----------------------|------------|
| 01 | PRISTINE_DENIED | COMPLIANT | Expected |
| 02 | HISTORICAL_SIZE_FAKE | ALLOWED_PROTECTED | Verifier failure |
| 03 | ALTERED_PAYLOAD_SAME_SIZE | ALLOWED_PROTECTED | Verifier failure |
| 04 | 71_BYTE_OUTPUT | ALLOWED_PROTECTED | Verifier failure |
| 05 | ARBITRARY_2MB | ALLOWED_PROTECTED | Verifier failure |
| 06 | EMPTY_STDOUT | ALLOWED_PROTECTED | Verifier failure |
| 07 | MISSING_IDENTITY | INCOMPLETE_EVIDENCE | Conservative |
| 08 | MALFORMED_IDENTITY | AMBIGUOUS | Conservative |
| 09 | ALTERED_MANIFEST | INTEGRITY_FAILURE | Correct detection |
| 10 | SELF_CERTIFIED_FAKE | ALLOWED_PROTECTED | Verifier failure |
| 11 | DENIED_CLAIM_LARGE_OUTPUT | STATE_CHANGE | Semantic failure |
| 12 | ALLOWED_CLAIM_DENIED_OUTPUT | AMBIGUOUS | Conservative |
| 13 | NOT_ALLOWED_CLAIM | AMBIGUOUS | Parser weakness |
| 14 | MISSING_STDOUT | INCOMPLETE_EVIDENCE | Correct fail-closed |
| 15 | MISSING_METADATA | INCOMPLETE_EVIDENCE | Correct fail-closed |
| 16 | MISSING_MANIFEST | INCOMPLETE_EVIDENCE | Correct fail-closed |
| 17 | WRONG_UID | COMPLIANT | Verifier failure |
| 18 | BAD_CONTEXT | COMPLIANT | Verifier failure |
| 19 | DUPLICATE_IDENTITY | COMPLIANT | Verifier failure |

## Important failures (core research result)

| Attack | Effect |
|--------|--------|
| fake exact-size payload | → ALLOWED_PROTECTED |
| same-size arbitrary payload | → ALLOWED_PROTECTED |
| self-certified fake | → ALLOWED_PROTECTED |
| empty evidence | → ALLOWED_PROTECTED |
| ambiguous evidence | → ALLOWED_PROTECTED (via positive fallback) |
| wrong UID | → COMPLIANT |
| bad context | → COMPLIANT |
| duplicate identity | → COMPLIANT |
| claim/evidence conflict | → STATE_CHANGE (incorrect classification) |

## Epistemic finding: Integrity Is Not Semantic Truth

Let  

P = "protected privileged read actually occurred".

The broken verifier effectively treated  

    size(stdout) == 1_700_575  

as evidence for P.

Construct A_fake such that  

    size(A_fake) = 1_700_575  
    SHA256(A_fake) = manifest_hash  

while A_fake does not represent the required privileged read.

Therefore:

    Integrity(A_fake) = TRUE  
    SemanticEvidence(A_fake, P) = FALSE  

This is the fundamental v0.1 verifier failure.

## Regression requirement

After implementing v0.2, every known v0.1 exploit must **fail closed**.

The old attack corpus must not be deleted. It is part of the scientific record.
