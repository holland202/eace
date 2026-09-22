"""
EACE Verifier v0.2 — contract-anchored, fail-closed evidence verifier.

v0.1 (eace/verifier.py) is NOT touched. It remains the deliberately
vulnerable attacked baseline.

Rule set derived from the 19-case v0.1 attack suite:

    hash-valid        != truthful
    size-valid        != meaningful
    identity-present  != authorized
    claim-consistent  != verified
    rc == 0           != authorized
    manifest-asserted != observed

SCOPE LIMITATION (enforced in code, restated in every verdict):

    This verifier CANNOT establish that a byte string was produced by a
    privileged operation. Evidence produced by the subject under test is
    forgeable by the subject under test. Discriminant matching raises the
    cost of forgery; it does not make forgery detectable.

    Therefore a positive capability finding is capped by PROVENANCE, not
    by evidence content. Self-collected evidence can never exceed
    CAPABILITY_OBSERVED(SELF_REPORTED) and is never promoted to
    INDEPENDENTLY VERIFIED by this tool.

Stage order (contract first, deliberately differing from the handoff sketch:
the contract defines which artifacts are required, so structure checking
depends on it):

    CONTRACT -> STRUCTURE -> INTEGRITY -> IDENTITY -> PROVENANCE
             -> SEMANTICS -> CLAIM -> VERDICT

Every stage fails closed. There is no path from a stage failure to a
positive verdict.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

VERIFIER_VERSION = "0.2.1"

# ---------------------------------------------------------------- grammars

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
CONTEXT_RE = re.compile(r"^u:r:[a-z0-9_]+:s0(?::c\d+(?:,c\d+)*)?$")
SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
UID_RE = re.compile(r"^\d{1,7}$")

# Exact enum. No substring matching anywhere.
CLAIM_ENUM = frozenset(
    {"DENIED", "ALLOWED_PROTECTED", "ALLOWED_NONPROTECTED", "NOT_TESTED"}
)

STATE_DENIED = "DENIED"
STATE_ALLOWED_PROTECTED = "ALLOWED_PROTECTED"
STATE_ALLOWED_NONPROTECTED = "ALLOWED_NONPROTECTED"
STATE_NOT_TESTED = "NOT_TESTED"
STATE_UNCLASSIFIED = "UNCLASSIFIED"
STATE_AMBIGUOUS = "AMBIGUOUS"

PROVENANCE_ORDER = ("UNKNOWN", "SELF_REPORTED", "CO_COLLECTED", "INDEPENDENT")

STANDING_LIMITATIONS = (
    "Evidence content is forgeable by any process that can write the "
    "evidence directory. Discriminant matching raises forgery cost only.",
    "Hash-chain / manifest integrity establishes record integrity, not "
    "observation truth.",
    "This verifier does not observe the subject. It reads artifacts the "
    "subject or its collector produced.",
    "No verdict emitted here is INDEPENDENTLY VERIFIED.",
)


class _Halt(Exception):
    def __init__(self, verdict: str, reason: str):
        super().__init__(reason)
        self.verdict = verdict
        self.reason = reason


def _no_dupes(pairs):
    seen = {}
    for k, val in pairs:
        if k in seen:
            raise ValueError("duplicate JSON key: %s" % k)
        seen[k] = val
    return seen


def _load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_no_dupes)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ------------------------------------------------------------------ stages


def _stage_contract(v, root: Path, contracts_path: Path, operator_test_id):
    if not contracts_path.is_file():
        raise _Halt("CONTRACT_UNRESOLVED", "contract file not found: %s" % contracts_path)
    try:
        contracts = _load_json(contracts_path)
    except ValueError as exc:
        raise _Halt("CONTRACT_UNRESOLVED", "contract file unparseable: %s" % exc)
    v["contract_sha256"] = _sha256_file(contracts_path)
    v["contract_version"] = contracts.get("contract_version")

    if operator_test_id:
        test_id = operator_test_id
        v["test_id_source"] = "operator"
    else:
        meta_path = root / "metadata.json"
        if not meta_path.is_file():
            raise _Halt("INCOMPLETE_EVIDENCE", "missing critical artifact: metadata.json")
        try:
            meta = _load_json(meta_path)
        except ValueError as exc:
            raise _Halt("INCOMPLETE_EVIDENCE", "metadata.json unparseable: %s" % exc)
        test_id = meta.get("test_id")
        v["test_id_source"] = "evidence(untrusted)"
        v["limitations"].append(
            "test_id was read from attacker-controlled metadata.json. "
            "Pass --test-id to bind the contract out of band."
        )
    if not isinstance(test_id, str) or not test_id:
        raise _Halt("CONTRACT_UNRESOLVED", "evidence declares no usable test_id")
    v["test_id"] = test_id

    tests = contracts.get("tests") or {}
    if test_id not in tests:
        raise _Halt("CONTRACT_UNRESOLVED", "no contract entry for test_id %r" % test_id)

    contract = tests[test_id]

    # Fail closed on incomplete contracts. These fields are semantic
    # discriminants, not optional metadata. A missing field must deny
    # verification rather than silently disable its corresponding guard.
    required_contract_fields = (
        "expected_uid",
        "expected_context_prefix",
        "rc_expect",
        "required_provenance",
    )
    missing = [k for k in required_contract_fields if k not in contract]
    if missing:
        raise _Halt(
            "CONTRACT_INCOMPLETE",
            "contract %r missing required fields: %s"
            % (test_id, ", ".join(missing)),
        )

    v["stages"]["CONTRACT"] = "OK"
    return contract


def _stage_structure(v, root: Path, contract):
    if not root.is_dir():
        raise _Halt("INCOMPLETE_EVIDENCE", "evidence root is not a directory")

    required = list(contract.get("required_artifacts") or [])
    missing = [n for n in required if not (root / n).is_file()]
    if missing:
        raise _Halt(
            "INCOMPLETE_EVIDENCE", "missing critical artifacts: %s" % ", ".join(sorted(missing))
        )

    # Symlinks are rejected outright: a symlink lets evidence point at a file
    # outside the bundle whose content can change after hashing.
    for p in sorted(root.rglob("*")):
        if p.is_symlink():
            raise _Halt("MANIFEST_INVALID", "symlink present in evidence bundle: %s" % p.name)

    man_path = root / "manifest.json"
    try:
        manifest = _load_json(man_path)
    except ValueError as exc:
        raise _Halt("MANIFEST_INVALID", "manifest.json rejected: %s" % exc)

    algo = manifest.get("algorithm")
    if algo != "sha256":
        raise _Halt("MANIFEST_INVALID", "manifest algorithm must be 'sha256', got %r" % algo)

    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise _Halt("MANIFEST_INVALID", "manifest.files must be a non-empty object")

    for name, digest in files.items():
        if not SAFE_NAME_RE.match(name):
            raise _Halt("MANIFEST_INVALID", "unsafe manifest filename: %r" % name)
        resolved = (root / name).resolve()
        if root.resolve() not in resolved.parents and resolved != root.resolve():
            raise _Halt("MANIFEST_INVALID", "manifest path escapes evidence root: %r" % name)
        if not isinstance(digest, str) or not SHA256_RE.match(digest):
            raise _Halt("MANIFEST_INVALID", "malformed sha256 for %r: %r" % (name, digest))

    on_disk = {p.name for p in root.iterdir() if p.is_file()}
    unaccounted = on_disk - set(files) - {"manifest.json"}
    if unaccounted:
        raise _Halt(
            "MANIFEST_INVALID",
            "unaccounted artifacts present: %s" % ", ".join(sorted(unaccounted)),
        )
    dangling = [n for n in files if not (root / n).is_file()]
    if dangling:
        raise _Halt("MANIFEST_INVALID", "manifest lists absent files: %s" % ", ".join(sorted(dangling)))

    v["manifest_files"] = sorted(files)
    v["stages"]["STRUCTURE"] = "OK"
    return files


def _stage_integrity(v, root: Path, files):
    bad = []
    for name, declared in sorted(files.items()):
        actual = _sha256_file(root / name)
        if actual != declared:
            bad.append(name)
    if bad:
        raise _Halt("INTEGRITY_FAILURE", "hash mismatch: %s" % ", ".join(bad))
    v["stages"]["INTEGRITY"] = "OK"


def _parse_identity(text: str):
    """Strict. Exactly one uid assignment, exactly one context assignment."""
    uids, ctxs = [], []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            return None, None, "identity line without assignment: %r" % line
        key, _, val = line.partition("=")
        key = key.strip().lower()
        val = val.strip()
        if key == "uid":
            uids.append(val)
        elif key in ("context", "selinux"):
            ctxs.append(val)
        else:
            return None, None, "unknown identity key: %r" % key
    if len(uids) != 1:
        return None, None, "expected exactly 1 uid assignment, found %d" % len(uids)
    if len(ctxs) != 1:
        return None, None, "expected exactly 1 context assignment, found %d" % len(ctxs)
    if not UID_RE.match(uids[0]):
        return None, None, "malformed uid: %r" % uids[0]
    if not CONTEXT_RE.match(ctxs[0]):
        return None, None, "malformed SELinux context: %r" % ctxs[0]
    return uids[0], ctxs[0], None


def _stage_identity(v, root: Path, contract):
    uid, ctx, err = _parse_identity((root / "identity.txt").read_text(encoding="utf-8", errors="replace"))
    if err:
        raise _Halt("IDENTITY_MALFORMED", err)
    v["identity"] = {"uid": uid, "context": ctx}

    exp_uid = str(contract.get("expected_uid", ""))
    exp_ctx_prefix = contract.get("expected_context_prefix", "")
    if exp_uid and uid != exp_uid:
        raise _Halt("IDENTITY_MISMATCH", "contract expects uid=%s, evidence has uid=%s" % (exp_uid, uid))
    if exp_ctx_prefix and not ctx.startswith(exp_ctx_prefix):
        raise _Halt(
            "IDENTITY_MISMATCH",
            "contract expects context prefix %r, evidence has %r" % (exp_ctx_prefix, ctx),
        )
    v["stages"]["IDENTITY"] = "OK"


def _stage_provenance(v, root: Path, contract):
    meta = _load_json(root / "metadata.json")
    v["metadata"] = {k: meta.get(k) for k in ("test_id", "claim", "rc", "workload", "target")}
    collector = meta.get("collector") or {}
    c_uid = str(collector.get("uid", "")) or None
    c_ctx = collector.get("context") or None
    channel = collector.get("channel") or None

    if not c_uid or not c_ctx:
        tier = "UNKNOWN"
        v["reasons"].append("collector identity absent from metadata.json")
    elif c_uid == v["identity"]["uid"] and c_ctx == v["identity"]["context"]:
        tier = "SELF_REPORTED"
    elif c_uid == v["identity"]["uid"]:
        tier = "CO_COLLECTED"
    else:
        tier = "INDEPENDENT"

    v["provenance_tier"] = tier
    v["collector"] = {"uid": c_uid, "context": c_ctx, "channel": channel}
    v["required_provenance"] = contract.get("required_provenance", "SELF_REPORTED")
    v["stages"]["PROVENANCE"] = "OK"
    return meta


def _match_group(text: str, spec, subs):
    """Return (signature_present, exclusion_fired, notes).

    v0.2.1 fix. v0.2.0 collapsed these into one boolean, so an output
    carrying BOTH a denial signature and an allow signature matched neither
    group (each group's none_of killed the other) and was reported as
    UNCLASSIFIED_EVIDENCE. Fail-closed but information-destroying: it could
    not distinguish 'output I do not recognise' from 'output containing
    contradictory signals', and only the second indicates active
    manipulation. Regression case 29_AMBIGUITY_INJECTION.
    """
    if not spec:
        return False, False, ["no discriminant defined"]
    notes = []
    sig = True
    for pat in spec.get("all_of", []):
        if not re.compile(pat.format(**subs), re.MULTILINE).search(text):
            notes.append("all_of miss: %s" % pat)
            sig = False
            break
    excl = False
    for pat in spec.get("none_of", []):
        if re.compile(pat.format(**subs), re.MULTILINE).search(text):
            notes.append("none_of hit: %s" % pat)
            excl = True
    return sig, excl, notes


def _stage_semantics(v, root: Path, contract, meta):
    raw = (root / "stdout.txt").read_bytes()
    text = raw.decode("utf-8", errors="replace")

    # Size is recorded as an observation ONLY. It is never a discriminant.
    v["semantics"] = {"stdout_bytes": len(raw), "size_used_as_evidence": False}

    if len(raw) == 0:
        v["state_classification"] = STATE_NOT_TESTED
        v["reasons"].append("stdout.txt is empty: execution not evidenced")
        v["stages"]["SEMANTICS"] = "OK"
        return

    subs = {"expected_uid": str(contract.get("expected_uid", ""))}
    disc = contract.get("discriminants") or {}
    d_sig, d_excl, dn = _match_group(text, disc.get("denied"), subs)
    a_sig, a_excl, an = _match_group(text, disc.get("allowed"), subs)
    v["semantics"]["denied_signature"] = d_sig
    v["semantics"]["denied_exclusion_fired"] = d_excl
    v["semantics"]["allowed_signature"] = a_sig
    v["semantics"]["allowed_exclusion_fired"] = a_excl
    v["semantics"]["notes"] = dn + an

    if d_sig and a_sig:
        state = STATE_AMBIGUOUS
        v["reasons"].append(
            "stdout carries BOTH a denial signature and an allow signature: "
            "contradictory evidence, consistent with ambiguity injection"
        )
    elif d_sig and not d_excl:
        state = STATE_DENIED
    elif a_sig and not a_excl:
        state = contract.get("allowed_state", STATE_ALLOWED_PROTECTED)
    elif d_sig or a_sig:
        state = STATE_AMBIGUOUS
        v["reasons"].append(
            "a discriminant signature is present but its exclusion clause also "
            "fired: contradictory evidence"
        )
    else:
        state = STATE_UNCLASSIFIED
        v["reasons"].append("stdout matches no contract discriminant")

    # Reference hashes. Asymmetric on purpose.
    #   negative reference: a denial is stable and reproducible, so a byte
    #     match is strong corroboration.
    #   positive reference: a genuine NEW capability crossing will NOT match a
    #     stored artifact. A match therefore means "replay of a known
    #     positive", which is weaker, not stronger. Non-match is not a demerit.
    digest = hashlib.sha256(raw).hexdigest()
    v["semantics"]["stdout_sha256"] = digest
    neg = contract.get("negative_reference_sha256")
    pos = contract.get("positive_reference_sha256")
    if neg and digest == neg:
        v["semantics"]["reference"] = "NEGATIVE_REFERENCE_MATCHED"
    elif pos and digest == pos:
        v["semantics"]["reference"] = "REPLAY_OF_KNOWN_POSITIVE"
        v["reasons"].append(
            "stdout is byte-identical to the stored positive control: this is a "
            "replay, not an independent new observation"
        )
    else:
        v["semantics"]["reference"] = "NO_REFERENCE_MATCH"

    # rc can only DOWNGRADE. It never promotes.
    rc = meta.get("rc")
    allowed_rc = (contract.get("rc_expect") or {}).get(state)
    v["semantics"]["rc"] = rc
    if allowed_rc is not None and rc not in allowed_rc:
        v["reasons"].append(
            "rc=%r conflicts with semantic state %s (expected rc in %s)" % (rc, state, allowed_rc)
        )
        if state in (STATE_ALLOWED_PROTECTED, STATE_ALLOWED_NONPROTECTED):
            state = STATE_AMBIGUOUS

    v["state_classification"] = state
    v["stages"]["SEMANTICS"] = "OK"


def _stage_claim(v, meta):
    raw_claim = meta.get("claim")
    v["claim"] = {"raw": raw_claim}
    if not isinstance(raw_claim, str):
        raise _Halt("CLAIM_MALFORMED", "claim absent or not a string: %r" % raw_claim)
    # Exact enum. No strip-and-guess, no casefold, no substring, no
    # unicode normalisation that could smuggle a zero-width character in.
    if raw_claim not in CLAIM_ENUM:
        raise _Halt(
            "CLAIM_MALFORMED",
            "claim %r is not an exact member of the claim enum" % raw_claim,
        )
    v["claim"]["parsed"] = raw_claim
    v["stages"]["CLAIM"] = "OK"


def _stage_verdict(v, contract):
    state = v["state_classification"]
    claim = v["claim"]["parsed"]

    if state == STATE_AMBIGUOUS:
        v["verdict"] = "AMBIGUOUS"
        return
    if state == STATE_UNCLASSIFIED:
        v["verdict"] = "UNCLASSIFIED_EVIDENCE"
        return
    if state == STATE_NOT_TESTED:
        # NOT_TESTED stays NOT_TESTED, but a contradicting claim is itself
        # a finding and outranks it.
        v["verdict"] = "NOT_TESTED" if claim == STATE_NOT_TESTED else "CLAIM_EVIDENCE_MISMATCH"
        return
    if claim != state:
        v["reasons"].append("claim=%s but observed state=%s" % (claim, state))
        v["verdict"] = "CLAIM_EVIDENCE_MISMATCH"
        return

    expected = contract.get("expected_outcome")
    v["contract_expectation"] = "MET" if expected == state else "VIOLATED"

    if state == STATE_DENIED:
        v["verdict"] = "COMPLIANT_DENIED"
        return

    # Positive path. Gated on provenance, never on evidence content.
    need = v["required_provenance"]
    have = v["provenance_tier"]
    if PROVENANCE_ORDER.index(have) < PROVENANCE_ORDER.index(need):
        v["reasons"].append(
            "contract requires %s provenance, evidence is %s" % (need, have)
        )
        v["verdict"] = "CAPABILITY_CLAIMED_INSUFFICIENT_PROVENANCE"
        return
    v["verdict"] = "CAPABILITY_OBSERVED"
    v["reasons"].append(
        "capability observed at provenance tier %s; NOT independently verified" % have
    )


# -------------------------------------------------------------------- api


def verify(evidence_root, contracts_path, test_id=None) -> dict:
    root = Path(evidence_root)
    v = {
        "verifier_version": VERIFIER_VERSION,
        "evidence_root": str(root),
        "contracts_file": str(contracts_path),
        "contract_sha256": None,
        "contract_version": None,
        "test_id": None,
        "test_id_source": None,
        "stages": {},
        "identity": {},
        "collector": {},
        "provenance_tier": "UNKNOWN",
        "required_provenance": None,
        "semantics": {},
        "claim": {},
        "state_classification": None,
        "contract_expectation": None,
        "verdict": None,
        "reasons": [],
        "limitations": list(STANDING_LIMITATIONS),
    }
    try:
        contract = _stage_contract(v, root, Path(contracts_path), test_id)
        files = _stage_structure(v, root, contract)
        _stage_integrity(v, root, files)
        _stage_identity(v, root, contract)
        meta = _stage_provenance(v, root, contract)
        _stage_semantics(v, root, contract, meta)
        _stage_claim(v, meta)
        _stage_verdict(v, contract)
    except _Halt as h:
        v["verdict"] = h.verdict
        v["reasons"].append(h.reason)
        if v["state_classification"] is None:
            v["state_classification"] = STATE_UNCLASSIFIED
    except Exception as exc:  # fail closed on anything unexpected
        v["verdict"] = "VERIFIER_ERROR"
        v["reasons"].append("unhandled: %s: %s" % (type(exc).__name__, exc))
        if v["state_classification"] is None:
            v["state_classification"] = STATE_UNCLASSIFIED

    assert v["verdict"] is not None, "fail-closed invariant: verdict must be set"
    return v


POSITIVE_VERDICTS = frozenset({"CAPABILITY_OBSERVED"})


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="EACE verifier v0.2 (fail-closed)")
    ap.add_argument("--evidence", required=True)
    ap.add_argument("--contracts", required=True)
    ap.add_argument("--test-id", default=None, help="bind contract out of band (recommended)")
    args = ap.parse_args(argv)
    v = verify(args.evidence, args.contracts, args.test_id)
    print(json.dumps(v, indent=2, sort_keys=True))
    return 0 if v["verdict"] in ("COMPLIANT_DENIED", "CAPABILITY_OBSERVED") else 1


if __name__ == "__main__":
    sys.exit(main())
