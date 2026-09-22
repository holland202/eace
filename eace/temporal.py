"""
EACE temporal / causal validity layer (EACE-SYN-ADV-002).

Motivation
----------
The provenance-forgery result established:

    content integrity  !=  provenance integrity

A hash can be mathematically valid while the run identity bound to it is
false, because the forger recomputes the hash after editing the fields.

This module tests the third property:

    provenance integrity  !=  causal validity

i.e. "these bytes are bound to this run" does not establish "this
observation actually supports the claimed state transition."

Adversary models
----------------
A1  PAYLOAD_ONLY   edits event content, cannot recompute d/h
A2  FULL_REWRITE   edits content AND recomputes the whole chain
A2P PRECOMMIT      A2, but the validator holds a chain head committed
                   before the forgery window opened

A1 is the weak adversary the chain was designed for. A2 is the adversary
the provenance forgery demonstrated actually exists. A2P is the only
configuration where an internal validator has any purchase on A2, and it
requires a commitment that left the forger's control.

Failure classes are reported separately, because they are not equally bad:

    FALSE POSITIVE  validator accepts a stream asserting something untrue
    FALSE NEGATIVE  validator accepts a stream that has erased something true

A validator that only avoids false positives by refusing everything is
vacuous, so the honest control must pass.
"""

from __future__ import annotations

import copy
import hashlib
import json

GENESIS = "0" * 64

# state vocabulary for the synthetic protected resource
UNCHANGED = "PROTECTED_UNCHANGED"
CHANGED = "PROTECTED_CHANGED"

KIND_CONTROL = "CONTROL"
KIND_ACTION = "ACTION"
KIND_OBSERVATION = "STATE_OBS"


def canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest(payload) -> str:
    return hashlib.sha256(canon(payload)).hexdigest()


def event(event_id, parent_event, tick, run_id, kind, state_before, state_after,
          action=None, observation=None, scenario="ADV-002"):
    """observation = {observer_id, observes_tick, observed_state} or None."""
    return {
        "event_id": event_id,
        "parent_event": parent_event,
        "tick": tick,
        "run_id": run_id,
        "scenario": scenario,
        "kind": kind,
        "state_before": state_before,
        "action": action,
        "state_after": state_after,
        "observation": observation,
        "d": None,
        "h": None,
    }


def _payload(ev):
    return {k: ev[k] for k in ev if k not in ("d", "h")}


def seal(events):
    """Compute d and h for the whole stream. This is what an A2 adversary
    is able to re-run after tampering; A1 is not."""
    out = []
    prev = GENESIS
    for ev in events:
        e = copy.deepcopy(ev)
        e["d"] = digest(_payload(e))
        e["h"] = hashlib.sha256((prev + e["d"]).encode("utf-8")).hexdigest()
        prev = e["h"]
        out.append(e)
    return out


def head(events):
    return events[-1]["h"] if events else GENESIS


def honest_run(run_id="RUN-ADV002"):
    """
    T0 authorized control      state unchanged
    T1 observation             confirms unchanged
    T2 containment break       state changes
    T3 observation             confirms changed
    T4 recovery/reset          state restored
    """
    evs = [
        event("E0", None, 0, run_id, KIND_CONTROL, UNCHANGED, UNCHANGED,
              action="authorized_control"),
        event("E1", "E0", 1, run_id, KIND_OBSERVATION, UNCHANGED, UNCHANGED,
              observation={"observer_id": "py", "observes_tick": 0,
                           "observed_state": UNCHANGED}),
        event("E2", "E1", 2, run_id, KIND_ACTION, UNCHANGED, CHANGED,
              action="containment_break"),
        event("E3", "E2", 3, run_id, KIND_OBSERVATION, CHANGED, CHANGED,
              observation={"observer_id": "py", "observes_tick": 2,
                           "observed_state": CHANGED}),
        event("E4", "E3", 4, run_id, KIND_CONTROL, CHANGED, UNCHANGED,
              action="recovery_reset"),
    ]
    return seal(evs)


def validate(events, precommit_head=None):
    """Returns {checks: {...}, valid: bool, reasons: [...]}"""
    r = {"checks": {}, "reasons": []}

    def fail(check, why):
        r["checks"][check] = "INVALID"
        r["reasons"].append("%s: %s" % (check, why))

    def ok(check):
        r["checks"].setdefault(check, "VALID")

    if not events:
        fail("V0_NONEMPTY", "empty event stream")
        r["valid"] = False
        return r
    ok("V0_NONEMPTY")

    # V1 CHAIN
    prev = GENESIS
    for ev in events:
        want_d = digest(_payload(ev))
        if ev.get("d") != want_d:
            fail("V1_CHAIN", "digest mismatch at %s" % ev["event_id"])
            break
        want_h = hashlib.sha256((prev + want_d).encode("utf-8")).hexdigest()
        if ev.get("h") != want_h:
            fail("V1_CHAIN", "chain link mismatch at %s" % ev["event_id"])
            break
        prev = ev["h"]
    else:
        ok("V1_CHAIN")

    # V2 DAG
    ids = [e["event_id"] for e in events]
    if len(set(ids)) != len(ids):
        fail("V2_DAG", "duplicate event_id")
    else:
        bad = False
        for i, ev in enumerate(events):
            expect_parent = None if i == 0 else events[i - 1]["event_id"]
            if ev["parent_event"] != expect_parent:
                fail("V2_DAG", "%s parent is %r, expected %r"
                     % (ev["event_id"], ev["parent_event"], expect_parent))
                bad = True
                break
        if not bad:
            ok("V2_DAG")

    # V3 MONOTONIC
    for a, b in zip(events, events[1:]):
        if b["tick"] <= a["tick"]:
            fail("V3_MONOTONIC", "tick %s -> %s not strictly increasing"
                 % (a["tick"], b["tick"]))
            break
    else:
        ok("V3_MONOTONIC")

    # V4 FRESHNESS
    last_transition_tick = None
    fresh_ok = True
    for ev in events:
        if ev["state_before"] != ev["state_after"]:
            last_transition_tick = ev["tick"]
        obs = ev.get("observation")
        if not obs:
            continue
        if obs["observes_tick"] > ev["tick"]:
            fail("V4_FRESHNESS", "%s observes future tick %s at tick %s"
                 % (ev["event_id"], obs["observes_tick"], ev["tick"]))
            fresh_ok = False
            break
        if last_transition_tick is not None and obs["observes_tick"] < last_transition_tick:
            fail("V4_FRESHNESS",
                 "%s observation is stale: observes tick %s but a transition "
                 "occurred at tick %s" % (ev["event_id"], obs["observes_tick"],
                                          last_transition_tick))
            fresh_ok = False
            break
    if fresh_ok:
        ok("V4_FRESHNESS")

    # V5 UNIQUENESS
    seen = {}
    dup = False
    for ev in events:
        obs = ev.get("observation")
        if not obs:
            continue
        key = canon(obs)
        if key in seen:
            fail("V5_UNIQUENESS", "%s reuses the observation from %s"
                 % (ev["event_id"], seen[key]))
            dup = True
            break
        seen[key] = ev["event_id"]
    if not dup:
        ok("V5_UNIQUENESS")

    # V6 STATE_CONTINUITY
    for a, b in zip(events, events[1:]):
        if b["state_before"] != a["state_after"]:
            fail("V6_STATE_CONTINUITY",
                 "%s begins in %s but %s ended in %s"
                 % (b["event_id"], b["state_before"], a["event_id"], a["state_after"]))
            break
    else:
        ok("V6_STATE_CONTINUITY")

    # V7 OBSERVATION_SUPPORT
    for ev in events:
        obs = ev.get("observation")
        if obs and obs["observed_state"] != ev["state_after"]:
            fail("V7_OBSERVATION_SUPPORT",
                 "%s records state %s but its observation reports %s"
                 % (ev["event_id"], ev["state_after"], obs["observed_state"]))
            break
    else:
        ok("V7_OBSERVATION_SUPPORT")

    # V8 PRECOMMIT
    if precommit_head is None:
        r["checks"]["V8_PRECOMMIT"] = "NOT_AVAILABLE"
        r["reasons"].append(
            "V8_PRECOMMIT: no externally committed chain head supplied; "
            "a full-rewrite adversary is unconstrained by V1")
    elif head(events) != precommit_head:
        fail("V8_PRECOMMIT", "final chain head %s does not match the "
             "externally committed head %s" % (head(events)[:12], precommit_head[:12]))
    else:
        ok("V8_PRECOMMIT")

    r["valid"] = all(v == "VALID" for k, v in r["checks"].items()
                     if v != "NOT_AVAILABLE")
    return r
