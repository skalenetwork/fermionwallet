#!/usr/bin/env python3
"""Model-check the device state machine, and compare the simulator with it.

`device_spec.py` is the signing device's flow written as a state machine, for the
hybrid ECDSA + ML-DSA-65 design. This script does two things with it:

  1. **Exhaustive model check.** Every reachable state is enumerated — not sampled,
     not fuzzed — over every payload a host can send, and the invariants are checked
     at each state and on each transition. The state space is small enough to explore
     completely, so a pass means the property holds for every sequence of events of
     any length.

  2. **Refinement.** `demo/ledger_sim.py` is driven through event sequences and what
     its screen shows is compared with the model's after every event.

Both parts are then checked for teeth: the invariants are re-run against deliberately
broken copies of the machine, and a check that survives its planted bug is reported as
a failure of the check, not a success of the code. A model checker nobody has tried to
fool proves nothing.

    python3 demo/ledger-proof/prove_device.py --no-sim   # model check + teeth (what CI runs)
    python3 demo/ledger-proof/prove_device.py            # + refinement against the simulator

The refinement part drives `demo/ledger_sim.py`, which still implements the XMSS
transfer approval; only its screen flow is compared. The model check needs nothing.
"""
import argparse
import itertools
import os
import random
import sys
import threading
import time
from collections import deque

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)

import device_spec as spec  # noqa: E402

EVENTS = spec.EVENTS

# ── part 1: exhaustive model check ───────────────────────────────────────────


def successors(d):
    """Every event the environment can deliver, and where it leads. The host chooses
    the payload, so `start` is offered with every one, refusable or not."""
    for p in spec.PAYLOADS:
        yield (f"start({p})", *spec.start(d, p))
    for button in EVENTS:
        yield (f"press({button})", *spec.press(d, button))
    yield ("timeout()", *spec.timeout(d))


def explore():
    """Breadth-first from the idle device. A state that already violates an invariant
    is recorded but not expanded: on the correct machine that never happens."""
    seen, edges, queue = {spec.IDLE}, [], deque([spec.IDLE])
    while queue:
        d = queue.popleft()
        for label, nxt, result in successors(d):
            edges.append((d, label, nxt, result))
            if nxt not in seen:
                seen.add(nxt)
                if not check_state_invariants(nxt):
                    queue.append(nxt)
    return seen, edges


# The device policy, restated here independently of `spec.refusal`, so a machine whose
# `start` stops consulting the policy is caught rather than trusted.
def must_refuse(p):
    return (not p.well_formed
            or (p.kind == "call" and not p.displayable)
            or (p.kind == "safetx" and not (p.refund_free and p.call_operation))
            or (p.kind == "approve" and p.unlimited))


def check_flows():
    """Facts about the screen flows themselves."""
    fails = []
    for kind, flow in spec.FLOWS.items():
        if not flow or flow[-1] != "decision" or "decision" in flow[:-1]:
            fails.append(f"F1 the {kind} flow does not end on exactly one decision screen")
    if spec.MODULE_WARNING not in spec.FLOWS["enable_module"][:-1]:
        fails.append("F2 enabling a module has no dedicated warning screen before the decision")
    return fails


def check_state_invariants(d):
    fails = []
    if d.active:
        if not 0 <= d.index <= d.decision:
            fails.append("I3 a screen index outside the flow")
        if d.seen < d.index:
            fails.append("I4 a screen is on display that was never reached")
        if must_refuse(d.payload):
            fails.append(f"I7 a payload the device must refuse is on display ({d.payload})")
        if d.out is not None:
            fails.append("I8 a signature was released while a session is still on screen")
    elif (d.index, d.seen, d.host_hash) != (-1, -1, None):
        fails.append("I5 no session, but session state left behind")
    if d.can_approve and not (d.index == d.decision and d.seen == d.decision):
        fails.append("I6 approval offered before every screen was seen")
    return fails


def check_transition_invariants(d, label, nxt, result):
    fails = []
    approved = result == "approved"
    if approved and not d.can_approve:
        fails.append("T5 an approval from a state that does not offer Approve")
    if label.startswith("start") and d.active and (nxt.payload, nxt.index, nxt.seen) != (d.payload, d.index, d.seen):
        fails.append("T7 a second session started while one was in flight")
    if label.startswith("start") and not d.active and nxt.active and must_refuse(nxt.payload):
        fails.append("R1 a refused payload was put on screen")
    if nxt.out is not None and not approved:
        fails.append(f"S1 something was signed without an approval ({label} → {result})")
    if approved:
        if nxt.out is None:
            fails.append("S2 an approval released nothing")
        elif nxt.out != spec.digest(d.payload):
            fails.append("S3 the device signed something other than the digest of the displayed fields")
        if nxt.out is not None and nxt.out == d.host_hash:
            fails.append("S4 the device signed the host's hash")
        if nxt.active:
            fails.append("S5 the session stayed open after an approval")
    return fails


def model_check(quiet=False):
    states, edges = explore()
    fails = [(None, None, f) for f in check_flows()]
    for d in states:
        fails += [(d, None, f) for f in check_state_invariants(d)]
    for d, label, nxt, result in edges:
        fails += [(d, label, f) for f in check_transition_invariants(d, label, nxt, result)]
    if not quiet:
        print(f"  {len(spec.PAYLOADS)} payloads: {len(states)} reachable states, {len(edges)} transitions, "
              f"{'no violations' if not fails else str(len(fails)) + ' VIOLATIONS'}")
        for d, label, f in fails[:10]:
            print(f"    {f}" + (f"\n      at {d}" if d else "") + (f" via {label}" if label else ""))
    return fails


# ── part 2: teeth — the check must fail on a broken machine ──────────────────

_ORIGINAL_PRESS = spec.press
_ORIGINAL_START = spec.start
_ORIGINAL_REFUSAL = spec.refusal


def _bug_approve_from_any_screen(d, button):
    """Accept Approve wherever the flow is: the host signs from screen 0, skipping the
    fields the human is supposed to read."""
    if button == "approve" and d.active:
        return spec.Device(out=spec.digest(d.payload)), "approved"
    return _ORIGINAL_PRESS(d, button)


def _bug_sign_host_hash(d, button):
    """Sign the hash the host sent instead of the digest of the displayed fields."""
    if button == "approve" and d.can_approve:
        return spec.Device(out=d.host_hash), "approved"
    return _ORIGINAL_PRESS(d, button)


def _bug_reject_signs(d, button):
    """Release a signature on rejection."""
    if button == "reject" and d.active:
        return spec.Device(out=spec.digest(d.payload)), "rejected"
    return _ORIGINAL_PRESS(d, button)


def _bug_second_session(d, p, host_hash=spec.HOST_HASH):
    """Let the host open a second signing session over the first."""
    if d.active and not spec.refusal(p):
        return spec.Device(payload=p, index=0, seen=0, host_hash=host_hash), "ok"
    return _ORIGINAL_START(d, p, host_hash)


def _refusal_without(rule):
    def refusal(p):
        r = _ORIGINAL_REFUSAL(p)
        return None if r == rule else r
    return refusal


def _flows_without_module_warning():
    flows = dict(spec.FLOWS)
    flows["enable_module"] = tuple(s for s in flows["enable_module"] if s != spec.MODULE_WARNING)
    return flows


PLANTED = [
    ("approve from any screen, skipping the fields", "press", _bug_approve_from_any_screen),
    ("sign the host's hash instead of the displayed fields", "press", _bug_sign_host_hash),
    ("release a signature on rejection", "press", _bug_reject_signs),
    ("start a second session over the first", "start", _bug_second_session),
    ("accept a SafeTx that pays a gas refund", "refusal", _refusal_without("Gas refunds are refused")),
    ("accept a delegatecall SafeTx", "refusal", _refusal_without("Delegatecall is refused")),
    ("accept a call the device cannot display", "refusal", _refusal_without("Cannot display this call")),
    ("accept an unlimited approval", "refusal", _refusal_without("Unlimited approvals are refused")),
    ("accept a malformed payload", "refusal", _refusal_without("Payload rejected")),
    ("enable a module without the dedicated warning screen", "FLOWS", _flows_without_module_warning()),
]


def teeth():
    """Every planted bug must be caught. One that survives means the check is vacuous."""
    survived = []
    for name, target, fn in PLANTED:
        original = getattr(spec, target)
        setattr(spec, target, fn)
        try:
            fails = model_check(quiet=True)
        finally:
            setattr(spec, target, original)
        kinds = sorted({f.split(" ", 1)[0] for _, _, f in fails})
        mark = "caught" if fails else "SURVIVED"
        print(f"  {mark:9} {name}" + (f" ({len(fails)} violations: {', '.join(kinds)})" if fails else ""))
        if not fails:
            survived.append(name)
    return survived


# ── part 3: refinement — the simulator must follow the specification ─────────

# The simulator implements one flow, the eight-screen transfer approval.
SIM_PAYLOAD = spec.Payload("transfer")
DECISION = len(spec.FLOWS["transfer"]) - 1


def _payload():
    """A well-formed transfer approval: what the host sends for a normal signing."""
    return {
        "payload": {
            "safe": "0x" + "11" * 20, "approvalClass": 0, "token": "0x" + "22" * 20,
            "recipient": "0x" + "33" * 20, "amount": 10 ** 18, "target": "0x" + "00" * 20,
            "value": 0, "dataHash": "0x" + "00" * 32, "validFrom": 1_700_000_000,
            "validTo": 1_700_003_600, "nonce": "0x" + "ab" * 32,
            "quantumKeyId": "0x" + "cd" * 32, "policyHash": "0x" + "ef" * 32,
            "txHash": "0x" + "00" * 32,
        },
        "domain": {"chainId": 31337, "verifyingContract": "0x" + "44" * 20},
    }


def _load_simulator(state_dir):
    """Import the simulator with its device state redirected to a scratch file, so a
    proof run can never move the counter of a running demo."""
    os.environ.setdefault("CONTRACTS_DIR", os.path.join(REPO, "contracts"))
    sys.path.insert(0, os.path.join(REPO, "demo"))
    import ledger_sim as sim  # noqa: PLC0415  (imported late: it builds a key at import)

    os.makedirs(state_dir, exist_ok=True)
    sim.STATE_DIR = state_dir
    sim.DEVICE_STATE = os.path.join(state_dir, "ledger-device.json")
    sim.IDLE_TIMEOUT_S = 0.4  # the 60 s decision timeout, scaled so a proof run can reach it
    sim.SESSION_CAP_S = 3.0
    return sim


class SimSession:
    """One signing session on the simulator, driven from outside like the UI does."""

    def __init__(self, sim):
        self.sim = sim
        self.result = None
        self.error = None
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        try:
            self.result = self.sim.sign_preapproval({"slot": self.sim.SLOT,
                                                     "rootPrefix": self.sim.ROOT[:18],
                                                     **_payload()})
        except Exception as e:  # noqa: BLE001 — the refinement check compares failures too
            self.error = e

    def start(self):
        self.thread.start()
        self._await_screen()

    def _await_screen(self, timeout=5.0):
        """The session appears on screen asynchronously; wait for it rather than sleeping."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.sim.screen_view()["active"] or not self.thread.is_alive():
                return
            time.sleep(0.005)

    def observe(self):
        v = self.sim.screen_view()
        if not v["active"]:
            return {"active": False}
        return {"active": True, "index": v["index"], "canApprove": v["canApprove"]}

    def finish(self, timeout=20.0):
        self.thread.join(timeout)
        return self.result, self.error


def settle(session, want, timeout=8.0):
    """Wait for the simulator to catch up, then report what it shows.

    The specification treats a decision as one atomic step; the simulator takes a few
    internal steps to get there — a press sets an event, a background thread closes the
    session, and an approval computes two signatures before the counter is readable. So
    the comparison is stuttering refinement: the simulator may pass through states the
    model does not name, but it must *converge* on the model's state within a bounded
    time. This waits for that convergence and returns whatever it finds when the wait
    ends, so a genuine disagreement still fails — it is not asserted away, only given
    time to appear.
    """
    deadline = time.monotonic() + timeout
    got = session.observe()
    while got != want and time.monotonic() < deadline:
        time.sleep(0.005)
        got = session.observe()
    return got


def model_observe(d):
    """The model's state, projected onto what the device screen actually shows."""
    if not d.active:
        return {"active": False}
    return {"active": True, "index": d.index, "canApprove": d.can_approve}


def sequences(depth, rng):
    """What to drive both machines through.

    Exhaustive short sequences alone never reach an approval — the decision screen is
    seven `next` presses away, so the shortest approving sequence is eight events and
    4^8 is too many to enumerate. So: every sequence up to `depth`, plus the paths that
    actually matter written out by hand, plus random ones weighted towards `next` so the
    fuzzer spends its time in the part of the flow where a signature can happen.
    """
    walk = ("next",) * DECISION
    for length in range(1, depth + 1):
        yield from itertools.product(EVENTS, repeat=length)

    yield walk + ("approve",)                      # the normal signing path
    yield walk + ("prev", "approve")               # backing off the decision screen: refused
    yield walk + ("prev", "next", "approve")       # …and returning to it: allowed
    yield walk + ("reject",)                       # rejection at the decision screen
    yield walk[:3] + ("reject",)                   # rejection mid-flow
    yield walk + ("approve", "next")               # a press after the session closed
    yield walk + ("approve", "approve")            # a second approval on a dead session
    yield ("prev",) * 3 + walk + ("approve",)      # `prev` at screen 0 is a no-op
    yield walk + ("prev",) * 9 + ("next",) * 9 + ("approve",)  # clamping at both ends

    for _ in range(40):
        n = rng.randrange(1, 14)
        yield tuple(rng.choices(EVENTS, weights=(8, 2, 1, 1), k=n))


def refine(depth, state_dir, rng):
    """Drive both machines through the sequences above and compare after every event."""
    sim = _load_simulator(state_dir)
    mismatches, runs, approvals = [], 0, 0

    for sequence in sequences(depth, rng):
        # A fresh simulator state for every sequence: it still keeps an XMSS counter,
        # which the flow comparison does not look at.
        if os.path.exists(sim.DEVICE_STATE):
            os.unlink(sim.DEVICE_STATE)
        session = SimSession(sim)
        session.start()
        model, _ = spec.start(spec.IDLE, SIM_PAYLOAD)
        runs += 1

        want = model_observe(model)
        got = settle(session, want)
        if got != want:
            mismatches.append((sequence, "start", want, got))
            session.finish()
            continue

        for i, button in enumerate(sequence):
            try:
                sim.press(button)
            except ValueError:
                pass  # a refused press changes nothing; the comparison below proves it
            model, result = spec.press(model, button)
            if result == "approved":
                approvals += 1
                session.finish()  # the signature is computed after the decision
            want = model_observe(model)
            got = settle(session, want)
            if got != want:
                mismatches.append((sequence[:i + 1], button, want, got))
                break
            if not model.active:
                break

        result, error = session.finish()
        if error is not None and not isinstance(error, ValueError):
            mismatches.append((sequence, "session", "no error", repr(error)))

    if depth:
        print(f"  {runs} sessions ({approvals} approved), sequences up to length {depth}: "
              f"{'the simulator matched the specification at every step' if not mismatches else str(len(mismatches)) + ' MISMATCHES'}")
        for seq, where, want, got in mismatches[:10]:
            print(f"    after {' → '.join(seq)} at {where}: specification {want}, simulator {got}")
    return mismatches


def refine_timeout(state_dir):
    """The one event the button sequences cannot produce: the idle timeout, which must
    end the session without a signature."""
    sim = _load_simulator(state_dir)
    if os.path.exists(sim.DEVICE_STATE):
        os.unlink(sim.DEVICE_STATE)
    session = SimSession(sim)
    session.start()
    for _ in range(DECISION):  # walk to the decision screen, then simply wait
        sim.press("next")
    result, error = session.finish()
    model, _ = spec.start(spec.IDLE, SIM_PAYLOAD)
    for _ in range(DECISION):
        model, _ = spec.press(model, "next")
    model, outcome = spec.timeout(model)

    bad = []
    if not (result and result.get("status") == "timeout"):
        bad.append(f"the simulator did not time out: {result!r} {error!r}")
    if model.out is not None:
        bad.append("the specification signed on a timeout")
    print(f"  idle timeout on the decision screen: "
          f"{'no signature' if not bad else '; '.join(bad)}")
    return bad


def refine_teeth(state_dir, rng):
    """Teeth for the refinement check: break the *simulator* and watch it get caught.

    Without this the refinement half proves only that two pieces of code agree, which is
    also what happens when the comparison is too weak to tell them apart.
    """
    sim = _load_simulator(state_dir)
    survived = []

    def scripted(_depth, _rng):
        walk = ("next",) * DECISION
        yield walk + ("approve",)
        yield walk[:2] + ("approve",)
        yield walk + ("reject",)

    original_press, original_sign = sim.press, sim.sign_preapproval

    def press_without_traversal(button):
        """Approve from wherever the flow is — the device signs what nobody read."""
        with sim.LOCK:
            s = sim.session
            if s is not None and button == "approve" and not s["done"].is_set():
                s["decision"] = "approve"
                s["done"].set()
                return
        return original_press(button)

    for name, attr, fn in (("approve without traversing the fields", "press", press_without_traversal),):
        setattr(sim, attr, fn)
        try:
            global sequences
            real_sequences, sequences = sequences, scripted
            try:
                mismatches = refine(0, state_dir, rng)
            finally:
                sequences = real_sequences
        finally:
            setattr(sim, attr, original_press if attr == "press" else original_sign)
        mark = "caught" if mismatches else "SURVIVED"
        print(f"  {mark:9} simulator that would {name}")
        if not mismatches:
            survived.append(name)
    return survived


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--depth", type=int, default=4, help="longest button sequence to compare")
    ap.add_argument("--no-sim", action="store_true", help="model check only")
    ap.add_argument("--seed", type=int, default=0, help="seed for the random sequences")
    ap.add_argument("--state-dir", default=os.path.join(REPO, "demo", "ledger-proof", ".state"))
    args = ap.parse_args()

    print("Model check — every reachable state of the device's signing flow")
    fails = model_check()

    print("\nTeeth — each planted bug must be caught")
    survived = teeth()

    mismatches, timeout_bad = [], []
    if not args.no_sim:
        print("\nRefinement — demo/ledger_sim.py against the specification")
        mismatches = refine(args.depth, args.state_dir, random.Random(args.seed))
        timeout_bad = refine_timeout(args.state_dir)
        print("\nTeeth — a broken simulator must fail the refinement check")
        sim_survived = refine_teeth(args.state_dir, random.Random(args.seed))
        survived += sim_survived

    ok = not (fails or survived or mismatches or timeout_bad)
    if not ok:
        print("\nFAILED — see above")
    elif args.no_sim:
        print("\nPROVED: every reachable state of the specification satisfies the invariants "
              "(the simulator was not checked: --no-sim)")
    else:
        print("\nPROVED: the specification holds, and the simulator refines it")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
