#!/usr/bin/env python3
"""Model-check the device state machine, and prove the simulator refines it.

`device_spec.py` is the Ledger app's signing flow written as a state machine,
straight from ledger-xmss-app.md. This script does two things with it:

  1. **Exhaustive model check.** Every reachable state is enumerated — not sampled,
     not fuzzed — and six invariants are checked at each state and on each
     transition. The state space is small enough to explore completely, so a pass
     means the property holds for every sequence of events of any length.

  2. **Refinement.** `demo/ledger_sim.py` is driven through event sequences and its
     observable state is compared with the model's after every event. If the
     simulator ever disagrees with the specification, the run fails and prints the
     sequence that separated them.

Both parts are then checked for teeth: the invariants are re-run against deliberately
broken copies of the machine, and a check that survives its planted bug is reported as
a failure of the check, not a success of the code. A model checker nobody has tried to
fool proves nothing.

    python3 demo/ledger-proof/prove_device.py            # model check + teeth + refinement
    python3 demo/ledger-proof/prove_device.py --depth 5  # longer refinement sequences
    python3 demo/ledger-proof/prove_device.py --no-sim   # model check only, no Foundry needed

The simulator part needs `cast` (Foundry) on PATH and the xmss-solidity submodule
checked out; the model check needs neither.
"""
import argparse
import itertools
import os
import random
import sys
import threading
import time
from collections import deque
from dataclasses import replace

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)

import device_spec as spec  # noqa: E402

EVENTS = spec.EVENTS


# ── part 1: exhaustive model check ───────────────────────────────────────────


def successors(d):
    """Every event the environment can deliver, and where it leads.

    `start` is offered with both a well-formed and a malformed payload, because the
    host chooses: the specification must hold whichever it sends.
    """
    for ok in (True, False):
        yield (f"start(payload_ok={ok})", *spec.start(d, ok))
    for button in EVENTS:
        yield (f"press({button})", *spec.press(d, button))
    yield ("timeout()", *spec.timeout(d))


def explore(height):
    """Breadth-first over every reachable state from every starting leaf count.

    A state that already violates an invariant is recorded but not expanded: the
    violation is the answer, and continuing from it only produces more of the same. The
    same goes for a counter past the last leaf. On the correct machine neither happens,
    so the search is exhaustive; on a broken one this is what keeps it finite instead of
    letting a device that signs past exhaustion — or that releases signatures without
    ever committing — run away for ever.
    """
    limit = 1 << height
    seen, edges, queue = set(), [], deque()

    def expandable(d):
        return d.leaf <= limit and d.committed <= limit and d.released <= limit \
            and not check_state_invariants(d, height)

    for leaf in range(0, limit + 1):
        d = spec.Device(leaf=leaf, height=height)
        if d not in seen:
            seen.add(d)
            queue.append(d)
    while queue:
        d = queue.popleft()
        for label, nxt, result in successors(d):
            edges.append((d, label, nxt, result))
            if nxt not in seen:
                seen.add(nxt)
                if expandable(nxt):
                    queue.append(nxt)
    return seen, edges


# Each invariant is a claim from ledger-xmss-app.md, named by the sentence it encodes.
def check_state_invariants(d, height):
    fails = []
    if d.released > d.committed:
        fails.append("I1 counter-before-signature: a signature was released without a committed counter")
    if d.leaf > (1 << height):
        fails.append("I2 the counter passed the last leaf")
    if d.active and not (0 <= d.index <= spec.DECISION):
        fails.append("I3 a screen index outside the flow")
    if d.active and d.seen < d.index:
        fails.append("I4 a screen is on display that was never reached")
    if not d.active and (d.index, d.seen) != (-1, -1):
        fails.append("I5 no session, but session state left behind")
    if d.can_approve and not (d.index == spec.DECISION and d.seen == spec.DECISION):
        fails.append("I6 approval offered before every field screen was seen")
    return fails


def check_transition_invariants(d, label, nxt, result, height):
    """The properties that are about the *step*, not the state — the ones that matter."""
    fails = []
    approved = result == "approved"

    if nxt.leaf != d.leaf and not approved:
        fails.append(f"T1 the leaf counter moved on a non-approval ({label} → {result})")
    if approved and nxt.leaf != d.leaf + 1:
        fails.append("T2 an approval did not consume exactly one leaf")
    if nxt.leaf < d.leaf:
        fails.append("T3 the leaf counter went backwards")
    if nxt.released > d.released and nxt.committed <= d.committed:
        fails.append("T4 a signature was released without the counter reaching NVM first")
    if approved and not d.can_approve:
        fails.append("T5 an approval from a state that does not offer Approve")
    if result in ("rejected", "timeout") and nxt.leaf != d.leaf:
        fails.append("T6 a rejection or timeout consumed a leaf")
    if label.startswith("start") and d.active and nxt != d:
        fails.append("T7 a second session started while one was in flight")
    if label.startswith("start") and d.exhausted and nxt.active and not d.active:
        fails.append("T8 an exhausted key started a signing session")
    return fails


def model_check(height, quiet=False):
    states, edges = explore(height)
    fails = []
    for d in states:
        fails += [(d, None, f) for f in check_state_invariants(d, height)]
    for d, label, nxt, result in edges:
        fails += [(d, label, f) for f in check_transition_invariants(d, label, nxt, result, height)]
    if not quiet:
        print(f"  h={height}: {len(states)} reachable states, {len(edges)} transitions, "
              f"{'no violations' if not fails else str(len(fails)) + ' VIOLATIONS'}")
        for d, label, f in fails[:10]:
            print(f"    {f}\n      at {d}" + (f" via {label}" if label else ""))
    return fails


# ── part 2: teeth — the check must fail on a broken machine ──────────────────


def _bug_approve_from_any_screen(d, button):
    """Accept Approve wherever the flow happens to be — a "sign now" shortcut that
    skips the fields the human is supposed to read. (Approving only on the decision
    screen is not enough on its own: the screen can only be reached with `next`, which
    marks each field seen, so a mutation that merely drops the `seen` test changes
    nothing. This one lets the host sign from screen 0.)"""
    if button == "approve" and d.active:
        d2 = replace(d, leaf=d.leaf + 1, committed=d.committed + 1)
        return replace(d2, index=-1, seen=-1, released=d2.released + 1), "approved"
    return _ORIGINAL_PRESS(d, button)


def _bug_release_before_commit(d, button):
    """Send the signature out and leave the counter commit for afterwards — the classic
    stateful-signature bug. A power cut in the gap loses the increment, and the next
    session signs a different digest with the same one-time leaf."""
    if button == "approve" and d.can_approve:
        return replace(d, index=-1, seen=-1, released=d.released + 1), "approved"
    return _ORIGINAL_PRESS(d, button)


def _bug_reject_consumes_leaf(d, button):
    """Burn a leaf on rejection."""
    if button == "reject" and d.active:
        return replace(d, index=-1, seen=-1, leaf=d.leaf + 1), "rejected"
    return _ORIGINAL_PRESS(d, button)


def _bug_sign_when_exhausted(d, ok):
    """Start a session on a key with no leaves left."""
    if d.active or not ok:
        return _ORIGINAL_START(d, ok)
    return replace(d, index=0, seen=0), "ok"


def _bug_second_session(d, ok):
    """Let the host open a second signing session over the first."""
    if not ok:
        return _ORIGINAL_START(d, ok)
    return replace(d, index=0, seen=0), "ok"


_ORIGINAL_PRESS = spec.press
_ORIGINAL_START = spec.start

PLANTED = [
    ("approve from any screen, skipping the fields", "press", _bug_approve_from_any_screen),
    ("release the signature before committing the counter", "press", _bug_release_before_commit),
    ("consume a leaf on rejection", "press", _bug_reject_consumes_leaf),
    ("sign with an exhausted key", "start", _bug_sign_when_exhausted),
    ("start a second session over the first", "start", _bug_second_session),
]


def teeth(height):
    """Every planted bug must be caught. One that survives means the check is vacuous."""
    survived = []
    for name, target, fn in PLANTED:
        original = getattr(spec, target)
        setattr(spec, target, fn)
        try:
            fails = model_check(height, quiet=True)
        finally:
            setattr(spec, target, original)
        mark = "caught" if fails else "SURVIVED"
        print(f"  {mark:9} {name}" + (f" ({len(fails)} violations)" if fails else ""))
        if not fails:
            survived.append(name)
    return survived


# ── part 3: refinement — the simulator must follow the specification ─────────


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
            return {"active": False, "nextLeaf": v["nextLeaf"]}
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
        return {"active": False, "nextLeaf": d.leaf}
    return {"active": True, "index": d.index, "canApprove": d.can_approve}


def sequences(depth, rng):
    """What to drive both machines through.

    Exhaustive short sequences alone never reach an approval — the decision screen is
    seven `next` presses away, so the shortest approving sequence is eight events and
    4^8 is too many to enumerate. So: every sequence up to `depth`, plus the paths that
    actually matter written out by hand, plus random ones weighted towards `next` so the
    fuzzer spends its time in the part of the flow where a signature can happen.
    """
    walk = ("next",) * spec.DECISION
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
    height = sim.HEIGHT
    mismatches, runs, approvals = [], 0, 0

    for sequence in sequences(depth, rng):
        # A fresh key for every sequence: the point is the flow, not exhaustion,
        # and h = 4 gives only 16 leaves.
        if os.path.exists(sim.DEVICE_STATE):
            os.unlink(sim.DEVICE_STATE)
        model = spec.Device(leaf=0, height=height)
        session = SimSession(sim)
        session.start()
        model, _ = spec.start(model, True)
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
        # The counter is the claim that matters: it moved exactly when the model says.
        expected_leaf = model.leaf
        actual_leaf = sim.load_state()["slots"][str(sim.SLOT)]["next"]
        if actual_leaf != expected_leaf:
            mismatches.append((sequence, "leaf", expected_leaf, actual_leaf))

    if depth:
        print(f"  {runs} sessions ({approvals} approved), sequences up to length {depth}: "
              f"{'the simulator matched the specification at every step' if not mismatches else str(len(mismatches)) + ' MISMATCHES'}")
        for seq, where, want, got in mismatches[:10]:
            print(f"    after {' → '.join(seq)} at {where}: specification {want}, simulator {got}")
    return mismatches


def refine_timeout(state_dir):
    """The one event the button sequences cannot produce: the idle timeout, which must
    end the session without consuming a leaf."""
    sim = _load_simulator(state_dir)
    if os.path.exists(sim.DEVICE_STATE):
        os.unlink(sim.DEVICE_STATE)
    session = SimSession(sim)
    session.start()
    for _ in range(spec.DECISION):  # walk to the decision screen, then simply wait
        sim.press("next")
    result, error = session.finish()
    leaf = sim.load_state()["slots"][str(sim.SLOT)]["next"]
    model, _ = spec.start(spec.Device(leaf=0, height=sim.HEIGHT), True)
    for _ in range(spec.DECISION):
        model, _ = spec.press(model, "next")
    model, outcome = spec.timeout(model)

    bad = []
    if not (result and result.get("status") == "timeout"):
        bad.append(f"the simulator did not time out: {result!r} {error!r}")
    if leaf != model.leaf:
        bad.append(f"the timeout consumed a leaf: specification {model.leaf}, simulator {leaf}")
    print(f"  idle timeout on the decision screen: "
          f"{'no signature, no leaf consumed' if not bad else '; '.join(bad)}")
    return bad


def refine_teeth(state_dir, rng):
    """Teeth for the refinement check: break the *simulator* and watch it get caught.

    Without this the refinement half proves only that two pieces of code agree, which is
    also what happens when the comparison is too weak to tell them apart.
    """
    sim = _load_simulator(state_dir)
    survived = []

    def scripted(_depth, _rng):
        walk = ("next",) * spec.DECISION
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

    def sign_twice_on_one_leaf(req):
        """Release the signature without moving the counter: the same leaf signs again."""
        state = sim.load_state()
        out = original_sign(req)
        if out.get("status") == "approved":
            sim.commit_state(state)  # put the counter back
        return out

    for name, attr, fn in (("approve without traversing the fields", "press", press_without_traversal),
                           ("release a signature without advancing the counter", "sign_preapproval",
                            sign_twice_on_one_leaf)):
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
    fails = []
    for height in (1, 2, 3):
        fails += model_check(height)

    print("\nTeeth — each planted bug must be caught (h = 2)")
    survived = teeth(2)

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
