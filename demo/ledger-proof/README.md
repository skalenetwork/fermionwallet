# The device's signing flow, model-checked

The Ledger app decides, on its own, whether a one-time XMSS leaf is spent. Nothing
on-chain can undo that decision, and the on-chain bitmap only catches a leaf spent
*twice* — it cannot catch a leaf spent for something the human never saw. So the flow
itself is worth proving, separately from the cryptography.

- **[`device_spec.py`](./device_spec.py)** — the flow of [`ledger-xmss-app.md`](../../ledger-xmss-app.md)
  ("Flow 2 — Sign pre-approval", "Device UI acceptance criteria") written as a state
  machine. It talks to no host, no file and no clock; the leaf counter is the only state
  that outlives a session.
- **[`prove_device.py`](./prove_device.py)** — checks that machine, and checks the
  simulator against it.

```
python3 demo/ledger-proof/prove_device.py           # everything (needs Foundry's `cast`)
python3 demo/ledger-proof/prove_device.py --no-sim  # the model check alone, no dependencies
```

## What is actually proven

**Every reachable state, not a sample.** The state space is small enough to enumerate
completely, so a pass covers every sequence of events of any length — 114, 375 and 1,341
states at tree heights 1, 2 and 3, with 798, 2,625 and 9,387 transitions between them.
Fourteen invariants are checked, six about states and eight about steps. The ones worth
naming:

| | Claim |
|---|---|
| I1 / T4 | A signature is never released before the counter commit has landed in NVM. |
| T1 / T2 / T6 | The counter moves on an approval, by exactly one, and on nothing else — a rejection or a timeout consumes no leaf. |
| T5 | Approve is only ever taken from the decision screen, reached by walking every field screen. |
| T8 | A key with no leaves left cannot open a signing session at all. |
| T7 | A second session cannot start over one in flight. |

**The simulator follows it.** `demo/ledger_sim.py` is driven through 133 sessions — every
button sequence up to length 3, the paths that actually reach a signature written out by
hand, and 40 random weighted ones — and its screen, its Approve availability and its leaf
counter are compared with the model's after every single event. It matched at every step.
The comparison allows stuttering: the simulator takes a few internal steps where the
model takes one (a press sets an event, a thread closes the session, an approval computes
two signatures), so it is given bounded time to converge rather than being required to
move atomically. It is never *assumed* to converge — if it does not, the run fails and
prints the sequence that separated them.

## Why you should believe the checks

Because they were tried against machines that are wrong. A model checker nobody has
fooled proves nothing, so `prove_device.py` plants bugs in its own subject and requires
each one to be caught:

| Planted in | Bug | Caught |
|---|---|---|
| the specification | approve from any screen, skipping the fields | 350 violations |
| the specification | release the signature, commit the counter afterwards | 12 violations |
| the specification | consume a leaf on rejection | 720 violations |
| the specification | sign with an exhausted key | 10 violations |
| the specification | start a second session over the first | 535 violations |
| the simulator | approve without traversing the fields | refinement mismatch |
| the simulator | release a signature without advancing the counter | refinement mismatch |

A planted bug that survives is reported as a **failure**, of the check rather than of the
code. Two of the original mutations did survive, and both turned out to be no-ops —
`index == DECISION` already implies every field was seen, and a commit reordered *within*
one atomic transition is invisible by construction. They were replaced with mutations
that genuinely differ. That is the part of this directory that took the longest, and it
is the part that makes the rest mean anything.

## What this does not cover

- **The real app.** This proves the *simulator* refines the specification. `ledger-app/`
  is a different implementation in Rust, with its own tests under `ledger-app/test/`.
- **The cryptography.** Whether a released signature is a correct XMSS signature is the
  verifier's problem, proven separately in
  [`xmss-solidity`](https://github.com/skalenetwork/xmss-solidity)'s `PROOF.md`.
- **Anything outside one signing session on one key slot**: key generation, rotation,
  denial, attestation, and several slots interacting are all out of scope here.
- **Real time.** The 60-second decision timeout is modelled as an event that may arrive,
  not as a duration; the refinement run scales it down so it can be reached at all.
