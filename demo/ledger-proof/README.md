# The device's signing flow, model-checked

With the hybrid ECDSA + ML-DSA-65 design the device keeps no per-signature state: there
is no leaf counter to commit, exhaust or roll back. What the device still decides on its
own, and what nothing on-chain can check for it, is *what it agrees to sign*. A device
that signs a hash the host made up, signs a field nobody saw, or signs a Safe
transaction whose gas refund pays the host, has given the host a valid signature, and
the verifier will accept it. So the flow is worth proving, separately from the
cryptography.

- **[`device_spec.py`](./device_spec.py)** — the signing flow as a state machine: one
  session, six payload kinds (FermionWallet transfer, Safe transaction, plain-text
  message, contract call, ERC-20 approval, enabling a Safe module), each with its own
  screens, and the rules for which payloads the device refuses before showing anything.
  It talks to no host, no file and no clock.
- **[`prove_device.py`](./prove_device.py)** — checks that machine exhaustively, plants
  bugs in it to show the checks have teeth, and compares the simulator's screen flow
  with it.

```
python3 demo/ledger-proof/prove_device.py --no-sim  # the model check and its teeth, no dependencies (CI)
python3 demo/ledger-proof/prove_device.py           # + the simulator comparison (needs Foundry's `cast`)
```

## What is actually proven

**Every reachable state, not a sample.** The host chooses every payload, so the model
offers all 192 of them — six kinds, each with every combination of the five flags a host
controls (well-formed, displayable, refund-free, Call-not-DelegateCall, unlimited) —
together with a hash of the host's own. The state space is small enough to enumerate
completely: 1,581 reachable states and 311,457 transitions, so a pass covers every
sequence of events of any length. The claims:

| | Claim |
|---|---|
| R1 / I7 | A payload the device must refuse never reaches the screen: malformed fields, a contract call it cannot display, an unlimited approval, and a Safe transaction with a non-zero gas refund (`gasPrice`, `gasToken`, `refundReceiver`) or with `operation = DelegateCall`. The policy is restated in the checker, independently of the machine's own refusal function. |
| S3 / S4 | What is signed is the digest of the payload that was displayed, and never the hash the host sent with it (FWL-014). |
| S1 / S2 / S5 | Something is signed exactly when an approval happens, and the session closes with it. A rejection or a timeout signs nothing. |
| T5 / I6 | Approve is only ever taken from the decision screen, reached by walking every screen of that payload's flow. |
| T7 | A second session cannot start over one in flight. |
| F1 / F2 | Every flow ends on exactly one decision screen, and enabling a Safe module has a dedicated warning screen before it. |

**Why the Safe-transaction rule is in the model.** A `SafeTx` has ten fields and the host
chooses all of them. A host that shows an innocent `to`, `value` and `data` but sets a
gas price with itself as `refundReceiver` is paid by the Safe when the transaction runs;
one that sets `operation = DelegateCall` hands the transaction the Safe's own storage. A
Safe running FermionGuard also refuses both on-chain, but a Safe that merely has a
FermionWallet as one of its owners has only the device between those fields and the
signature. The refusal is the device's half of the zero-field rule the Guard already
enforces for its own approvals (`NonZeroClassFields`).

**The simulator follows the transfer flow.** `demo/ledger_sim.py` still implements the
XMSS transfer approval, so only its screen flow is compared: the screen on display and
whether Approve is offered, after every event, for the eight-screen transfer flow. The
comparison allows stuttering — the simulator takes a few internal steps where the model
takes one — so it is given bounded time to converge rather than being required to move
atomically. It is never *assumed* to converge: if it does not, the run fails and prints
the sequence that separated them.

## Why you should believe the checks

Because they were tried against machines that are wrong. A model checker nobody has
fooled proves nothing, so `prove_device.py` plants bugs in its own subject and requires
each one to be caught:

| Planted in | Bug | Caught by |
|---|---|---|
| the specification | approve from any screen, skipping the fields | T5 (1,444 violations) |
| the specification | sign the host's hash instead of the displayed fields | S3, S4 (136) |
| the specification | release a signature on rejection | S1 (1,512) |
| the specification | start a second session over the first | T7 (102,748) |
| the specification | accept a Safe transaction that pays a gas refund | I7, R1 (560) |
| the specification | accept a delegatecall Safe transaction | I7, R1 (280) |
| the specification | accept a contract call the device cannot display | I7, R1 (560) |
| the specification | accept an unlimited approval | I7, R1 (560) |
| the specification | accept a malformed payload | I7, R1 (6,720) |
| the specification | enable a module without the dedicated warning screen | F2 (1) |
| the simulator | approve without traversing the fields | refinement mismatch |

A planted bug that survives is reported as a **failure**, of the check rather than of the
code.

## What this does not cover

- **The real app.** `ledger-app/` is a separate implementation in Rust, with its own
  tests under `ledger-app/test/`. The properties of its core code are argued in
  [`ledger-xmss-app.md`](../../ledger-xmss-app.md), which still describes the XMSS build.
- **The cryptography.** Whether a released signature is a correct ML-DSA-65 signature is
  the verifier's problem, tested against NIST's ACVP vectors and an independent reference
  implementation in [`contracts/test/MLDSA65.t.sol`](../../contracts/test/MLDSA65.t.sol).
- **What a screen shows.** The model knows that a screen of each name is traversed, not
  that it renders the right bytes; ERC-7730 rendering of contract calls in particular is
  a property of the descriptors and the app.
- **Anything outside one signing session**: key derivation from the recovery phrase,
  several sessions interacting, and the APDU wire format.
- **Real time.** The decision timeout is modelled as an event that may arrive, not as a
  duration; the simulator comparison scales it down so it can be reached at all.
