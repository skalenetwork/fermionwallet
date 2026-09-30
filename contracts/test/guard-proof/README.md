# Formal verification of the Guard and the pre-approval engine

Twenty-eight lemmas over `src/FermionGuard.sol` and `src/PreApprovalEngine.sol` are proven by symbolic execution. This is a proof about **parts** of these contracts, not all of them, and the parts are named below.

What is proven with **every argument symbolic** — caller, timestamp, calldata, stored state alike, so the property holds for all inputs and not for sampled ones: the escape-hatch decision; the selector deny-list and permit-list; pause, unpause and their cooldown; the emergency de-guard and both Guard time locks; the whole pre-approval validity and revocation lifecycle; and `_consumeMatching` — exact field matching, the window boundaries, at-most-once consumption, the Tier-1 pin, Tier-2 FIFO order and the queue never growing.

`checkTransaction` is covered in both directions, but with narrowings named where they are made. Its *refusing* direction is proven for a symbolic target, value, timestamp, selector, argument and three calldata shapes; its *succeeding* direction fixes the target and the value to constants and uses empty calldata, leaving the validity window, the timestamp and the tier symbolic. Both are plain `CALL`s only, and the Safe's `getTransactionHash` is collapsed to a constant throughout. Authorization and both signature schemes are permissive mocks everywhere.

What is **not proven here at all**: `_checkBatchLegs` and `MAX_BATCH_LEGS`, which Halmos 0.3.3 cannot symbolically execute; `_dispatch`'s choice of class; and everything behind `PreApprovalEngine._create`, which the harness cannot reach — the `MAX_COMMITMENT_QUEUE` cap, `_compactDead`, `MIN_WINDOW`, the ADMIN lead time and `TxHashAlreadyPinned`. Two deliberately planted faults in exactly those places are **not** caught by any lemma here; [`planted-bugs.md`](planted-bugs.md) records them and names the tests that do catch them. The Assumptions section below is the full list, and it is the authority — not this summary.

**These lemmas require `--solver z3`.** Halmos 0.3.3 defaults to its bundled `yices-smt2`, which does not terminate on some of them. That failure mode is dangerous rather than merely slow: with `--solver-timeout-assertion 0`, a solver that never answers looks exactly like a proof still in progress, and a mutation run under it looks exactly like a mutation that was not caught.

This is the same method as [the XMSS proof](../../lib/xmss-solidity/PROOF.md), applied to a stateful contract: `GuardSpec.sol` is an executable transcription of the normative rules in [`fermionguard-module.md`](../../../fermionguard-module.md) and [`pre-approval-engine.md`](../../../pre-approval-engine.md); `GuardEquivalence.t.sol` proves the contracts agree with it with [Halmos](https://github.com/a16z/halmos).

Every lemma asserts something about the **contract's** behaviour. The specification only ever supplies the predicate the contract is compared against; no lemma is a statement about the model alone.

The registry's own state machine is proven the same way in [`../registry-proof/`](../registry-proof).

## What is proven

| Lemma | Subject | Property |
|---|---|---|
| 1 | `_isEmergencyEscapeCall` | A call escapes the Guard — no approval, no pause, no enrollment check — **exactly** for the seven owner safety calls to the Guard in their canonical 4- and 36-byte forms, and for a Safe's own `setGuard(0)` when it never enrolled or its emergency de-guard has matured. Checked for every selector, argument, value, operation and stored state, including padded calldata; no third-party call ever escapes. |
| 2 | `_isDeniedSelector`, `setSelectorPolicy` | `approve`, `transferFrom`, `increaseAllowance` and `permit` are refused for every Safe and caller, and only the Safe itself can change its own permit-list. |
| 3 | `pauseSafe`, `requestUnpauseSafe`, `unpauseSafe` | Pausing succeeds exactly for the Safe, an owner or the Administrator, with the cooldown applying only to the single-key actors; a re-pause never cancels a pending unpause; unpausing needs the Safe and the matured admin time lock, and starts the cooldown from now. |
| 4 | `requestEmergencyDeGuard`, `cancelEmergencyDeGuard` | Only an enrolled Safe can request, the delay runs from the present, and only the Safe itself can cancel — a stolen Administrator key cannot veto the owners' exit. |
| 5 | `validatePreApproval`, `revokePreApproval` | An approval is valid exactly when it exists, is unspent, unrevoked, inside its window and its key is usable; consumable and dead never overlap. **Dead is monotone in time**, with both verdicts taken from the engine itself: whenever `validatePreApproval` refuses an approval at `t1` for any reason other than "not yet valid", it still refuses it at every later `t2` — which is what makes pruning a dead queue entry safe. Also proven in the equivalent single-timestamp form (`check_deadIsNeverValid`). Revocation is allowed exactly for the Safe, the key's Administrator, or any single owner except against an ADMIN approval, and never for an unknown id. |
| 6 | `_consumeMatching` | **Exact field matching**: a pinned approval is spent exactly when it is live and token, recipient and amount all match the transaction — and the **validity window is proven at both boundaries** (`validFrom`, `validTo` and the timestamp are independently symbolic). **At most once**: whichever tier it was reached on, a second consumption always fails and `used` never clears. **The Tier-1 pin is authoritative and hash-specific**: with two live, field-identical approvals pinned at different hashes and both also queued, consumption spends the one pinned at *this* hash. **Tier 2 is FIFO**: with three identical-commitment approvals queued, consumption takes the first *live* one in queue order — never a later one, never a dead one — and **never leaves the queue longer than it found it**. |
| 7 | `requestUnpauseSafe`, `requestEmergencyDeGuard` | Both Guard time locks are armed from the present, so re-requesting can only move a deadline later: **a time lock never shortens**. |
| 8 | `checkTransaction` | The **gas-refund ban is step 0 and unconditional** — a non-zero `gasPrice` is refused with exactly `GasRefundForbidden`, for every target, value, operation and payload, the escape hatch included, so no owner safety call can be turned into a token drain. A **paused Safe** executes nothing but the escape hatch and the quantum-approved `setGuard(0)`, and it is the pause that stops it (the revert selector is checked, not just the revert). Only a delegatecall to the pinned `MultiSendCallOnly` is ever admitted. **With no approval in the Guard's storage, `checkTransaction` admits exactly the escape-hatch calls and nothing else** — an iff, for a symbolic target, value, timestamp, selector, argument and three calldata shapes, plain `CALL`s only. Its success path is exercised separately, and as an iff: for a fixed third-party target and value, with the validity window, the timestamp and the tier symbolic, the transaction goes through exactly while its approval is live — and executing it is the only thing that ever spends it. (A variant with the target, value and approval class symbolic too passes in isolation at 203 paths / 12.4 s, but did not reliably finish inside a whole-file run; see that lemma's doc comment.) |

Path counts, run times and the result of trying to break every one of these lemmas are recorded in [`planted-bugs.md`](planted-bugs.md).

## Assumptions and trust base

These proofs are about the Guard's **decisions and state transitions**. What is deliberately outside them:

- **Authorization is abstracted.** The Safe in the proofs answers "yes" to every ownership question and accepts every signature, so what is proven is "given the caller holds role R, the Guard decides D". That the Safe decides roles correctly is Safe's own property; that owner-threshold signatures are verified correctly is covered by the registry's integration tests against real Safe v1.3.0, v1.4.1 and v1.5.0.
- **XMSS and ECDSA verification are abstracted, and with them the whole creation path.** `_verifyAndConsumeXmss` is `internal` but not `virtual`, so the harness cannot stub it out, and a full XMSS verification (about 745k gas of hashing) cannot be carried through symbolic execution of a stateful contract. `PreApprovalEngine._create` is therefore **not yet reachable by the harness**, and these five creation-time rules are **not proven here** — they are covered by the unit and fuzz suites instead. (Making `_verifyAndConsumeXmss` `internal virtual`, exactly as `_afterEnrollment` already is for the registry harness, would bring them into reach; that is a source change and is left to a separate commit.)
  - the `MAX_COMMITMENT_QUEUE` cap itself (`CommitmentQueueFull`) and `_compactDead`;
  - the `MIN_WINDOW` minimum validity-window length;
  - the mandatory `ADMIN_TIMELOCK` lead time on ADMIN approvals;
  - the `TxHashAlreadyPinned` rule that a live or used pin is never overwritten;
  - the `NonZeroClassFields` / class-field hygiene checks.

  Lemma 6's "consumption never grows the queue" is the **reachable half** of the queue bound: it proves no consumption can push a queue over a cap, not that creation establishes one.
- **`getTransactionHash` is collapsed to a constant.** The proof Safe reports one fixed `safeTxHash`, so the `checkTransaction` lemmas prove that the Guard *uses* the hash the Safe gives it to select a pin, not that Safe's own EIP-712 hashing binds the payload.
- **The batch parser cannot be symbolically executed at all, and the dispatch order is unproven.** Bringing `Enum.Operation.DelegateCall` into scope reaches `_checkBatchLegs`, whose `abi.decode(Bytes.slice(data, 4), (bytes))` reads memory at an offset taken from the symbolic payload; Halmos 0.3.3 aborts with `NotConcreteError: symbolic memory offset`, under either solver and under every narrowing tried. So `MAX_BATCH_LEGS` and the per-leg target and selector rules rest on `test/DocExamples.t.sol`, the two Safe integration suites and `test/properties/`, not on a lemma here — see [`planted-bugs.md`](planted-bugs.md) for the fault this leaves uncaught and the exact test that catches it. The delegatecall branch is covered only by `check_delegateCallOnlyToMultiSend`, which proves no other delegatecall target is admitted. `_dispatch`'s mapping from a transaction to an approval class is likewise unproven. This is the largest remaining gap.
- **A note on the solver, because it cost hours.** "Dead is monotone in time" was written off here as non-terminating after Halmos ran 55 minutes on it without an answer. That was the bundled default solver, `yices-smt2`, not the lemma: under `--solver z3` the same property — strengthened so that *both* verdicts come from the contract — passes in 0.43 s. Nothing in Halmos's output distinguishes "this solver will never answer" from "still working", so pass `--solver z3` explicitly and treat a lemma that runs for minutes as a solver problem first.

Tooling: Halmos 0.3.3 with z3 — passed explicitly as `--solver z3`, since the bundled default does not terminate on some of these lemmas — over the bytecode compiled with this repository's settings (solc 0.8.37, via-IR, 200 optimizer runs). Halmos 0.3.3 also needs the one-line SHA-256 fix described in the XMSS proof's README before it can run anything that hashes.

`_isDeniedSelector` was changed from `private` to `internal` so the harness can call it; nothing else in the contracts was changed for the proof, and the Guard's deployed size is unchanged. That accessor is the proof's only dependency on a source change — the `setSelectorPolicy` half of lemma 2 needs none.

## Checking that the proofs have teeth

Every lemma was run against deliberately broken copies of the contracts, and each mutation must produce a counterexample. The mutations and results are listed in [`planted-bugs.md`](planted-bugs.md).

## Running

```sh
cd contracts
forge build --ast --force   # halmos needs the AST; a plain `forge test` caches without it
halmos --match-contract GuardEquivalence --loop 32 --solver z3 --solver-timeout-assertion 0
halmos --match-contract RegistryEquivalence --loop 32 --solver z3 --solver-timeout-assertion 0
```
