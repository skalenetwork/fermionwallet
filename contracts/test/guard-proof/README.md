# Formal verification of the Guard and the pre-approval engine

Eighteen properties of `src/FermionGuard.sol` and `src/PreApprovalEngine.sol` are proven by symbolic execution. This is a proof about **parts** of these contracts, not all of them, and the parts are named below.

What is proven with **every argument symbolic** — caller, timestamp, calldata, stored state alike, so the property holds for all inputs and not for sampled ones: the escape-hatch decision; the selector deny-list and permit-list; pause, unpause and their cooldown; the emergency de-guard and both Guard time locks; the whole pre-approval validity and revocation lifecycle; and `_consumeMatching` — exact field matching, the window boundaries, at-most-once consumption, the Tier-1 pin, Tier-2 FIFO order and the queue never growing.

What is proven only over a **narrowed** input space, each narrowing named in the lemma that makes it:

- `checkTransaction`'s **refusing** direction is proven for a symbolic target, value, timestamp, selector and three calldata shapes, but only for plain `CALL`s; its **succeeding** direction is proven only for a concrete target and payload, with the validity window and the timestamp symbolic (a fully symbolic approval record makes it diverge).
- The Safe's `getTransactionHash` is collapsed to a constant.
- Authorization and both signature schemes are replaced by permissive mocks.

What is **not proven here at all**: `_checkBatchLegs` and `MAX_BATCH_LEGS`; `_dispatch`'s choice of class; and everything behind `PreApprovalEngine._create`, which the harness cannot reach — the `MAX_COMMITMENT_QUEUE` cap, `_compactDead`, `MIN_WINDOW`, the ADMIN lead time and `TxHashAlreadyPinned`. One lemma was abandoned in its original form for non-termination and restated more narrowly; see `check_deadIsNeverValid`. The Assumptions section below is the full list, and it is the authority — not this summary.

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
| 5 | `validatePreApproval`, `revokePreApproval` | An approval is valid exactly when it exists, is unspent, unrevoked, inside its window and its key is usable; consumable and dead never overlap; **dead is monotone in time** — an approval the engine calls dead at `t1` is never valid at any later `t2` — so pruning a dead queue entry can never discard a usable approval. Revocation is allowed exactly for the Safe, the key's Administrator, or any single owner except against an ADMIN approval, and never for an unknown id. |
| 6 | `_consumeMatching` | **Exact field matching**: a pinned approval is spent exactly when it is live and token, recipient and amount all match the transaction — and the **validity window is proven at both boundaries** (`validFrom`, `validTo` and the timestamp are independently symbolic). **At most once**: whichever tier it was reached on, a second consumption always fails and `used` never clears. **The Tier-1 pin is authoritative and hash-specific**: with two live, field-identical approvals pinned at different hashes and both also queued, consumption spends the one pinned at *this* hash. **Tier 2 is FIFO**: with three identical-commitment approvals queued, consumption takes the first *live* one in queue order — never a later one, never a dead one — and **never leaves the queue longer than it found it**. |
| 7 | `requestUnpauseSafe`, `requestEmergencyDeGuard` | Both Guard time locks are armed from the present, so re-requesting can only move a deadline later: **a time lock never shortens**. |
| 8 | `checkTransaction` | The **gas-refund ban is step 0 and unconditional** — a non-zero `gasPrice` is refused with exactly `GasRefundForbidden`, for every target, value, operation and payload, the escape hatch included, so no owner safety call can be turned into a token drain. A **paused Safe** executes nothing but the escape hatch and the quantum-approved `setGuard(0)`, and it is the pause that stops it (the revert selector is checked, not just the revert). Only a delegatecall to the pinned `MultiSendCallOnly` is ever admitted. **With no approval in the Guard's storage, `checkTransaction` admits exactly the escape-hatch calls and nothing else** — an iff, for a symbolic target, value, timestamp, selector, argument and three calldata shapes, plain `CALL`s only. Its success path is exercised separately, for a concrete target and payload with a symbolic window: the transaction goes through exactly while its approval is live, and executing it is the only thing that spends it. |

Path counts, run times and the mutation results are recorded in [`planted-bugs.md`](planted-bugs.md).

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
- **The batch parser and the dispatch order are not proven.** `_checkBatchLegs` walks MultiSend calldata; `MAX_BATCH_LEGS` and the per-leg target and selector rules are covered by fuzz and invariant tests (`test/properties/`) but not by a lemma here. Pulling the parser into a `checkTransaction` lemma stopped that lemma converging, so the delegatecall branch is restricted to `check_delegateCallOnlyToMultiSend`, which proves only that no other delegatecall target is admitted. `_dispatch`'s mapping from a transaction to an approval class is likewise unproven. This is the largest remaining gap.
- **One lemma was abandoned in its original form.** "Dead is monotone in time" was first written over a pair of timestamps (`dead at t1` implies `not valid at any t2 >= t1`). Halmos ran 55 minutes on it without terminating, and still over 7 minutes after its symbolic approval id was made concrete; no external solver process was ever spawned, so it was path/constraint explosion rather than a hard query. It is now stated in the equivalent single-timestamp form as `check_deadIsNeverValid`, which runs in 0.3 s; the equivalence argument is written out in that lemma's doc comment.

Tooling: Halmos 0.3.3 with Z3, over the bytecode compiled with this repository's settings (solc 0.8.37, via-IR, 200 optimizer runs). Halmos 0.3.3 needs the one-line SHA-256 fix described in the XMSS proof's README before it can run anything that hashes.

`_isDeniedSelector` was changed from `private` to `internal` so the harness can call it; nothing else in the contracts was changed for the proof, and the Guard's deployed size is unchanged. That accessor is the proof's only dependency on a source change — the `setSelectorPolicy` half of lemma 2 needs none.

## Checking that the proofs have teeth

Every lemma was run against deliberately broken copies of the contracts, and each mutation must produce a counterexample. The mutations and results are listed in [`planted-bugs.md`](planted-bugs.md).

## Running

```sh
cd contracts
forge build --ast --force   # halmos needs the AST; a plain `forge test` caches without it
halmos --match-contract GuardEquivalence --loop 32 --solver-timeout-assertion 0
halmos --match-contract RegistryEquivalence --loop 32 --solver-timeout-assertion 0
```
