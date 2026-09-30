# Do these lemmas have teeth?

A lemma nobody has tried to fool is not evidence. Every lemma in [`GuardEquivalence.t.sol`](GuardEquivalence.t.sol) was run against a deliberately broken copy of the contract it is about, and had to produce a counterexample. This file records every mutation tried, including the two that **nothing here caught** — those are the most useful rows, because they mark exactly where the proof stops and something else has to take over.

Method: plant one fault, `forge build --ast`, run the lemma it should catch, then restore the file with `git checkout -- contracts/src/<file>` (by exact path — never a saved copy, which can silently re-plant a stale bug, and never a whole directory, which would clobber other work in the tree). Afterwards `git diff --exit-code -- contracts/src/FermionGuard.sol contracts/src/PreApprovalEngine.sol` is clean; those are the only two files any mutation here touches.

**All runs use `--solver z3`.** This is not cosmetic. Halmos 0.3.3 defaults to its bundled `yices-smt2`, which does not terminate on some of this file's queries — and a solver that never answers is indistinguishable from "no counterexample found", i.e. from a lemma that passes. Under the default solver, `check_deadIsMonotone` ran 55 minutes without an answer; under z3 it takes 0.43 s. Any mutation run under the default solver could therefore be recorded as "not caught" when it is caught; every row below was produced under z3.

## Caught

| # | Fault planted | File | Lemma that caught it | Counterexample in |
|---|---|---|---|---|
| 1 | `_fieldsMatch` stops comparing `amount` on a TRANSFER approval | `PreApprovalEngine.sol` | `check_consumeRequiresExactFieldMatch` | 1.6 s, 26 paths |
| 2 | `_markUsed` no longer sets `used` | `PreApprovalEngine.sol` | `check_consumedAtMostOnce` **and** `check_executionConsumesTheApproval` | 1.4 s / 0.9 s |
| 3 | `_isConsumable` uses `block.timestamp < a.validTo` instead of `<=` | `PreApprovalEngine.sol` | `check_consumeRequiresExactFieldMatch` | 2.5 s, 35 paths |
| 4 | Tier-2 queue scanned back to front instead of FIFO | `PreApprovalEngine.sol` | `check_queueIsFifoAndNeverGrows` | 19.3 s, 127 paths |
| 5 | The Tier-1 pin is never consulted; matching falls through to the queue | `PreApprovalEngine.sol` | `check_pinSelectsExactlyItsOwnApproval` | 1.6 s, 10 paths |
| 6 | `validatePreApproval` stops checking the `used` flag | `PreApprovalEngine.sol` | `check_approvalLifecycle` **and** `check_deadIsMonotone` | 0.7 s / 0.6 s |
| 7 | A single owner may revoke an ADMIN approval | `PreApprovalEngine.sol` | `check_revokeAuthorization` | 0.4 s, 21 paths |
| 8 | `_consumeMatching` returns `bytes32(0)` instead of reverting when nothing matches | `PreApprovalEngine.sol` | `check_nothingExecutesWithoutAnApproval` | 2.7 s, 101 paths |
| 9 | `revokePreApproval` drops the "does this approval exist" check | `PreApprovalEngine.sol` | `check_revokeUnknown` | 0.05 s, 3 paths |
| 10 | The gas-refund ban moves from step 0 to after the escape hatch | `FermionGuard.sol` | `check_gasRefundBanned` | 0.3 s, 25 paths |
| 11 | The Safe's pause is checked *before* the escape hatch | `FermionGuard.sol` | `check_pauseBlocksAllButDeGuard` | 0.9 s, 24 paths |
| 12 | A re-requested unpause does not re-arm the delay (it shortens it) | `FermionGuard.sol` | `check_unpauseTimelockNeverShortens` | 0.1 s, 7 paths |
| 13 | The emergency de-guard unlocks at `> executableAt` instead of `>=` | `FermionGuard.sol` | `check_escapeHatch_setGuard` | 0.2 s, 20 paths |
| 14 | `permit()` drops off the hardcoded deny-list | `FermionGuard.sol` | `check_deniedSelectors` | 0.2 s, 10 paths |
| 15 | The anti-veto pause cooldown is not enforced against single-key actors | `FermionGuard.sol` | `check_pause` | 0.2 s, 11 paths |
| 16 | Unpausing does not arm the cooldown | `FermionGuard.sol` | `check_unpause` | 0.2 s, 11 paths |
| 17 | Any delegatecall target is accepted, not only `MultiSendCallOnly` | `FermionGuard.sol` | `check_delegateCallOnlyToMultiSend` | 0.4 s, 18 paths |
| 18 | A re-requested emergency de-guard does not re-arm the delay | `FermionGuard.sol` | `check_emergencyTimelockNeverShortens` | 0.2 s, 7 paths |

Row 2 is the one that matters most for trusting the rest. `check_executionConsumesTheApproval` drives `checkTransaction` all the way to a *successful* return; if that success path were unreachable — the classic way a symbolic lemma goes quietly vacuous — deleting `a.used = true` could not possibly break it. It breaks it.

Row 8 is the same test for the headline lemma: `check_nothingExecutesWithoutAnApproval` claims the Guard admits **exactly** the escape hatch when nothing is approved, and the mutation that turns "no matching approval" from a revert into a silent pass is the fault it exists to catch.

## Not caught — and what stands behind those lines instead

| # | Fault planted | File | Result |
|---|---|---|---|
| 19 | `_checkBatchLegs` drops the `legs > MAX_BATCH_LEGS` cap entirely | `FermionGuard.sol` | **Not caught.** |
| 20 | `_create` drops the `q.length() >= MAX_COMMITMENT_QUEUE` cap | `PreApprovalEngine.sol` | **Not caught.** |

Both were run against the lemmas that could conceivably reach the mutated line, and every one still passed. For 19 that is `check_delegateCallOnlyToMultiSend` (6 paths), `check_gasRefundBanned` (10), `check_pauseBlocksAllButDeGuard` (20) and `check_nothingExecutesWithoutAnApproval` (68) — 4 passed in 2.7 s. For 20 it is `check_consumeRequiresExactFieldMatch` (25), `check_consumedAtMostOnce` (13), `check_pinSelectsExactlyItsOwnApproval` (8), `check_queueIsFifoAndNeverGrows` (98) and `check_nothingExecutesWithoutAnApproval` (68) — 5 passed in 15.4 s. The remaining lemmas cannot reach either site by construction: `_checkBatchLegs` is called only from `_dispatch`'s `DelegateCall` branch, which requires `to == MULTISEND_CALL_ONLY`, and no lemma in the file sends a delegatecall to that address with well-formed `multiSend(bytes)` calldata; `_create` is `private` and reachable only through the three external `create*PreApproval` entry points, which no lemma calls.

These are not oversights, and the reasons are different in each case.

**19 — the batch parser is beyond Halmos, not merely unproven.** Bringing `Enum.Operation.DelegateCall` into scope in `check_nothingExecutesWithoutAnApproval` reaches `_checkBatchLegs`, whose `abi.decode(Bytes.slice(data, 4), (bytes))` reads memory at an offset taken from the symbolic payload. Halmos 0.3.3 aborts there, under both solvers, with

```
Encountered NotConcreteError: symbolic memory offset
```

which is a tool limitation rather than a solver or budget problem: no narrowing of the timestamps, the target or the approval record changes it. What guards that cap instead is concrete:

- `test/DocExamples.t.sol:365-383` — `test_Doc_BatchCapIs100Legs_AndPlusOneReverts` builds a batch of exactly `MAX_BATCH_LEGS + 1` legs and asserts the revert is `BatchTooLarge(MAX_BATCH_LEGS + 1, MAX_BATCH_LEGS)`, with the bound read from the contract rather than restated as a literal. This is the single test that fails on mutation 19.
- `test/GuardIntegration.t.sol:506-521` and `test/LegacySafeIntegration.t.sol:324` cover the neighbouring per-leg rules — `MalformedBatch` on truncated and over-long leg headers, and `ForbiddenBatchLegTarget` on a leg aimed back at the Safe — against real Safe deployments.
- `test/properties/GuardFuzz.t.sol` and `GuardInvariants.t.sol` fuzz the parser.

So the batch leg cap rests on one targeted unit test plus fuzzing. If that test is ever deleted or weakened, nothing else in the repository notices.

**20 — the creation path is not reachable by this harness.** `PreApprovalEngine._create` is `private` and runs a full XMSS verification via `_verifyAndConsumeXmss`, which is `internal` but **not** `virtual`, so the harness cannot override it the way `registry-proof`'s harness overrides `_afterEnrollment`. Every creation-time rule is therefore outside these lemmas: the `MAX_COMMITMENT_QUEUE` cap, `_compactDead`, `MIN_WINDOW`, the mandatory ADMIN lead time, and the `TxHashAlreadyPinned` replacement rule. What guards the queue cap instead:

- `test/DocExamples.t.sol:317-338` — `test_Doc_CommitmentQueueCapAndDeadEntriesDoNotCount` deploys a Guard with a small cap, fills one commitment's queue to it, and asserts the next creation reverts `CommitmentQueueFull(commitment)`, again reading the cap off the contract. This is the test that fails on mutation 20.
- `test/Deploy.t.sol:48-49,84-85,96` pin the deployed values and reject a zero cap.

The reachable half of the cap *is* proven: `check_queueIsFifoAndNeverGrows` asserts that a consumption never leaves a queue longer than it found it, so no consumption can push a queue past a cap that creation established. Making `_verifyAndConsumeXmss` `internal virtual` would bring the other half into reach; that is a source change and belongs in its own commit.

## Reproducing

```sh
cd contracts
forge build --ast --force
halmos --match-contract GuardEquivalence --loop 32 --solver z3 --solver-timeout-assertion 0
```

Then, for any row above, apply the fault, `forge build --ast`, re-run the named lemma, and restore with `git checkout -- contracts/src/<file>`.
