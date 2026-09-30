# The key registry, proven equivalent to its specification

`RegistrySpec.sol` is an executable model of `QuantumKeyRegistry`'s state machine.
`RegistryEquivalence.t.sol` proves the contract makes exactly those transitions, for all
inputs, with [Halmos](https://github.com/a16z/halmos). `DESCRIPTION.md` is the model
rendered into English by `contracts/script/describe_spec.py` and must be regenerated
whenever the model changes.

```shell
cd contracts
forge clean && forge build --ast --force        # --ast or Halmos reports "No tests"
halmos --match-contract RegistryEquivalence --loop 32 --solver-timeout-assertion 0
python3 script/describe_spec.py > test/registry-proof/DESCRIPTION.md
python3 script/describe_spec.py --check test/registry-proof/DESCRIPTION.md
```

`check_*` functions are symbolic proofs, driven by Halmos and **not** by `forge test`; a
PASS means the property holds for all inputs. There are no `test_*` functions here, so
`forge test` correctly reports no tests in this directory.

## Read this before you trust a lemma here

Four of the six lemmas this directory started with were **vacuous**, and every one of
them passed.

`setUp()` registered no key, and each lemma built the state it wanted to test by
*calling* the registry. Since no key was ever registered, `_activeKey` reverted on entry,
so `check_requestRevocation`, `check_cancelRevocation`, `check_executeRevocation` and
`check_revocationTimelockNeverShortens` only ever explored the one branch where the Safe
has no key at all — the branch on which both the contract and the specification refuse
everything, and the equivalence is trivially true. Their path counts were 3, 4, 3 and 4.

That was not deduced from reading them. Three faults were planted in
`QuantumKeyRegistry.sol`, one at a time, and run against those lemmas:

| Planted fault | Old lemmas |
|---|---|
| the Administrator allowed to cancel a revocation (`onlySafe` dropped) | **passed** |
| the nonce bump dropped from `executeKeyRevocation` | **passed** |
| the already-enrolled check dropped from `registerQuantumKey` | **passed** |

The third is the instructive one: `check_rootIsOneShot` *looked* like it covered
double registration, but it re-registers the **same** root, so `RootAlreadyRegistered`
fires first and hides whether the enrollment check exists at all. A lemma can be
non-vacuous and still prove the wrong thing, because an earlier check masks the one under
test.

So the standard in this directory is not "the lemmas pass". It is:

1. **Never build the pre-state by calling the contract.** Every transition lemma installs
   an arbitrary state with the harness's `primeState`, constrained only by
   `RegistrySpec.invariant`, and proves the invariant again afterwards. Genesis is
   all-zero and satisfies it, so induction covers every reachable state — and priming
   reaches states no call sequence can, such as the defensive `RevocationSuperseded`
   branch, which a rotation always clears in practice.
2. **Watch what the assumptions delete.** `vm.assume(invariant(before))` is what makes
   the lemmas tractable, and it is also what silently removed the only states in which
   `_activeKey`'s status check can fire — so the `activeKeyStatus == Status.Active`
   clauses were implied by the assumption rather than proven against the contract.
   `check_activeKeyStatusIsEnforced` is the one lemma that does not assume the invariant.
   Likewise, coupling "this root is spent" to "a key is Active" in `primeState` deleted
   the post-revocation state that makes a root one-shot, and hid the deletion of
   `RootAlreadyRegistered` from every lemma.
3. **Plant the fault each new lemma was written for.** A lemma written for a fault and
   never tested against it is the thing this directory exists to prevent.
4. **Check for vacuity mechanically.** Replacing each lemma's success-branch assertion
   with `assert(false)` must make every lemma fail. If one still passes, that branch is
   unreachable and the lemma proves nothing.
5. **Distrust a non-terminating lemma before you distrust the query.** Halmos 0.3.3's
   default solver does not terminate on some queries in this repository while z3 answers
   them in milliseconds, so re-run with `--solver z3` before recording anything as
   intractable. This matters most for a mutation that appears **not** caught: a solver
   that gives up is indistinguishable from "no counterexample exists".

## What is abstracted, and why

Stated in full in the header of `RegistrySpec.sol`. In short:

- **Owner-threshold signatures and the Ledger attestation.** `PermissiveSafe` and
  `PermissiveSigner` accept everything, so the lemmas say what the registry does *given*
  that both authorizations succeeded.
- **The Guard's enrollment posture check** ([QKR-006]) lives in
  `FermionGuard._afterEnrollment`. It is not silently missing: it enters the
  specification as `canRegister`'s `postureOk` parameter, and the harness's hook refuses
  when it is false, which also proves the hook runs and is told `firstEnrollment`
  correctly.
- **XMSS verification.** A valid signature is unreachable under symbolic execution:
  Halmos models SHA-256 as an uninterpreted function even on concrete input, so the 67
  WOTS+ chain lengths stay symbolic and the chains fork (`lib/xmss-solidity/PROOF.md`
  records the solver not finishing in 40 minutes at h = 2 with a symbolic message).
- **Used-leaf accounting.** The per-root bitmap is not a `SafeState` field, so "the
  rotation leaf is unused" is outside `canRotate`.

## The two rotation lemmas are a pair, and neither means much alone

`rotateQuantumKey` needs an old-key XMSS possession proof, which the point above says
cannot be supplied symbolically. The gap is closed from both sides, and the distinction
is the entire content of the pair:

- **`check_rotate`** runs against `RegistryHarness`, whose `_verifyAndConsumeXmss` is the
  **real** one. It hands the registry a well-formed but unverifiable proof — an empty
  authentication path against a key of height ≥ 1 — so the call always reverts
  `LeafIndexMismatch`, and reaching *that* revert is exactly "every state precondition
  passed", because all of them are checked before it. This proves the gate is in the
  right place.
- **`check_rotateEffects`** runs against `StubbedProofHarness`, which overrides
  `_verifyAndConsumeXmss` to accept without verifying. It proves what happens on the
  other side of the gate: the new key Active, the old key `Rotated` rather than left
  Active or marked `Revoked`, any pending revocation cancelled, the nonce advanced, the
  new root spent.

Neither says anything about XMSS verification, and **the stub must never move into
`RegistryHarness`** — `check_rotate` earns its meaning by hitting the real revert and
would silently stop proving anything. `QuantumKeyRegistry._verifyAndConsumeXmss` is
`virtual` only to allow that seam; overriding it forfeits the one-time-leaf guarantee, and
CI fails if anything under `contracts/src/` does so.

## Mutation testing

27 faults have been planted in `QuantumKeyRegistry.sol`, one at a time, each restored with
`git checkout --` on that exact path before the next. Caught means a `check_*` lemma
produced a counterexample; a `test_*` failure does not count. The three that survived the
first sweep are recorded in the commit history along with the lemmas added for two of
them:

- the `RootAlreadyRegistered` check deleted from `registerQuantumKey` — closed by
  decoupling root-spending from key-priming, and by
  `check_rootStaysSpentAcrossRevocation`;
- the status check deleted from `_activeKey` — closed by
  `check_activeKeyStatusIsEnforced`;
- `oldKey.status = KeyStatus.Rotated` deleted from `rotateQuantumKey` — closed by
  `check_rotateEffects`, once the seam above existed. Before that it was caught by
  nothing but two single-path FFI tests, and [QKR-011] rested on them.
