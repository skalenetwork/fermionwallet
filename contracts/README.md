# FermionGuard contracts

Solidity contracts for FermionGuard. The XMSS verifier lives in its own
MIT-licensed repository, [skalenetwork/xmss-solidity](https://github.com/skalenetwork/xmss-solidity),
included here as the submodule `lib/xmss-solidity`. The deploy/demo scripts
are MIT-licensed; `FermionGuard.sol`, `QuantumKeyRegistry.sol` and
`PreApprovalEngine.sol` are LGPL-3.0-only (they build on Safe's LGPL
contracts). The XMSS verifier is a **clean-room implementation** (RFC 8391 /
NIST SP 800-208), written from the specification — no code taken from poqeth
(unlicensed) or hashsigs-solidity (AGPL).

## Contents

- `lib/xmss-solidity` (submodule) — the stateless XMSS verification library
  `XMSS.sol` (`XMSS-SHA2_*_256`: n = 32, w = 16, len = 67; tree height from
  the auth-path length, max 20), **formally verified** against RFC 8391 with
  Halmos (see its `PROOF.md`), plus its tests, reference vectors and the
  Python reference implementation (`py/xmss_ref.py`, `py/gen_h20.py`,
  `py/sign_digest.py`). Imported as `xmss-solidity/XMSS.sol`.
- `src/QuantumKeyRegistry.sol` — owns leaf-index consumption:
  `_verifyAndConsumeXmss` checks the key's used-leaf bitmap (OpenZeppelin
  `BitMaps`), verifies, and burns the leaf atomically; reverts loudly on reuse.
- `src/PreApprovalEngine.sol` — hybrid (ECDSA + XMSS) pre-approvals: creation,
  revocation and consumption. Abstract, like the registry.
- `src/FermionGuard.sol` — the Safe transaction guard and module guard;
  the only deployable contract (it contains the registry and the engine).
- `script/Deploy.s.sol` — CREATE2 deployment of the Guard through an
  explicit call to the deterministic deployment proxy (env vars
  `MULTISEND_CALL_ONLY`, `ADMIN_TIMELOCK`, `EMERGENCY_TIMELOCK`,
  `MAX_BATCH_LEGS`, `MAX_COMMITMENT_QUEUE`, `SALT`; defaults 2 days,
  14 days, 100, 16). It refuses out-of-range env values, zero caps and an
  emergency timelock not above the admin timelock, is a no-op if the Guard
  already exists, and reads every immutable back after deploying.
  `script/Demo.s.sol` drives the demo container: `deploy()` (Safe v1.5.0,
  2-of-3) for the standalone demo, `deployWallet()` (canonical Safe v1.4.1,
  1-of-1) for the Safe{Wallet} stack, then `blocked`, `submitApproval` and
  `execute` per payout.
- `foundry.toml` pins solc 0.8.37, so a release tag rebuilds byte-identical
  binaries.
- `test/GuardIntegration.t.sol`, `test/FermionGuard.t.sol` — leaf
  consumption, reuse rejection, invalid-signature rollback, height binding,
  zero-key rejection (through the registry), plus the Guard and engine suites.
- `test/LegacySafeSignatures.t.sol` — contract owners co-signing on Safe
  v1.3.0, v1.4.1 (creation bytecode in `test/vectors/safe-v*`) and v1.5.0
  (compiled from the `lib/safe-smart-account` submodule).
- `test/Deploy.t.sol` — `Deploy.s.sol` end to end: the same CREATE2 address
  on every target chain id (OP-stack ones included), idempotent re-runs,
  immutables read back, and rejection of bad parameters.
- `test/properties/` — fuzz properties of the Guard and a stateful invariant
  test against a reference model.
- `test/registry-proof/` — the key registry's state machine as an executable
  specification (`RegistrySpec.sol`) plus `RegistryEquivalence.t.sol`, which
  proves with Halmos that `QuantumKeyRegistry` makes exactly those transitions
  for all inputs. `DESCRIPTION.md` there is the specification rendered in
  English, generated from it by `script/describe_spec.py` — regenerate it
  whenever the specification changes
  (`python3 script/describe_spec.py --check test/registry-proof/DESCRIPTION.md`
  fails when it is stale).
- `test/ffi/sign_batch.py`, and `lib/xmss-solidity/py/sign_digest.py` — test-only
  helpers that the Foundry tests call through FFI to sign digests with the
  deterministic test XMSS key.

## Measured gas

| Operation | Gas |
|---|---|
| `XMSS.verify` (h = 10) | 712,531 |
| `XMSS.verify` (h = 20, **measured**) | **745,003** |

Measured with the pinned submodule (`xmss-solidity` v0.1.0) and its own Foundry
profile: `cd lib/xmss-solidity && forge test --match-test test_gas_verify_h20 -vv`.
Within the 0.4–1M target set in `../fermionguard-module.md`
(asserted in the library's CI: `test_gas_verify_h20` fails above 1.1M).

## Security notes

- `XMSS.sol` is stateless. **Never expose it to callers that do not consume
  leaf indices** — use the FermionGuard's registry as the
  enforcement point. Index reuse breaks XMSS entirely.
- `verify` rejects zero roots/seeds and tree heights outside 1..20.
- The XMSS verifier is formally verified against RFC 8391 (functional
  correctness, SHA-256 abstracted); see `lib/xmss-solidity/PROOF.md` for
  what is proven and assumed. The registry's state machine is proven
  equivalent to the executable specification in `test/registry-proof/` with
  Halmos (authorization and XMSS verification abstracted). That proof is run
  offline — `halmos --match-contract RegistryEquivalence --loop 32
  --solver-timeout-assertion 0` — and is not a CI gate yet: Halmos drives the
  `check_*` functions, so `forge test` does not exercise it. Beyond that, the
  Guard, registry and engine are fuzz and invariant tested, not formally
  verified.
- Not audited yet; audit is an acceptance criterion before mainnet.

## Usage

You need [Foundry](https://getfoundry.sh) (the release workflow and the demo image pin v1.8.3:
`curl -L https://foundry.paradigm.xyz | bash`, then `foundryup --install v1.8.3`)
and `python3`: the tests sign with the Python reference implementation through
Foundry FFI (`ffi = true` in `foundry.toml`). Fetch the OpenZeppelin, Safe
and xmss-solidity libraries once from the repository root, then run everything
from `contracts/`:

```shell
git submodule update --init --recursive   # from the repository root
cd contracts
```

```shell
forge test -vv                 # run the Guard, registry and engine tests
```

The XMSS library's own tests, gas benchmarks and formal proofs run in its
repository (`cd lib/xmss-solidity && forge test`; the proofs with Halmos, see
its README).
