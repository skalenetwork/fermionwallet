# FermionWallet contracts

Solidity contracts for FermionWallet. `XMSS.sol` and the deploy/demo scripts
are MIT-licensed; `FermionWalletGuard.sol`, `QuantumKeyRegistry.sol` and
`PreApprovalEngine.sol` are LGPL-3.0-only (they build on Safe's LGPL
contracts). The XMSS verifier is a **clean-room implementation** (RFC 8391 /
NIST SP 800-208), written from the specification — no code taken from poqeth
(unlicensed) or hashsigs-solidity (AGPL).

## Contents

- `src/XMSS.sol` — stateless XMSS verification library
  (`XMSS-SHA2_*_256` family: n = 32, w = 16, len = 67; tree height taken
  from auth-path length, max 20). SHA-256 precompile with bounded gas
  stipend, memory-safe assembly hashing through a caller-allocated buffer.
- `src/QuantumKeyRegistry.sol` — owns leaf-index consumption:
  `_verifyAndConsumeXmss` checks the key's used-leaf bitmap (OpenZeppelin
  `BitMaps`), verifies, and burns the leaf atomically; reverts loudly on reuse.
- `src/PreApprovalEngine.sol` — hybrid (ECDSA + XMSS) pre-approvals: creation,
  revocation and consumption. Abstract, like the registry.
- `src/FermionWalletGuard.sol` — the Safe transaction guard and module guard;
  the only deployable contract (it contains the registry and the engine).
- `script/Deploy.s.sol` — CREATE2 deployment of the Guard (env vars
  `MULTISEND_CALL_ONLY`, `ADMIN_TIMELOCK`, `EMERGENCY_TIMELOCK`,
  `MAX_BATCH_LEGS`, `MAX_COMMITMENT_QUEUE`, `SALT`; defaults 2 days,
  14 days, 100, 16). `script/Demo.s.sol` drives the demo container.
- `py/xmss_ref.py` — independent Python reference implementation
  (RFC 8391 keygen/sign/verify) used to generate the test vectors in
  `test/vectors/` (h = 4, 10). `py/gen_h20.py` generates the h = 20
  production-parameter vectors (multiprocessing, ~10 min).
- `test/XMSS.t.sol` — Foundry suite: 12 positive vectors (h = 4, 10, 20 at
  edge leaf indices), negative/tamper tests including checksum chains and
  cross-height, 5 fuzz tests, gas benchmarks.
- `test/GuardIntegration.t.sol`, `test/FermionWalletGuard.t.sol` — leaf
  consumption, reuse rejection, invalid-signature rollback, height binding,
  zero-key rejection (through the registry), plus the Guard and engine suites.

## Measured gas

| Operation | Gas |
|---|---|
| `XMSS.verify` (h = 10) | 703,258 |
| `XMSS.verify` (h = 20, **measured**) | **736,700** |

Within the 0.4–1M target set in `../fermionwallet-guard-module.md`
(asserted in CI: `test_gas_verify_h20` fails above 1.1M).

## Security notes

- `XMSS.sol` is stateless. **Never expose it to callers that do not consume
  leaf indices** — use the FermionWallet Guard's registry as the
  enforcement point. Index reuse breaks XMSS entirely.
- `verify` rejects zero roots/seeds and tree heights outside 1..20.
- Not audited yet; audit is an acceptance criterion before mainnet.

## Usage

```shell
forge test -vv                 # run tests + gas benchmarks
python3 py/xmss_ref.py         # regenerate h=4 / h=10 test vectors
python3 py/gen_h20.py          # regenerate h=20 vectors (~10 min, all cores)
```
