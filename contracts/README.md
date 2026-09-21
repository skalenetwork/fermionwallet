# FermionWallet contracts

MIT-licensed Solidity contracts for FermionWallet. First component: a
**clean-room XMSS signature verifier** (RFC 8391 / NIST SP 800-208),
implemented from the specification — no code taken from poqeth (unlicensed)
or hashsigs-solidity (AGPL).

## Contents

- `src/XMSS.sol` — stateless XMSS verification library
  (`XMSS-SHA2_*_256` family: n = 32, w = 16, len = 67; tree height taken
  from auth-path length, max 20). SHA-256 precompile with bounded gas
  stipend, memory-safe assembly hashing through a caller-allocated buffer.
- `src/XMSSStateful.sol` — stateful wrapper enforcing leaf-index
  consumption: `verifyAndConsume` checks a used-leaf bitmap, verifies, and
  burns the leaf atomically; reverts loudly on reuse.
- `py/xmss_ref.py` — independent Python reference implementation
  (RFC 8391 keygen/sign/verify) used to generate the test vectors in
  `test/vectors/` (h = 4, 10). `py/gen_h20.py` generates the h = 20
  production-parameter vectors (multiprocessing, ~10 min).
- `test/XMSS.t.sol` — Foundry suite: 12 positive vectors (h = 4, 10, 20 at
  edge leaf indices), negative/tamper tests including checksum chains and
  cross-height, 5 fuzz tests, gas benchmarks.
- `test/XMSSStateful.t.sol` — leaf consumption, reuse rejection, rollback
  on invalid signature, height binding, zero-key deploy rejection.

## Measured gas

| Operation | Gas |
|---|---|
| `XMSS.verify` (h = 10) | 957,370 |
| `XMSS.verify` (h = 20, **measured**) | **999,247** |

Within the 0.4–1M target set in `../fermionwallet-guard-module.md`
(asserted in CI: `test_gas_verify_h20` fails above 1.1M).

## Security notes

- `XMSS.sol` is stateless. **Never expose it to callers that do not consume
  leaf indices** — use `XMSSStateful.sol` (or the FermionWallet Guard) as
  the enforcement point. Index reuse breaks XMSS entirely.
- `verify` rejects zero roots/seeds and tree heights outside 1..20.
- Not audited yet; audit is an acceptance criterion before mainnet.

## Usage

```shell
forge test -vv                 # run tests + gas benchmarks
python3 py/xmss_ref.py         # regenerate h=4 / h=10 test vectors
python3 py/gen_h20.py          # regenerate h=20 vectors (~10 min, all cores)
```
