# Fermion v2 — decision record

**Writers: implement the CURRENT STATE section below. The decision log after it is history:
later entries supersede earlier ones, and several were reversed (monorepo 42→44, interface
45→46, ML-DSA-87 on device 39→48). Where the log and this section disagree, this section wins.**

## CURRENT STATE (authoritative)

### Products and naming
- Brand **Fermion**. **Fermion Wallet**: post-quantum cold vault (receives anything; sends ETH, ERC-20,
  ERC-721/1155 deliberately; batches of up to 8 legs; no DeFi, no approve, no arbitrary call, no modules).
  **Fermion Guard**: post-quantum gate for Safes (full ecosystem). One Ledger app named "Fermion".
  Client library npm `fermion-sdk`. Repo rename fermionwallet→fermion deferred to the dedicated-domain move.
- Licence: Fermion repo AGPL-3.0-or-later; all verifier libraries MIT; ERC drafts CC0.

### Signatures and keys
- Hybrid: ECDSA (secp256k1) + ML-DSA, both over the same 32-byte EIP-712 digest. ML-DSA is pure
  (FIPS 204 external interface), empty context. Hedged signing on device (deterministic only in test builds).
- ECDSA half: the admin MUST be an EOA (constructor/enrollment refuse code); checked only by ECDSA recovery.
  No ERC-1271 admin, no adminIsContract snapshot. ERC-1271 appears only INBOUND (Fermion Wallet answering
  as a Safe owner, both the bytes32 and legacy bytes forms).
- Keys derived from the recovery phrase, ONE KEY PER CONTRACT (wallet or Safe), path
  m/<purpose>'/60'/<slot>'/<role>'/<paramSet>' all hardened (purpose placeholder 204', role 0'=Wallet 1'=Guard,
  paramSet 0'=44 1'=65); ECDSA key = child 0', ML-DSA seed xi = SHA-256(label ‖ privkey of child 1'),
  label "FermionWallet/ML-DSA-<set>/xi/v1". BIP-39 passphrase recommended, not required.
- Parameter sets: ML-DSA-44 default, ML-DSA-65 opt-in at creation/enrollment (both products).
  ML-DSA-87 is CONTRACT-LEVEL ONLY: accepted by the contracts, but no v2 signer produces it (Ledger app ships
  44/65 only; nShield app is a design doc). Fermion accepts ML-DSA only — no SLH-DSA/FN-DSA/LMS.

### Contracts
- Verification: Fermion calls `IPQVerifier` (skalenetwork/pq-verifier-interface) and stores a
  `uint256 algorithm` per wallet/Safe, restricted to 0x0101 (44), 0x0102 (65), 0x0103 (87). `IMLDSAVerifier`
  and `ParamSet` are internal to mldsa-solidity. Verifier address fixed at deployment (no switching).
- Per-key precomputation via MLDSAKeyFactory (registerA/commitA/storeA/registerT; 87 in two A parts).
  Wallet setup in ONE transaction (commitA + registerT + clone deploy); first transfer stores A (calldata);
  public key stored as contract code. Unregistered key → full-verify fallback.
- Replay: sequential nonce; every signed struct carries validFrom + validUntil, contracts enforce
  validFrom <= block.timestamp <= validUntil and validUntil - validFrom <= 24h.
- Deployment: Arachnid deterministic deployer 0x4e59b44847b379578588920cA78FbF26c0B4956C, fixed salts, same
  addresses on every chain (mainnet, Base, Arbitrum, Optimism). Wallets = clones of one implementation
  (clone-with-immutable-args), created UP FRONT.
- Fermion Wallet: transfer/batch path (≤8 legs, ETH/ERC-20/721/1155), payable, NFT receiver hooks,
  ERC-1271 as Safe owner (signs SafeTx: ERC-20/ETH/named Safe admin/ERC-7730 calls; undecodable calls allowed
  after a strong warning; delegatecall, non-zero gas-refund fields, unlimited approvals always refused) and
  plain-text messages (SIWE / ownership proofs). Gas paid by the user's EOA or any relayer; no reimbursement.
- Fermion Guard: one Quantum Administrator per Safe; EVERY Safe transaction needs a quantum approval
  (only exceptions: emergency-removal calls). Approvals INLINE (appended to Safe signatures) or STORED
  (preApprove, consumed once; revocable by the Admin (hybrid-signed) or by the Safe itself; key-epoch counter
  kills old-key approvals). No on-chain spending policy, no pause. Modules only on Safe >=1.5.0 with the guard
  as module guard, every module tx gated, enableModule has its own device screen. Supports Safe 1.3.0/1.4.1/1.5.0.
  Key rotation: old key approves the new key's hash. Emergency removal: owners request, 14-day timelock,
  only owners cancel; while pending the Safe is frozen except cancel, final removal, and rescue transfers
  (quantum approval + owner threshold). Threat model covers case 1 only (honest owners keep working keys).

### Device and signers
- Ledger app "Fermion": Nano S Plus, Nano X, Stax/Flex (NBGL UI); Ledger SDK ML-DSA with mldsa_optimization;
  SDK pinned v26.6.5 87def514 (private MLDSA_internal_* symbols; ask Ledger for a public seeded API).
  ERC-7730 descriptors: Ledger-signed only, cached in fermion-sdk. Device refuses windows > 24h.
  Device model (demo/ledger-proof) is checked against the REAL app in Speculos (Nano + Stax/Flex).
- Signer requirements doc (normative, informational companion to the ERC); Ledger app is the reference signer;
  nShield CodeSafe signer = design doc + shared Rust signer-core (no SDK yet).

### UIs, SDK, ops
- fermion-sdk (EIP-712 payloads, WebHID + Ledger Live transport, hybrid/inline Safe signatures, factory
  registration, open relayer interface, cached descriptors). Safe App: full flow (enroll, approve inline/stored,
  execute, revoke, rotate, emergency removal). Web UI (github.io previews; dedicated domain before mainnet)
  + Ledger Live app (both built). No UI ever has a recovery-phrase field.
- Self-hostable event watcher (removal requests, stored approvals, rotations; email/webhook).
- Demos use the real Ledger app in Speculos; demo moves to Safe 1.5.0.

### Process
- Branch ml-dsa-v2; push after each phase; merge to main only when ALL 11 phases are done; v2.0.0;
  local tag xmss-final on the last XMSS commit (push on request).
- Phase order: specs → contracts+tests → Ledger Nano → SDK → Safe App → web UI → Stax/Flex → Live App →
  demos → formal → docs/ERC.
- No audit gate (state "unaudited" plainly). Formal: invariant fuzz + symbolic proofs for both contracts +
  machine-checked FIPS 204 equivalence of the verifier with open-source tools (plan to be proposed first).
- Testing on local chains only before release (EIP-7825 cap enforced, deterministic deployer etched).
- Docs: docs/fermion-wallet.md (FW-), docs/fermion-guard.md (FG-), docs/ledger-app.md (LA-),
  docs/signer-requirements.md (SR-), docs/security.md, docs/release.md, docs/sdk.md, docs/nshield-signer.md,
  docs/user-guide.md, the ERC draft, short readme.md. Fresh requirement IDs.

### Coordinator clarifications (resolve conflicts in the log)
- C1 (items 46/49/50): Fermion calls IPQVerifier restricted to ML-DSA ids, as above.
- C2 (item 33): ERC-1271 is inbound only; Open Finding 1 is closed by the EOA rule.
- C3 (items 17/25/26): the committed device model (aa55132; ca48253 before the history rewrite) still REFUSES undecodable calls; the spec follows
  items 25/26 (allow with warning). Updating the model is a phase-3 task — do not change the spec to match it.
- C4 (items 47/48): ML-DSA-87 is contract-level only with no shipping signer in v2 (residual-risk table).
- C5 (item 57 vs checker): phase 1 ADDS docs/*.md and extends check_requirements.py to accept both old and new
  prefixes; the old docs and old tests are deleted TOGETHER in phase 2. check_doc_links.py scans docs/.
  contracts/script/describe_spec.py is removed in phase 2 with the specs it describes.
- C6 (item 14): the ERC specifies the hybrid signature encoding (ECDSA ‖ ML-DSA), digest/context rules and
  ERC-1271 wrapping, and REFERENCES pq-verifier-interface for the verifier interface instead of re-specifying it.
- C7 (MultiSend vs "delegatecall always refused"): Safe batches run as a DELEGATECALL to MultiSendCallOnly.
  Rule: delegatecall is refused EXCEPT to the canonical MultiSendCallOnly deployment (address pinned per Safe
  version, as the XMSS-era guard did); every leg must be a CALL and is decoded and checked under the same rules
  as a single transaction (device shows every leg). Module transactions get no such exception. Applies to the
  Guard, the device and the Fermion Wallet owner path alike; covers emergency-removal rescue batches.
- C8 (log "Product roles" omitted from CURRENT STATE): Fermion Guard keeps the GATED FALLBACK HANDLER: the Safe's
  own ERC-1271 answers (Permit2, CoW, SIWE) are given only for messages the Quantum Administrator approved on the
  device, so off-chain signatures cannot bypass the guard. The device therefore needs a Safe-message approval flow.
- C9 (calls by the Safe to itself): only the named Safe admin functions are allowed (own screen); any other
  self-call is REFUSED before any screen (takeover vector), even though undecodable external calls are allowed
  with a warning (items 25/26 relaxed external calls only).
- Note: commit hashes in the log from before 2026-10-07's history rewrite (contributor-trailer removal) no longer
  exist on GitHub; old→new mapping is in the local backup refs.

## Measured facts (cite these; do not retype from memory)
| | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
|---|---|---|---|
| pk / sig bytes | 1312 / 2420 | 1952 / 3309 | 2592 / 4627 |
| verify, key registered (via interface) | 2.68M | 3.66M | 5.53M |
| verify, from scratch | 5.75M | 9.13M | 14.23M |
| one-tx wallet setup | 5.55M | 9.53M | 14.99M |
| first transfer (stores A) | 5.90M | 9.56M | 16.30M (store A parts ahead) |
| later transfer | 2.82M | 3.83M | 5.60M |
| APDU chunks @255 B: sig / pk | 10 / 6 | 13 / 8 | 19 / 11 |
- Per-tx cap EIP-7825 = 16,777,216 (2^24, live since Fusaka 2025-12-03); mainnet block gas 60M (2026-10-07).
  Glamsterdam (Q4 2026) reprices gas — re-measure after.
- Ledger (Speculos): keygen+sign peak 10,092 B (mldsa_optimization), same for 44/65; Nano S Plus 6.6 KB spare;
  Nano X fits only without XMSS + heap 2048. No side-channel hardening documented in Ledger's SDK.
- Pins: mldsa-solidity (v1.0.0 pending), pq-verifier-interface 6efa8e3, xmss-solidity (v1.1.0 pending),
  OpenZeppelin acd4ff74, Safe smart-account dc437e8f, forge-std v1.16.2, solc 0.8.37 via_ir.

# Decision log (chronological; superseded entries kept for history)

## Keys (device)
- secp256k1: BIP-32, unchanged path (as today's ECDSA half).
- ML-DSA-65 (DECIDED by user: derived from the recovery phrase): xi = H(label || privkey of a
  fully-hardened BIP-32 node, dedicated purpose outside 44'/60' if BOLOS allows); KeyGen_internal(xi)
  (FIPS 204 Alg 6). Replaces the NVM-random XMSS seed (main.rs xmss_key) and its "no import/export" rule.
  Stateless: restoring the phrase on a second device is SAFE and yields the same pk — backup exists;
  uninstalling the app no longer destroys the key; old FWL-025 / A3 / clone-rollback risk disappears.
  Fully hardened path => a quantum break of any exposed ECDSA pubkey cannot reach xi.
  TRADE-OFF to state in docs: the phrase is now the single secret behind BOTH halves; phrase
  compromise = full compromise (previously the XMSS half was device-bound and unrecoverable).
  hardware-security-policy.md must be rewritten accordingly (phrase custody becomes the key control).
- Signing: pure ML-DSA (not HashML-DSA), external interface, empty context: M' = 0x00||0x00||M,
  M = the 32-byte EIP-712 digest. Hedged (rnd from device RNG).

## Signature encoding on the wire
- hybrid = ecdsa(65: r||s||v) || mldsa(3309)  → 3374 bytes, where a single `bytes` is needed (ERC-1271).
- transfer() keeps two separate args.

## Check order (all paths)
1. ECDSA half under the scheme fixed at construction (adminIsContract, FWL-017a) — kept as-is.
2. ML-DSA-65 verify against stored pk (1952 bytes, storage, set once in constructor; pkHash immutable for cheap identity).

## FermionWallet
- transfer(token,to,amount,validUntil,ecdsaSig,mldsaSig): EIP-712 Transfer(address token,address to,uint256 amount,uint256 nonce,uint64 validUntil);
  replay = sequential nonce (uint256 public nonce). No leaves, no bitmap, no exhaustion, no rotation leaf.
- isValidSignature(bytes32 hash, bytes sig) → 0x1626ba7e   (Safe ≥1.5.0, generic ERC-1271)
- isValidSignature(bytes data, bytes sig)   → 0x20c13b0b   (Safe 1.4.1 legacy; hash = keccak256(data))
  Both verify over wrapped = EIP712(FermionWallet domain, SafeHash(bytes32 hash)) — hash tied to this wallet.
  Replay: the Safe's nonce is inside the hash. view-only: possible because ML-DSA is stateless.
- Device side: never signs a bare hash. It takes SafeTx fields + safe address + chainId, displays them
  (ERC-20 transfer decoded), computes the SafeTx hash, wraps it, signs.
- SafeTx ACCEPTANCE RULE (owner path; the signer REFUSES, never "displays and lets the human decide").
  A Safe without FermionGuard has no contract-side check here, so the signer is the only gate:
  1. operation == Call (0). DelegateCall refused (an owner signature over delegatecall = full Safe compromise).
  2. gasPrice == 0 && gasToken == address(0) && refundReceiver == address(0) (no refund drain); safeTxGas and
     baseGas still displayed.
  3. to != safe, except Safe self-administration (addOwnerWithThreshold, removeOwner, swapOwner, changeThreshold,
     setGuard, setFallbackHandler, enableModule, disableModule, setModuleGuard) through a dedicated admin screen
     naming the function and its arguments — never as a decoded-data page; any other self-call refused.
  4. data must decode to a displayable action: ERC-20 transfer(to, amount), or native ETH with empty data;
     anything else refused (ERC-7730 widening is for the Guard product only, not the vault).
  5. Screens show safe address, chainId, Safe nonce, the decoded action, and the role "Sign as Safe OWNER" —
     visibly distinct from a Guard approval over the same fields (different EIP-712 domain/type).

## FermionGuard (Safe guard)
- Device rule for Guard approvals: the same five SafeTx acceptance items as the owner path (refuse before
  signing rather than burn an approval on a tx the guard would revert); role shown as "Quantum APPROVAL".
- Per-Safe enrollment of (ML-DSA pk, ECDSA admin). checkTransaction requires a quantum approval of the exact
  SafeTx (same device flow as above, approval stored by hash, consumed once). Plain reverts for delegatecall
  and gas refunds. MODULES (keep current guard's rule): allowed only on Safe >=1.5.0 with FermionGuard wired as
  module guard; enableModule refused otherwise (so never on 1.4.1); every module tx needs a quantum approval of
  its exact call (to, value, dataHash, module) carrying its own nonce + validUntil (module txs have no
  safeTxHash/nonce); no exemptions; module delegatecall forbidden; dedicated device screen for enableModule. Keep ONE escape hatch: timelocked emergency de-guard by owners. Drop registry,
  pre-approval engine, XmssVerifier, xmss-solidity.

## Removed with XMSS
leaf counter/bitmap, exhaustion, rotation-on-last-leaf, per-slot binding (FWL-023 relaxed),
FWL-018/018a CI grep, lifecycle prover.

## FermionWallet UI
Static single page (no backend), built by pages.yml, served on its OWN domain (placeholder — user to pick),
not under skalenetwork.github.io (shared origin => shared WebHID permission + storage across all org pages).
WebHID to the device, user-chosen RPC, gas paid by the user's browser wallet or a relayer (msg.sender has
no authority). Pinned deps, no third-party scripts, strict CSP, bundle hash published per release
(+ IPFS mirror / run-locally option).
REVISED (user): because the phrase is now the single secret behind both halves, distribution integrity
matters more. Primary channel for the FermionWallet UI = Ledger Live app (needs Ledger listing +
device-exchange permission for our custom APDUs); the web page above is the fallback. Device app: Ledger
Live catalog ONLY — essential now, since any app allowed our derivation path can derive the ML-DSA key.
Normative rule: no UI ever has a recovery-phrase field; restore happens only on the device.
FermionGuard keeps the Safe App as its UI (same no-phrase rule).

## Signer requirements (new doc; signer-agnostic contracts)
Contracts check only ECDSA + ML-DSA-65 over the EIP-712 digest, so the Quantum Administrator may be ANY
conforming signer: the Ledger app, a custodian HSM (e.g. Anchorage, Entrust/Thales ML-DSA firmware), etc.
One short normative doc any signer implements: exact digest (EIP-712 types/domains incl. SafeTx wrapping),
pure ML-DSA-65 + empty ctx, ECDSA scheme fixed at construction, mandatory human-visible fields before signing,
digest rebuilt from displayed fields (never a host hash), key generation/backup expectations.
Includes the SafeTx acceptance rule (owner path and Guard approvals, five items above) verbatim, so an HSM
signer inherits it. The Ledger app is the reference implementation of it.
Integration paths to document: (a) custodian vault as Safe owner (WalletConnect, typed-data sig or on-chain
approveHash) + FermionGuard + Ledger; (b) custodian HSM as the Quantum Administrator (partnership).

## Entrust nShield signer (CodeSafe 5) — institutional reference signer #2
- SEE app inside nShield 5; ML-DSA-65 via native firmware (v13.8+), ECDSA secp256k1 (confirm curve support).
- Key ACLs: keys usable ONLY by our SEE app (no host-callable raw sign) — otherwise blind signing.
- No screen: replace "human sees fields" with k-of-n approver signatures over the same fields (approvers on
  Ledger/phone); SEE app verifies approvals + policy, rebuilds the EIP-712 digest, then signs both halves.
- Backup via Security World (k-of-n ACS cards), no phrase. FIPS 140-3 L3 hardware (check ML-DSA validation scope).
- Shared Rust crate `signer-core` (payload parse, EIP-712 digest, policy) used by Ledger app and SEE app.
- Blocked on: CodeSafe SDK + nShield/nShield-as-a-Service access (user to obtain). Thales Luna FM = port target.
Order: signer spec → Ledger reference app → signer-core → nShield app.

## Device gate — PASSED (Speculos)
- Use Ledger SDK's built-in ML-DSA (C, `mldsa` + `mldsa_optimization` features of the Rust SDK 1.37.1, compiled
  into the app). Low-RAM variant peak ~10.1 KB keygen+sign; fits nanos+ (6.6 KB spare) and nanox (5 KB spare,
  needs HEAP_SIZE nanox 2048 + XMSS buffers gone). Stax/Flex: not buildable yet (Nano-only UI).
- Seeded keygen needs PRIVATE symbols MLDSA_internal_keygen / MLDSA_internal_sign → ask Ledger for public seeded API.
- xi = SHA-256("FermionWallet/ML-DSA-65/xi/v1" || secp256k1 privkey at m/204'/60'/0'/0'), manifest path "204'/60'"
  (Speculos enforces it). Byte-identical vs dilithium-py (pk, sk, deterministic sig); restore-from-phrase reproduces pk.
- Open: real-hardware signing time; side-channel status (Ledger says none in v1); wipe 4,032-byte sk after sign;
  14-chunk read-out of the 3,309-byte sig. Prototype in worktree agent-a524a9818eee51f4f (uncommitted).

## Product roles — DECIDED (user: "do it")
### FermionWallet = post-quantum cold vault (receives anything, sends deliberately, no DeFi)
- payable: receives ETH; sends ETH via the same hybrid-signed path (Transfer with token = address(0) → native).
- ERC-721 / ERC-1155 receiver hooks (accept; sending NFTs: out of scope for v1 — state it).
- CREATE2 factory is THE deployment path (was optional FWL-031): same address on every chain, address pins key.
- ERC-1271 isValidSignature (both Safe forms) — device signs only typed, displayed messages:
  (a) SafeTx (Safe owner), (b) plain-text message for address-ownership proofs / SIWE (EIP-191 text shown in full
  on device, wrapped in the wallet's EIP-712 domain). No arbitrary EIP-712, no permits.
- Still no approve, no arbitrary call, no modules, no 4337 (FWL-009 stays). Gas: any relayer / user's EOA.
### FermionGuard on Safe = full-ecosystem product
- Gated fallback handler: Safe ERC-1271 (Permit2, CoW, SIWE) answers only for messages the Quantum Admin approved
  on device — closes the off-chain-signature bypass without forbidding the handler.
- Device clear signing of arbitrary calls via ERC-7730 descriptors; raw-hex calldata = refused by default.
- Approval policy: device shows spender + amount for approve/permit; unlimited approvals refused.
- Modules: as in the guard section (>=1.5.0, fully gated).
### Not fixable by design (state in docs)
Existing EOAs can't be made PQ-safe (ECDSA key keeps authority even with 7702) → funds must migrate to a new
contract address; exchanges' withdrawal allowlists must be updated. ML-DSA verify cost → L2-friendly, mainnet
pricey until an ML-DSA precompile ships.

## Parameter set — DECIDED: ML-DSA-65 with precomputation (user briefly chose 44, then reverted)
- On-chain per key, computed at deployment FROM THE WALLET'S OWN pk (never caller-supplied): tr (64 B),
  A_hat (30 polys, 23,040 B), NTT(t1·2^d) (6 polys, 4,608 B) → stored as contract code (SSTORE2-style) in two
  data contracts (27.7 KB total > 24,576 code limit), read via EXTCODECOPY.
- STORAGE PATTERN (fixes the per-tx cap): precompute in the wallet constructor does NOT fit 2^24
  (expandA 6.66M + 23 KB blob ~4.6M + 4.7 KB blob ~0.9M + tr/NTT(t1) ~1.9M + wallet code ~2M ≈ 16M+ of 16.78M),
  and Guard key rotation (old-key approval ~4.2M + new-key precompute ~13M) exceeds it outright.
  → A permissionless `MLDSA65Key` factory, one tx per data contract:
    registerA(pk) computes A_hat FROM pk and deploys it; registerT(pk) computes tr || NTT(t1·2^d) FROM pk and deploys it.
    Each data contract is created with CREATE2(salt = keccak256(pk) [+ part tag], FIXED init code that fetches
    the blob from the factory's transient storage), so its address depends only on keccak256(pk) — not on the
    blob — and the content is trusted because only the factory, computing from pk, can produce it.
  → FermionWallet constructor and Guard enrollment store only keccak256(pk) (+ the ECDSA admin) and DERIVE the
    two blob addresses; they revert (or the verify fails closed) if the code is not there yet. Reusable by
    both products; enrollment/rotation become: tx 1 registerA, tx 2 registerT, tx 3 deploy/enroll/rotate.
- Estimated verifyPrecomputed ~4.2M gas (3 per tx under the 2^24 cap); full verify 10.5M measured. Being measured.
- Device unchanged: Ledger SDK ML-DSA-65, label "FermionWallet/ML-DSA-65/xi/v1".

## Decisions (Q&A round 2)
- Devices: Nano S+/X AND Stax/Flex (NBGL touchscreen UI) in this pass.
- EIPs: delete both drafts (hash-based key registry, hybrid pre-approvals); write ONE new short ERC for the hybrid
  ECDSA + ML-DSA-65 signature format, digest/ctx rules and ERC-1271 wrapping (signer-requirements basis).
- Demo: move to Safe 1.5.0 (module guard; gated modules demo-able). Guard still refuses modules on <=1.4.1.
- Emergency de-guard: keep, EMERGENCY_TIMELOCK unchanged (immutable ctor arg, > ADMIN_TIMELOCK by construction).

## Decisions (Q&A round 3)
- Key reuse: ONE KEY PER CONTRACT (keep FWL-023/024 strictness): a fresh derivation slot for every wallet or Safe.
  Each key needs its own precompute (registerA + registerT) → setup cost per contract.
- Chains: Ethereum mainnet + Base, Arbitrum, Optimism; same addresses via CREATE2 factory.
- Guard pause: DROPPED (admin stops approving instead). Remove pause/unpause/cooldown/ADMIN unpause timelock.
- UI domain: github.io for previews only (shared-origin risk accepted for previews); dedicated domain required
  before mainnet release.

## Verifier precompute — MEASURED
verifyStored 3.93M (32-byte msg), 6.14M (3000 B); store() one tx 14.72M (12% under cap) → split into
registerA / registerT via permissionless factory (advisor fix above). load 15.7k cold.

## Decisions (Q&A round 4)
- FermionWallet as Safe OWNER signs: ERC-20 transfers, ETH sends, named Safe admin functions (own screen), AND
  ERC-7730 clear-signed contract calls. Always refused before any screen: operation != Call, non-zero
  gasPrice/gasToken/refundReceiver, calls the device can't fully decode, unlimited approvals. (Formal model ca48253.)
- Guard key rotation: old key quantum-approves the new key's hash (new key pre-registered via registerA/registerT);
  lost/compromised key → emergency de-guard (timelock) + re-enroll.
- Ledger Live app AND standalone web UI both built in this pass (Live App untested against Ledger review).
- Nothing deployed to migrate: ML-DSA version is a clean new major version.

## Decisions (Q&A round 5)
- ERC-7730 descriptors: only Ledger-signed (Ledger clear-signing registry); device verifies Ledger's signature.
- Validity: device refuses validUntil > now + 24h (device clock source to specify: host-supplied time is untrusted →
  cap is relative to a timestamp the device shows; contracts enforce expiry on-chain).
- ML-DSA signing: hedged (FIPS 204 default, device RNG); deterministic only in test builds.
- No on-chain spending policy in FermionGuard (every tx needs an approval; limits live in device/custodian policy).
  RESOLVED: a Ledger has no trusted clock, so the 24h cap is enforced ON-CHAIN, not by the device: every signed
  struct carries validFrom + validUntil; contracts require validFrom <= block.timestamp <= validUntil and
  validUntil - validFrom <= 24h; the device refuses a window > 24h and shows both times in UTC.

## Decisions (Q&A round 6)
- Guard approvals INLINE: quantum signature appended to the Safe tx `signatures`; guard verifies in checkTransaction
  (~3.9M). No stored pre-approvals, no revoke/queue machinery (PreApprovalEngine gone entirely).
- Exactly ONE Quantum Administrator per Safe.
- Drop fermionguard-add-on-service.md and fermionguard-gnosis-service-deployment.md.
- nShield: design doc + extract shared Rust `signer-core` (parse, digest, acceptance rules) used by the Ledger app.
- Key factory (measured): registerA 11.58M, registerT 3.52M (separate txs, permissionless, idempotent);
  wallets/guard store factory (immutable) + pkHash; verify via MLDSA65Keys library 3.92M (32-byte msg).

## Parameter sets — FINAL DECISION (supersedes all earlier ones)
Support BOTH ML-DSA-44 (DEFAULT) and ML-DSA-65 (opt-in at wallet creation; fixed per wallet/key).
paramSet stored immutably per wallet/key and included in factory salts; verify dispatches on it; device derives
xi per set ("FermionWallet/ML-DSA-44/xi/v1" / "...-65/xi/v1"). All precomputed (A, tr, NTT(t1)).

## Decisions (one-by-one round)
1. Guard keys: same rule as FermionWallet — ML-DSA-44 default, ML-DSA-65 opt-in at enrollment.
2. One Ledger app ('FermionGuard') for both products; separate key slot per contract; screens name product + role.
3. Replace src/fermion-wallet.js with a real client SDK (EIP-712 payloads, device transport WebHID + Ledger Live Wallet API, hybrid sig + inline Safe sig assembly, factory registration); shared by web UI, Live App, Safe App.
4. NO audit gate (user choice): ship once tests + proofs pass; SECURITY.md and readme state plainly that MLDSA verifier, factory and contracts are unaudited. Differential oracles (AWS-LC, ZKNox standard ML-DSA) still added.
5. Formal: invariant fuzz + symbolic proofs for FermionWallet/FermionGuard AND a machine-checked proof that the ML-DSA verifier matches FIPS 204 (large effort; approach TBD — e.g. per-component symbolic equivalence of Keccak/SHAKE, NTT, decode, UseHint against an executable spec, plus composition).
6. Guard approvals: BOTH paths. (i) inline: quantum sig appended to Safe tx signatures; (ii) stored pre-approval: preApprove(...) verifies the SAME signed struct (device signs identical bytes either way) and stores it keyed by (safe, safeTxHash); checkTransaction consumes it once. Needed for any Safe front-end's Execute button (Ledger Enterprise Multisig, custodian tooling). Required extras: expiry (<=24h window), revoke (hybrid-signed by the Quantum Admin), key-epoch counter so rotation kills old-key approvals, dead approvals harmless (nonce-bound). Formal proofs must cover both paths' equivalence.
7. Verifier FIXED at deployment (IMLDSAVerifier address immutable); moving to a new verifier = new FermionWallet (signed transfer) or Safe re-enrollment. Other defaults confirmed: unregistered key falls back to full verify; pk stored as contract code.
8. ECDSA half also one key per contract: derived from the same key slot as that contract's ML-DSA key (fully hardened slot path; ECDSA child and ML-DSA xi domain-separated). No shared admin address across contracts.
9. Gas: user's own EOA submits by default; client SDK exposes an open relayer interface (any relayer, ours or third-party, can submit the signed transfer); contract unchanged, NO reimbursement from the vault.
10. Stored-approval revoke: by the Quantum Admin (hybrid-signed revoke) OR by the Safe itself via an ordinary Safe tx (guard exempts the revoke self-call from needing a quantum approval — it only removes permission).
11. FermionGuard supports Safe 1.3.0, 1.4.1 and 1.5.0 (modules blocked on <1.5.0); per-version compatibility tests; FermionWallet ERC-1271 already answers both legacy (bytes) and bytes32 forms.
12. FermionWallet sends NFTs in v1: EIP-712 NftTransfer(standard 721|1155, collection, tokenId, amount (1155), to, nonce, validFrom, validUntil), safeTransferFrom, shown on device; same hybrid-signed path; receiver hooks kept.

## Device ML-DSA-44/65 — MEASURED (Speculos)
- One build, set chosen per call (SDK MLDSA_44/MLDSA_65 runtime arg). 70/70 checks per run on nanos+ and nanox.
- Stack identical for 44 and 65 (SDK sizes workspaces for the max set): keygen+sign 10,092 B with
  mldsa_optimization → USE IT. nanox needs XMSS buffers gone + HEAP_SIZE 2048 (full XMSS build: 40 B margin).
- Chunks @255 B: sig44 10, sig65 13, pk44 6, pk65 8.
- Side-channel: NOTHING documented in SDK → treat as unhardened (earlier "no countermeasures" quote was from
  Ledger's blog, not the SDK). Pin SDK (v26.6.5 87def514) because internal keygen/sign symbols are private.
- OPEN: key slot must record its param set (derivation doesn't encode it).
13. Derivation: m/<purpose>'/60'/<slot>'/<role>'/<paramSet>' (all hardened). purpose = dedicated unused number (placeholder 204', confirm unregistered in SLIP-44/BIP-43 usage before release); role 0'=FermionWallet,1'=FermionGuard; slot counts up per contract (client SDK scans); paramSet 0'=ML-DSA-44, 1'=ML-DSA-65. ECDSA key and ML-DSA xi come from TWO SEPARATE HARDENED CHILDREN of that node:
  .../<paramSet>'/0' = secp256k1 key (its pubkey is public; a quantum break yields only this child's privkey),
  .../<paramSet>'/1' = node whose privkey feeds xi = SHA-256(label || privkey). Hardened siblings: breaking 0'
  reveals nothing about 1' or the parent. NEVER derive xi from the ECDSA key's own node (that would let a quantum
  break of the classical half yield the ML-DSA key — hybrid defeated). Same fix applies to item 8.
14. ONE narrow ERC: hybrid ECDSA + ML-DSA-44/65 signature encoding, paramSet ids, pure ML-DSA empty ctx over the EIP-712 digest, ERC-1271 wrapping, IMLDSAVerifier interface. Signer requirements = separate informational companion doc (not part of the ERC).
15. Clean v2.0.0: delete all XMSS code/docs/submodule/registry/engine/simulator in the rewrite; local tag 'xmss-final' on the last XMSS commit (push only with user go-ahead); CHANGELOG explains the switch.
16. Demos use the REAL Ledger app in Speculos everywhere; delete demo/ledger_sim.py; formal model's refinement check retargets Speculos (or is limited to the model).
17. Formal model's refinement check retargeted to the REAL app in Speculos, for Nano AND Stax/Flex: generated button/touch sequences, screens + outputs compared to the model at every step.
18. Safe App full flow: enroll (factory registerA/registerT, setGuard, module guard on 1.5.0), approve on device (inline or stored), execute with appended quantum sig, revoke stored approvals, key rotation, request/cancel emergency de-guard. Built on the client SDK.
19. A_hat commit-then-store (both sets): setup tx = commitA (compute A on-chain, store keccak hash) + registerT + wallet deploy (clone w/ immutable args + pk code) in ONE tx (~10.9M for 65 est.); FIRST transfer supplies A in calldata (~0.37M), factory storeA checks hash and deploys the code blob (~4.6M), then fast verify; later transfers ~3.9M. registerA (commit+store) kept as convenience. Wallet transfer takes optional aHat bytes.
20. Wallet creation UP FRONT: setup tx (commitA + registerT + wallet deploy) runs at creation, before any funds arrive; NFT safe transfers work from day one. CREATE2 address still derived from the key (same on every chain).
21. Gas levers (advisor fork): queued to verifier agent — single-lane Keccak for sequential hashes (~-0.4M/verify),
    trim interface external-call overhead (~-0.25M), tighten ExpandA rejection loop (up to ~-2M setup).
    Design notes only: per-chain verifiers behind the interface (Arbitrum Stylus), check EIP-7825 applicability on
    each L2; optimistic verification REJECTED (changes security model). Spec cost section: setup is paid per
    contract (one key per contract). Re-measure after Glamsterdam repricing. Batch transfers: user decision pending.
22. FermionWallet batch transfers: one hybrid signature authorizes up to 8 legs (token/ETH/NFT legs), each leg shown in full on the device, executed atomically (all or nothing), one nonce + one validity window for the batch.

## Verifier v2 — COMMITTED cc7d91f (390/390 tests)
IMLDSAVerifier (ParamSet uint8: 0=44, 1=65; supportsParamSet; ERC-165), MLDSAVerifier (fast path if registered,
else full verify), MLDSAKeyFactory (registerA/commitA/storeA/registerT), MLDSAPublicKeys (pk as code).
Gas 44/65: verify by hash 2.65M/3.60M; through interface fast 2.68M/3.66M; one-tx wallet setup 5.55M/9.53M;
first transfer 5.90M/9.56M; later 2.82M/3.83M. 23-bit packing rejected (loses after ~4 transfers);
single-lane Keccak rejected (no gain under EVM gas model).
23. Emergency removal (threat model: CASE 1 ONLY — compromised owners leave honest owners with working keys):
    - owners request removal; EMERGENCY_TIMELOCK 14 days; only owners can cancel (no QA veto → no ransom freeze).
    - while pending, the Safe is FROZEN except: (i) cancel, (ii) final setGuard(0) after the timelock,
      (iii) rescue transfers out (ETH / ERC-20 / 721 / 1155 transfers, batched via MultiSendCallOnly) with the
      normal quantum approval + owner threshold, to any destination both sides approve. Kills nonce griefing.
    - NO rescue-sweep module, NO recovery address. Case 2 (attacker holds the threshold exclusively) is an
      explicitly documented residual risk.
24. Guard gate scope: EVERY Safe transaction needs a quantum approval (except the emergency-removal escape calls). No exemptions, no allow-list in v2.
25. Undecodable calls (no Ledger-signed ERC-7730 descriptor) on GUARD approvals: ALLOWED after a strong warning; device shows target address, function selector, value, and calldata (full hex paged, plus its hash). Still hard-refused regardless: delegatecall, non-zero gas-refund fields, unlimited approvals. SUPERSEDES the 'undecodable → refused' rule in items 19/round-4; formal model (ca48253) must be updated.
26. Same rule for FermionWallet signing as a Safe OWNER: undecodable calls allowed after the strong warning (same screens as item 25); delegatecall, gas-refund fields, unlimited approvals still hard-refused.
27. Alerting: minimal self-hostable event watcher in the repo (watches guard events for configured Safes: removal requested/cancelled, stored approvals, key rotation; email + webhook). No hosted service. Safe App also shows pending items prominently.
28. BIP-39 passphrase: RECOMMENDED (not required) for both FermionGuard and FermionWallet keys; hardware-security-policy.md explains the trade-off (stolen-backup protection vs a second secret that can be lost; store separately).
29. Hardware: user has/will get Nano S Plus + Flex (or Stax). Real-device tests (signing time, real-handler stack, path enforcement) on those; Nano X stays emulator-only until a device is available (40 B margin risk noted).
30. Formal verification: OPEN-SOURCE tools only (K/Kontrol, hevm/halmos); component-wise proofs/equivalence of Keccak/SHAKE, NTT, decoding, hints, ExpandA vs an executable FIPS 204 spec, plus composition; plan with effort estimates to be proposed before starting.
31. ERC-7730 descriptors: client SDK bundles + caches Ledger-signed descriptors (our own contracts + common protocols), fetches the rest online; device always verifies Ledger's signature; fetch failure → warning screen.
32. Delivery order: spec → contracts+tests → Ledger Nano → client SDK → Safe App → web UI → Stax/Flex → Live App → demos → formal → docs/ERC; one signed commit per phase; PUSH to GitHub after each phase (signatures verified before every push).

## Naming — DECIDED
- Umbrella brand "Fermion". Products: Fermion Wallet (post-quantum cold vault), Fermion Guard (post-quantum gate for Safes).
- Ledger app name: "Fermion" (signs for both). Client library: fermion-sdk (npm scope @fermion is already registered by someone else as of 2026-10-07; fermion-sdk is free).
- Repo rename fermionwallet → fermion: done TOGETHER WITH the move to the dedicated domain (Pages/Safe App URL change),
  not before. User to run a trademark/name search before the Ledger catalog listing.
- Pending at that time: repo GitHub description (set 2026-10-07, names FermionGuard/FermionWallet) to be updated.
33. ECDSA half MUST be an EOA: constructor/enrollment rejects an admin with code; classical half checked only by
    ECDSA recovery (tryRecover). Deletes adminIsContract / FWL-017a snapshot machinery and ERC-1271 admin support;
    closes Open Finding 1. A later 7702 delegation of the admin address is irrelevant (recovery only).
34. Solidity ML-DSA library → its own repo, added as a git submodule under contracts/lib (like xmss-solidity). Rust ML-DSA stays inside ledger-app for now (no separate repo).
35. Licences: Fermion repo AGPL-3.0-or-later (own code; vendored/submodule code keeps its licence); mldsa-solidity MIT.
36. Move the whole XMSS stack to skalenetwork/xmss-solidity: QuantumKeyRegistry.sol, PreApprovalEngine.sol, their
    docs (quantum-key-registry.md, pre-approval-engine.md), registry proof (test/registry-proof), and all three EIP
    drafts (xmss-verification, hash-based-key-registry, hybrid-pre-approvals) + eips checker/assets/licence.
37. Moved XMSS stack (registry, pre-approval engine, proofs) relicensed MIT in xmss-solidity; EIP drafts stay CC0.
38. xmss-solidity: push straight to its main, then tag v1.1.0 (signed; xmss-solidity main is already at v1.0.0, so v0.2.0 would go backwards). Fermion repo keeps its copies until the v2 contract rewrite deletes them (branch stays green).
39. ML-DSA-87 added as a third OPT-IN parameter set (ParamSet id 2) in mldsa-solidity AND as an option in Fermion Wallet. Contract side: two-part A storage (43 KB > code limit), split store-on-first-use. Device support per model as measured (Ledger keeps 87 behind HAVE_MLDSA_87; Nano X likely cannot).
40. Safe-specific XMSS registry + pre-approval engine (+ their tests, proof, specs, EIP drafts, XmssVerifier) live in xmss-solidity under a clearly marked reference/ folder (application-level reference); the generic library stays at the root src/. Repo-level deps (OZ, Safe) accepted.
41. ML-DSA key registry (key IDs, rotation signed by the current key) moves from xmss-solidity to mldsa-solidity; generalise to a scheme-agnostic registry later once SLH-DSA / FN-DSA verifiers exist.
42. ONE monorepo for all post-quantum Solidity verifiers: rename skalenetwork/xmss-solidity → skalenetwork/pq-solidity
    (keeps stars, history, v1.0.0 release; old URL redirects). Packages src/<scheme>/ (xmss, mldsa, slhdsa, fndsa, lms;
    XMSS^MT in xmss), per-package tests/proofs/docs, per-package tags (e.g. mldsa-v1.2.0). reference/ = Safe-based XMSS
    registry + engine + EIP drafts. mldsa-solidity archived, README pointing to pq-solidity. One site with a
    cross-scheme gas table. Fermion uses one submodule (pq-solidity). Licence MIT (reference EIPs CC0).
43. ML-DSA-87 on Ledger (Speculos): correct on both Nanos (byte-identical vs dilithium-py). Shippable on Nano S Plus
    only with mldsa_optimization (2,532 B margin). Nano X: NOT shippable (overflow; 912 B even without XMSS).
    Stax/Flex: estimate only — fits only with ~2 KB heap + optimization. Enabling 87 (HAVE_MLDSA_87) raises signing
    stack for 44/65 too (+1,920 B optimized) because SDK workspaces size for the max set. Sig 19 chunks, pk 11.
44. REVERTS item 42: NO monorepo. Separate repos: mldsa-solidity (ML-DSA incl. key registry + 87), xmss-solidity (XMSS + XMSS^MT + reference/), and new skalenetwork/slhdsa-solidity, fndsa-solidity, lms-solidity (public, MIT). No rename, no archive.
45. Verifier interfaces: one per repo (IMLDSAVerifier, ISLHDSAVerifier, IFNDSAVerifier, ...); no shared interface repo, no generic dispatcher. Fermion integrates per scheme.
46. REVERTS item 45: shared-interface repo skalenetwork/pq-verifier-interface (public, MIT): IPQVerifier.verify(algorithm, publicKey, message, signature) + supportsAlgorithm + ERC-165, with one algorithm-id registry (PQAlgorithms). Every stateless verifier repo (mldsa, slhdsa, fndsa) implements it (submodule dependency); per-scheme interfaces may remain. XMSS/LMS (stateful) keep their own interfaces. Ledger build question (87) still open.
47. mldsa-solidity ML-DSA-87 done (local, 4 signed commits): 106 tests; ACVP 87 all correct; fast verify 5.53M, full 14.23M, one-tx setup 14.99M (1.79M headroom), first transfer storing both A parts 16.30M (only 0.48M headroom → store parts ahead via storeAPart), later transfer 5.60M. registerA(87) one-call 19.09M > cap → use registerAPart twice.
48. ML-DSA-87: SKIPPED on the Ledger for now (no HAVE_MLDSA_87 in the app; Ledger users get 44/65). Stays in mldsa-solidity and accepted by Fermion contracts for other signers (e.g. HSMs). Revisit when Ledger documents side-channel hardening and Stax/Flex are measured. Device agent's 87 feature code stays unmerged.
49. skalenetwork/pq-verifier-interface PUBLISHED (6efa8e3, MIT, no deps): IPQVerifier is IERC165 {verify(uint256 algorithm, bytes pk, bytes msg, bytes sig); supportsAlgorithm(uint256)}, interfaceId 0x97b4ac55; PQAlgorithms ids family<<8|variant: ML-DSA 0x0101-0x0103, SLH-DSA SHA2 0x0201-0x0206 / SHAKE 0x0211-0x0216, FN-DSA 0x0301-0x0302. Pure signing, empty context, never reverts.
50. Fermion accepts ML-DSA only: 44/65 (Ledger), 87 for HSM signers. No SLH-DSA / FN-DSA / LMS in Fermion; those libraries are standalone. Fermion calls the ML-DSA verifier (it may call it via IPQVerifier, but only ML-DSA ids are accepted).
51. Publish slhdsa-solidity, fndsa-solidity, lms-solidity NOW: public, MIT, site each, signed tag v0.1.0, README 'unaudited'. SLH-DSA and FN-DSA implement IPQVerifier (pq-verifier-interface submodule); LMS keeps its own interface.
52. mldsa-solidity release: v1.0.0 (signed tag) after merging ML-DSA-87, the key registry (+87), the site and IPQVerifier.
53. xmss-solidity release v1.1.0 WITHOUT new submodules: OZ + Safe are NOT git submodules; reference/ fetches them at pinned commits via a setup script (reference/scripts/setup-deps.sh → reference/lib/, gitignored) used by its Foundry profile and CI. Plain forge install of xmss-solidity pulls nothing new. If infeasible → v2.0.0.
54. Fermion v2 first release = EVERYTHING (all 11 phases: specs, both contracts, Ledger app Nano+Stax/Flex, client SDK, Safe App, web UI, Ledger Live app, demos, formal verification, docs, ERC) in one release; ml-dsa-v2 branch merges to main only when all are done.
55. Pre-release testing on LOCAL chains only (demo anvil chain with EIP-7825 cap emulated where possible); no public testnet deployments before release. Residual: same-address-on-every-chain and L2 per-tx cap behaviour unverified on live networks — state in release notes.
56. Shared contracts (MLDSAKeyFactory, MLDSAVerifier, FermionWallet implementation + wallet factory, FermionGuard) deployed via the Arachnid deterministic CREATE2 deployer 0x4e59b44847b379578588920cA78FbF26c0B4956C with fixed salts; same addresses on every chain; permissionless redeploy; no owners/initialisation. Local tests deploy through the same deployer (etched).
57. v2 docs: lean set under docs/ — fermion-wallet.md, fermion-guard.md (merges fermionguard-module.md + fermionguardspec.md), ledger-app.md, signer-requirements.md, security.md (threat model + hardware/custody policy + residual risks), release.md, sdk.md, nshield-signer.md, user-guide.md (was ui-help.md), the ERC draft; short root readme.md. All other old top-level docs deleted (history keeps them).
58. Requirement IDs: fresh per document — FW- (fermion-wallet), FG- (fermion-guard), LA- (ledger-app), SR- (signer-requirements); old FWL/GRD/QKR/ENG IDs retire with the old code; check_requirements.py updated accordingly.
