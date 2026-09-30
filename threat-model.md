# Threat Model — Adversary Analysis

This document defines who FermionGuard defends against, what each adversary can and cannot achieve, and which spec mechanism stops them. Every security claim elsewhere in the suite should trace back to a row here. It covers FermionGuard only; §6 says why the second product needs its own.

**System recap (one paragraph).** A Gnosis Safe holds the funds. The FermionGuard (non-upgradeable singleton) sits on `checkTransaction` and refuses any execution that lacks a live on-chain pre-approval. Pre-approvals are created by `createPreApproval`, which verifies **two signatures over the same EIP-712 digest**: an ECDSA half against the registered `quantumAdmin` (the Administrator's Ledger EOA) and an XMSS half (RFC 8391, SHA-256) against the registered `xmssRoot`, with single-use leaf enforcement in an on-chain bitmap **keyed by the XMSS root** — so one leaf is one digest across every Safe that key serves. (It used to be keyed per registration, which handed one physical key a fresh empty bitmap per Safe; fixed in `0be0ce2`, pinned by `contracts/test/CrossSafeLeafReuse.t.sol`. That bitmap is the on-chain backstop for A3's counter monotonicity — the rolled-back or cloned device.) Both halves come from the same physical Ledger (FermionGuard XMSS app); the backend holds no keys. Escape hatches: ADMIN-class pre-approvals under `ADMIN_TIMELOCK` (48 h in the reference deployment; they need the XMSS key), and a quantum-key-independent, owners-only emergency de-guard under `EMERGENCY_TIMELOCK` (14 d). The owners' emergency key revocation (`requestKeyRevocation`, also 14 d) is the second quantum-key-independent path.

One rule precedes all of that and is easy to trip over: `checkTransaction` rejects any Safe transaction with `gasPrice != 0` **before** the escape-hatch allow, so every owner-threshold safety action — cancel, unpause, the matured `setGuard(0)` — must be signed with no gas refund, or it reverts. Calls an owner makes directly from their own EOA (`pauseSafe`, `revokePreApproval`) never pass through the Guard and are unaffected.

---

## 1. Security assumptions

| # | Assumption | If it falls |
|---|---|---|
| A1 | SHA-256 (second-)preimage resistance holds, classically and against quantum adversaries (Grover halves bits: 128-bit quantum preimage security) | XMSS forgeable → entire quantum layer void |
| A2 | ECDSA/secp256k1 **may fail at any time** (cryptographically relevant quantum computer, or key theft) | This is the design premise, not a failure — see §2.1 |
| A3 | The Ledger ST33 secure element resists physical extraction and enforces PIN + counter monotonicity. Since `8379818` it also holds the **only** copy of the XMSS seed: 32 bytes from the SE's RNG on first use, with no command that imports, exports or resets it | Stolen device becomes a signing oracle (§2.4). It also cuts the other way: a wiped device destroys the key, and the 24 words do not bring it back |
| A4 | Ethereum consensus and the Safe v1.4.1 contracts behave as specified | Out of scope; inherited risk |
| A5 | At least one honest, online watcher observes Guard events within the shortest timelock window | Timelocked attacks (§2.5, §2.7) can complete unobserved |
| A6 | Safe owners' hardware wallets display EIP-712 fields truthfully | Ceremony co-signatures can be phished |
| A7 | The clean-room XMSS verifier computes what RFC 8391 verification computes. Machine-checked **in part only** — §4 says which part | XMSS half forgeable. Contained by the ECDSA half against a classical attacker; against §2.1's adversary it is a drain with no timelock |

A5 is the softest assumption in the system — the watcher role is currently under-specified; see §5. A7 is the one with a partial proof behind it rather than a citation, and §4 states its reach exactly, because a threat model that assumes a fully verified verifier is assuming something nobody proved.

---

## 2. Adversary catalog

Each adversary: capabilities → attack → what stops them → residual risk.

### 2.1 Quantum-capable attacker (the headline adversary)

**Capabilities:** recovers any secp256k1/ECDSA private key from its public key or signatures. That includes: every Safe owner key, the Administrator's `quantumAdmin` EOA, the relayer, and any EIP-712 signature ever published. Cannot invert SHA-256 (A1), so cannot forge XMSS.

**Attack:** forge owner signatures → `execTransaction` with threshold "owner" approval → drain.

**What stops them:** the Guard. Execution requires a pre-approval whose creation required a valid **XMSS** signature over the exact payload. The attacker can mint the ECDSA half of a pre-approval but not the XMSS half; `createPreApproval` reverts. Forged owner signatures get the attacker into `checkTransaction`, which finds no matching approval and reverts.

**Attack, escalated:** forge owner signatures to call `setGuard(0)` and remove the Guard. Blocked **once the Safe has registered a key**: admin self-calls need an ADMIN-class pre-approval (XMSS-signed) plus `ADMIN_TIMELOCK`. The owners-only emergency de-guard path is also signature-gated but additionally time-locked 14 days and loudly evented. Within the window the honest owners cancel it with their own owner-threshold Safe transaction (`cancelEmergencyDeGuard`); the Administrator cannot cancel it alone, and neither pausing nor key rotation stops the de-guard clock (assumption A5).

**Attack, escalated — and not blocked before enrollment:** `_isEmergencyEscapeCall` has a third branch (`FermionGuard.sol` ~line 406): on a `setGuard(address(0))` self-call it returns true immediately while `enrolledSafe[safe]` is false — no pre-approval, no timelock, no pause check, ahead of the enrollment check itself. The valve is correct, because a Safe that attached the Guard before registering a key would otherwise be frozen forever: every checked transaction reverts `NotEnrolledSafe`, enrollment reverts on the posture check, and `requestEmergencyDeGuard` requires enrollment. But it means **attaching the Guard buys nothing until the key lands.** The window between `setGuard(guard)` and `registerQuantumKey` is classically protected only, and an attacker holding forged owner signatures walks out of it in one transaction. What closes it is that `enrolledSafe` is sticky: no Safe that ever held a key can take this path again. Operationally: register in the same session you attach, and treat a Guard-attached, unenrolled Safe as unprotected rather than half-protected.

**Attack, escalated (second path):** forge owner signatures over `RequestKeyRevocation`, wait `EMERGENCY_ROTATION_TIMELOCK` (the same 14 days), execute the revocation, then register the attacker's own key: `registerQuantumKey` needs only owner signatures and an attestation by whichever `quantumAdmin` the owners signed, and the attacker can forge both, since both are ECDSA. The owner threshold really can activate a key alone; that is [QKR-013], and it is accepted, not overlooked — it is what lets honest owners recover after the Administrator's device is lost. The honest owners cancel the same way (`cancelKeyRevocation`, an owner-threshold Safe transaction no Safe or Guard state can block — subject only to the universal `gasPrice == 0` rule). The request consumes the registry nonce, so repeated requests also kill in-flight ceremonies (liveness only).

**Residual risk:** a quantum attacker who **also** controls or destroys all watchers can ride either 14-day path to completion. Mitigation: watcher redundancy (§5) so the honest owners learn of it in time to cancel.

**Residual risk (legitimate revocations):** when the honest owners revoke a lost or stolen key themselves, the key they register next is protected only by classical signatures until it is active. A quantum attacker can race it: execute the matured revocation and register its own key in the same block. The honest registration then reverts `SafeAlreadyEnrolled`, and the attacker holds an Active key. Nothing on-chain prevents this (`test_TM_ResidualRisk_PostRevocationRegistrationIsClassicalOnly`). The revocation's 14-day public countdown is the only warning. Against a quantum-capable adversary, prefer routine rotation (it needs an old-key XMSS proof) and use revocation only when the old key is really gone.

### 2.2 Compromised backend / add-on service

**Capabilities:** full control of the Node.js service — queue, policy engine, ceremony coordinator, relayer key, WebSocket feeds. Holds **zero key material** (Ledger-only architecture).

**Attacks & outcomes:**
- *Mint pre-approvals autonomously* — impossible: both signature halves come from the Ledger secure element; the service only relays.
- *Present a lying payload for signature* — the Ledger renders token/recipient/amount/leaf on its own screen from the streamed payload and recomputes the digest from what it rendered; the Administrator's review is the control. Residual: human inattention (see §3, UX mitigations: no raw-hash path).
- *Grief via relayer* — withhold `createPreApproval` submissions (liveness attack, not safety), or burn relayer gas. Funds never move.
- *Desync leaf mirror* — advisory only; chain bitmap is authoritative, and now global per root, so a mirror cannot disagree with the chain in the direction that matters.
- *Suppress alerts / act as a blind watcher* — this is the real damage: see A5/§5.

**Verdict:** total backend compromise is a **liveness** problem plus an alerting problem, never a fund-safety problem.

**Build state, because it changes what the bullets mean.** The service does not exist. `src/` is an early JavaScript model with HMAC stand-in signatures (its own `package.json` says so) and `demo/` is a Python demo harness. So the desync alarm, the policy engine and the alert transports above are specification, not code. The verdict survives, because it rests on what the chain enforces and not on the service; the *detection* story does not, and it compounds A5.

### 2.3 Malicious frontend (Safe App / ceremony UI)

**Capabilities:** renders anything, swaps parameters in flight, initiates rogue ceremonies.

**Attacks:** substitute an attacker's `xmssRoot` or `quantumAdmin` during a ceremony; present a rotation as a routine approval; misdescribe a transfer.

**What stops them on-chain:** owners clear-sign `ApproveQuantumKey{safe, quantumAdmin, xmssRoot, xmssSeed, treeHeight, parameterSet, registryNonce, validUntil}` on their **own hardware**, so a swapped root or admin address invalidates every signature; `registerQuantumKey` then checks the attestation against the same root and `quantumAdmin` the owners named, so the two proofs cannot be made to disagree; `registryNonce` kills stale and aborted sessions.

**What does not stop them yet: the device's half.** The built app (`ledger-app/`) implements `SIGN_PREAPPROVAL` plus the read commands, over one key slot. There is no `SIGN_KEY_ATTESTATION`, no `SIGN_ROTATION`, no `GEN_XMSS_KEY`, no `RETIRE_KEY`; no ceremony words anywhere; and the review headings are `Sign approval` / `Sign payload` / `ADMIN ACTION`, not the per-flow `Register key` / `Rotate key` headers `ledger-xmss-app.md` specifies. The Administrator's `ledgerAttestation` for a registration or rotation is therefore produced off-device today, by whatever holds the admin key. The anti-substitution property is real and tested on-chain; the trusted display that is supposed to let a human *see* a substituted root is specified and unbuilt.

**Residual risk:** owners who don't actually read their device screens (A6) — and, until those commands exist, a ceremony with no trusted display of its own at all. The owners' own hardware review of `ApproveQuantumKey` is the whole control in the meantime.

### 2.4 Thief with the Administrator's Ledger

**Capabilities:** physical device. Without the PIN: 3 attempts, then the device wipes (zeroization). With the PIN (coerced/observed): a full signing oracle for both hybrid halves.

**What stops them (PIN known):** the thief can create pre-approvals, but every creation is a public on-chain event with the target fields visible; owners still control execution (threshold signatures) and any owner can revoke transfer/payload approvals and pause the Safe (except during the `ADMIN_TIMELOCK` cooldown after an unpause, when only the owner threshold can pause), and the owner threshold can revoke ADMIN approvals; the owner threshold triggers the emergency revocation path (`Active` → `Revoked` after `EMERGENCY_ROTATION_TIMELOCK`, then fresh registration — quantum-key-registry.md). Rotation is not available: it needs an XMSS proof by the old key, which is on the stolen device. ADMIN-class actions are additionally time-locked.

**The exception to "owners still control execution":** a Safe with an enabled module. `checkModuleTransaction` runs the same dispatch and consumes a matching approval with **no owner signatures at all** — `execTransactionFromModule` checks only that the module is enabled. On that path the thief's spending power is bounded by whatever the module will do on a valid approval, not by the threshold, and that includes ADMIN-class approvals. Enabling a module took owner threshold + XMSS + `ADMIN_TIMELOCK`, so the owners consented; what they consented to is worth re-reading. A single owner's `pauseSafe` blocks the module path outright.

**Residual risk:** window between theft and revocation for TRANSFER-class approvals *that owners then also sign*. A stolen Ledger alone moves nothing — it removes only the quantum layer, leaving classical multisig intact. And the mirror case, which A3 now makes sharper: a wiped or destroyed device is permanent key loss, because the XMSS seed was generated inside the secure element and is not in the recovery phrase. The only remedy is owner-threshold `requestKeyRevocation`, 14 days, and a fresh registration; rotation can never recover it, since rotation needs the key that is gone.

### 2.5 Rogue Quantum Administrator

**Capabilities:** legitimate device, legitimate key, insider knowledge.

**Attacks:** approve transfers to self — but the Administrator cannot execute: owner threshold still required, with the same enabled-module exception as §2.4. Sabotage: refuse to sign (liveness), burn leaves, revoke pending approvals (including ADMIN ones), or pause the Safe. Pausing is bounded: unpausing takes the owners `ADMIN_TIMELOCK`, after which the Administrator cannot pause again for another `ADMIN_TIMELOCK`, so it can keep the Safe paused at most about half the time. Escape calls, including the emergency de-guard, keep working while paused. Attempt self-serving ADMIN approvals (e.g., de-guard) — publicly evented + `ADMIN_TIMELOCK`; owners cancel.

**What stops them:** the Administrator is deliberately **not** a spending authority — the design is two independent authorization layers, and this adversary holds exactly one.

**Residual risk:** liveness. Mitigation: emergency de-guard exists precisely so a striking Administrator cannot hold funds hostage beyond 14 days.

### 2.6 Compromised minority of owners (below threshold)

Cannot reach threshold; cannot touch the quantum layer; can *initiate* the owners-only de-guard only if threshold is met — which it is not. **Contained by the Safe's own model.** One compromised owner in a ceremony can refuse to sign (abort — nonce bump) but not substitute anything. What one owner *can* do is grief: `pauseSafe` freezes the Safe instantly, and `revokePreApproval` kills any live TRANSFER or PAYLOAD approval, burning its leaf. Both are bounded by design — the threshold unpauses after `ADMIN_TIMELOCK` and then holds a cooldown during which no single key may re-pause, and a lone owner may not revoke the ADMIN approval that removes them.

### 2.7 Colluding owner threshold (or quantum forgery of it — same thing)

**Capabilities:** everything the Safe can classically do.

**What stops them:** nothing permanently — **by design** (no-brick invariant: owners must always be able to eventually exit). The Guard converts "instant drain" into "14-day public, cancellable process": ADMIN pre-approvals need the Administrator's XMSS key, so the colluders' paths are the owners-only emergency de-guard and the emergency key revocation followed by registering their own key. Both are time-locked by 14 days and loudly evented. Only an owner-threshold Safe transaction can cancel it, so against a colluding threshold nothing on-chain stops it — the 14 days buy detection and off-chain response, not a veto. The Administrator deliberately has no cancel power: a stolen Ledger must never be able to block the owners' exit.

**Residual risk:** if the collusion includes suppressing every watcher for 14 days, funds move. This is the accepted floor of the design; the timelock trades brick-risk for a detection window.

### 2.8 Owner threshold + Administrator collusion

Total compromise: both layers cooperate, funds move immediately and "legitimately". Out of scope — no on-chain system survives the collusion of all its authorization roles. Organizational control: separate the Administrator from owner governance (different people, different reporting lines).

### 2.9 Network-level adversary (mempool, RPC, relayer)

- **Front-running `registerQuantumKey`/`rotateQuantumKey`:** signatures bind `safe`, `chainid`, `registryNonce` — a copied transaction executes identically or reverts on the bumped nonce; nothing redirectable.
- **Claiming a Safe's key slot before the Safe exists:** `registerQuantumKey` is permissionless and takes `safe` as calldata, and the only thing authenticating that address is the Safe's own `checkSignatures`. A Safe's address is knowable long before deployment (`createProxyWithNonce` is CREATE2). A registration against a codeless address would make the attacker `quantumAdmin` of a Safe that does not exist, block the real owners with `SafeAlreadyEnrolled`, and close §2.1's no-timelock detach — for one transaction of gas. It reverts, but **not because of a check anyone wrote**: `ISafeLegacySignatures.checkSignatures` has no return values, so solc keeps the `extcodesize` guard it elides for calls whose returndata gets decoded, and the call reverts before any signature logic runs. Give that interface a return value, wrap it in `try`/`catch`, or lower it to a raw `call`, and squatting opens with the suite still green. `contracts/test/PreDeploymentSafe.t.sol` (`a86a532`) is what holds it now; the property it pins is that the address is left **unenrolled** — the damage would not be the failed call, it is the sticky flag a successful one leaves behind.
- **Front-running `createPreApproval`:** a front-runner who submits the same calldata first creates exactly the approval the Administrator signed, for the same Safe; any second submission reverts (`ApprovalExists` — the ID is `keccak256(safe, nonce)` — and the XMSS leaf is already used). An attacker paying our gas is a gift.
- **Censorship (RPC/relayer/builder):** liveness only; validity windows may lapse and burn leaves (~1M budget absorbs this); nonce-order discipline in the queue limits cascade.
- **Reorgs:** leaf bitmap writes finalize with the chain; the service resyncs from chain before any advisory decision; "fail toward waste, never toward reuse."

### 2.10 Malicious ERC-20 / callback reentrancy

A token with hostile transfer hooks executes *after* the Guard's checks with the approval already consumed. The Guard keeps a transient per-Safe depth counter, so a hook that re-enters the same Safe's `execTransaction` reverts (`NestedSafeTransaction`); `checkAfterExecution` closes the frame; approvals are exact-payload bound so nothing new can be smuggled mid-call. The first line is not an allowlist: a TRANSFER approval binds the token address, recipient and amount, so the hostile token can only be one the Administrator already reviewed and signed for, and `approve`/`transferFrom`/`increaseAllowance`/`permit` sit on a hardcoded deny-list that no governance action can re-enable — enforced on the direct path and on every batch leg. The token allowlist of `fermionguardspec.md` is off-chain policy, unbuilt, and defence in depth rather than the control that holds.

---

## 3. Trust-boundary summary

| Component compromised | Funds at risk? | Worst outcome | Recovery |
|---|---|---|---|
| Backend service (total) | No | Liveness loss, blind watcher | Redeploy; keys unaffected |
| Frontend / Safe App | No | Phished ceremony **if** owners skip device review | Abort ceremony, bump nonce |
| Relayer EOA | No | Lost gas funds (< 2 ETH policy) | Rotate relayer key |
| Administrator's Ledger (no PIN) | No | Device wiped after 3 attempts — and the XMSS key with it (A3) | Owner-threshold revocation (14 d), then fresh registration. Rotation cannot: it needs the key the wipe destroyed |
| Administrator's Ledger + PIN | No (alone) | Quantum layer nullified until revocation; unbounded on an enabled-module Safe (§2.4) | Revoke + re-register |
| One owner key | No | Pause + approval revocation griefing, bounded (§2.6) | Owner rotation via Safe |
| Guard attached, **no key registered** | **Yes, immediately** | Forged owner signatures detach the Guard with no timelock (§2.1) | None needed and none available — register the key in the same session as the attach |
| Our XMSS verifier (A7) | Not alone; **yes** together with §2.1 | XMSS half forgeable | New Guard deployment (non-upgradeable by design) |
| Owner threshold (incl. quantum forgery) | **After 14 d** | De-guard (or key revocation + own key) then drain, unless cancelled | Honest owners cancel in window (owner-threshold Safe tx, `gasPrice == 0`); the Administrator cannot |
| Owners + Administrator | Yes, immediately | Total | None (by definition) |
| SHA-256 | Yes | XMSS forgery | None — rotate the planet |

The system's invariant, stated once: **for a Safe with a registered key, no single compromised component — including a quantum computer holding every ECDSA key — moves funds without either the Administrator's physical Ledger or a 14-day public countdown.** The qualifier is load-bearing. Before registration there is no invariant, only a Guard that freezes the Safe and can be detached at will.

---

## 4. Quantum timeline rationale

Why hybrid now: Safe owners keep signing with ECDSA, so a quantum attacker can always *propose and co-sign* — the product's claim is narrower and honest: quantum forgery of classical signatures grants **zero spending power** because execution is gated on an XMSS-authorized pre-approval (hash-based, Grover-only degradation, 128-bit post-quantum). The classical half of the hybrid is not a security layer against quantum adversaries at all — it is a *hardware human-in-the-loop* anchor against host compromise. Each half covers the other's blind spot; that is the entire design.

**How far the verifier's proof reaches (A7).** The XMSS library is machine-checked against an executable transcription of RFC 8391 by symbolic execution in Halmos, over all inputs: the primitives — `chain`, `randHash`, the base-w message and checksum encoding, `ltree`, `climbStep`, `hMsg` — for equality with the RFC's algorithms; the tree-index loop invariant and the shared scratch buffer's freedom from cross-call contamination as properties in their own right; and `verify`'s input-validation rejections (zero root or SEED, h = 0 or h > 20, a leaf index ≥ 2^h, and a signature that does not carry exactly the registered number of authentication nodes). The step that decides whether a **well-formed** signature is accepted — that composing those primitives reproduces Algorithm 13's root computation at a general height — is a hand argument, checked symbolically only at h = 2 with a fixed message, plus reference vectors at h = 4, 10 and 20. SHA-256 is an uninterpreted function throughout, so none of it says anything about SHA-256 (that is A1), and key generation and signing are neither specified nor proven. See the library's `PROOF.md`. The registry uses the height-binding `verify(M, sig, pk, treeHeight)` form and independently compares the authentication path's length against the height stored for the key, so the caller-chooses-the-height hazard of the three-argument form does not apply here.

---

## 5. Open items

**The watcher role (under-specified).** Assumption A5 and the residual risks in §2.1/§2.7 all lean on watchers who observe `AdminPreApprovalCreated`, de-guard initiations (`EmergencyDeGuardRequested`), key-revocation requests (`KeyRevocationRequested`), and rotation events, and can escalate or cancel within the timelock. Not yet specified: who runs watchers (self-hosted daemon? third-party watchtower network?), redundancy requirements (N independent operators, at least one outside the backend's blast radius), alert transport diversity (the backend must not be the single alert channel), authorized cancellers per event type, and response-time SLA versus the 48 h / 14 d windows. **This needs its own spec (`watcher-service.md`) before the timelock numbers can be defended.**

**And the mitigations above that are not built yet.** Three of them are specification rather than code: the ceremony's device-side review (§2.3 — `SIGN_KEY_ATTESTATION` and `SIGN_ROTATION` do not exist in the app), the add-on service's detection controls (§2.2 — desync alarm, policy engine, alert transport), and the watchers themselves. None of the three guards funds; all three guard against *signing the wrong thing* and against *not noticing in time*. The on-chain layer holds without them. The human layer does not, and every 14-day window in this document is a bet on the human layer.

---

## 6. Out of scope: FermionWallet

[fermionwallet.md](./fermionwallet.md) specifies a second product — one contract, one immutable key, no Safe and no registry — and it is specification only; no contract is implemented. This document does not cover it, and the reason is structural rather than editorial: that wallet's used-leaf bitmap lives in the wallet contract and can only see leaves that wallet spent, so "one leaf, one digest" has no on-chain backstop across contracts at all. The device's per-slot binding to one verifying contract on one chain is the only thing enforcing it (FWL-023, implemented in `ledger-app/src/wallet.rs`), and a rolled-back or cloned device — precisely what a backstop exists to distrust — defeats it with nothing on-chain to notice (FWL-025); the optional shared `LeafRegistry` (FWL-026) is what restores the property, and it is not the default. FermionGuard's registry does have that backstop, keyed by the root. Read that document's own "What can go wrong" table; do not read this one as covering it.
