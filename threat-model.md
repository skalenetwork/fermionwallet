# Threat Model — Adversary Analysis

This document defines who FermionWallet defends against, what each adversary can and cannot achieve, and which spec mechanism stops them. Every security claim elsewhere in the suite should trace back to a row here.

**System recap (one paragraph).** A Gnosis Safe holds the funds. The FermionWalletGuard (non-upgradeable singleton) sits on `checkTransaction` and refuses any execution that lacks a live on-chain pre-approval. Pre-approvals are created by `createPreApproval`, which verifies **two signatures over the same EIP-712 digest**: an ECDSA half against the registered `quantumAdmin` (the Administrator's Ledger EOA) and an XMSS half (RFC 8391, SHA-256) against the registered `xmssRoot`, with single-use leaf enforcement in an on-chain bitmap. Both halves come from the same physical Ledger (FermionWallet XMSS app); the backend holds no keys. Escape hatches: ADMIN-class pre-approvals under `ADMIN_TIMELOCK`, and a quantum-key-independent emergency de-guard (48 h public / 14 d owners-only).

---

## 1. Security assumptions

| # | Assumption | If it falls |
|---|---|---|
| A1 | SHA-256 (second-)preimage resistance holds, classically and against quantum adversaries (Grover halves bits: 128-bit quantum preimage security) | XMSS forgeable → entire quantum layer void |
| A2 | ECDSA/secp256k1 **may fail at any time** (cryptographically relevant quantum computer, or key theft) | This is the design premise, not a failure — see §2.1 |
| A3 | The Ledger ST33 secure element resists physical extraction and enforces PIN + counter monotonicity | Stolen device becomes a signing oracle — see §2.4 |
| A4 | Ethereum consensus and the Safe v1.4.1 contracts behave as specified | Out of scope; inherited risk |
| A5 | At least one honest, online watcher observes Guard events within the shortest timelock window | Timelocked attacks (§2.5, §2.7) can complete unobserved |
| A6 | Safe owners' hardware wallets display EIP-712 fields truthfully | Ceremony co-signatures can be phished |

A5 is the softest assumption in the system. The watcher role is currently under-specified; see §5.

---

## 2. Adversary catalog

Each adversary: capabilities → attack → what stops them → residual risk.

### 2.1 Quantum-capable attacker (the headline adversary)

**Capabilities:** recovers any secp256k1/ECDSA private key from its public key or signatures. That includes: every Safe owner key, the Administrator's `quantumAdmin` EOA, the relayer, and any EIP-712 signature ever published. Cannot invert SHA-256 (A1), so cannot forge XMSS.

**Attack:** forge owner signatures → `execTransaction` with threshold "owner" approval → drain.

**What stops them:** the Guard. Execution requires a pre-approval whose creation required a valid **XMSS** signature over the exact payload. The attacker can mint the ECDSA half of a pre-approval but not the XMSS half; `createPreApproval` reverts. Forged owner signatures get the attacker into `checkTransaction`, which finds no matching approval and reverts.

**Attack, escalated:** forge owner signatures to call `setGuard(0)` and remove the Guard. Blocked: admin self-calls need an ADMIN-class pre-approval (XMSS-signed) plus `ADMIN_TIMELOCK`. The owners-only emergency de-guard path is also signature-gated but additionally time-locked 14 days and loudly evented — the legitimate Administrator rotates/pauses within the window (assumption A5).

**Residual risk:** a quantum attacker who **also** controls or destroys all watchers can ride the 14-day owners-only de-guard to completion. Mitigation: watcher redundancy (§5) and the Administrator's pause.

### 2.2 Compromised backend / add-on service

**Capabilities:** full control of the Node.js service — queue, policy engine, ceremony coordinator, relayer key, WebSocket feeds. Holds **zero key material** (Ledger-only architecture).

**Attacks & outcomes:**
- *Mint pre-approvals autonomously* — impossible: both signature halves come from the Ledger secure element; the service only relays.
- *Present a lying payload for signature* — the Ledger renders token/recipient/amount/leaf on its own screen from the streamed payload; the Administrator's review is the control. Residual: human inattention (see §3, UX mitigations: ceremony words, no raw-hash path).
- *Grief via relayer* — withhold `createPreApproval` submissions (liveness attack, not safety), or burn relayer gas. Funds never move.
- *Desync leaf mirror* — advisory only; chain bitmap is authoritative; desync alarm pages the Administrator (pre-approval-engine.md).
- *Suppress alerts / act as a blind watcher* — this is the real damage: see A5/§5.

**Verdict:** total backend compromise is a **liveness** problem plus an alerting problem, never a fund-safety problem.

### 2.3 Malicious frontend (Safe App / ceremony UI)

**Capabilities:** renders anything, swaps parameters in flight, initiates rogue ceremonies.

**Attacks:** substitute an attacker's `xmssRoot` or `quantumAdmin` during a ceremony; present a rotation as a routine approval; misdescribe a transfer.

**What stops them:** owners clear-sign `ApproveQuantumKey{safe, quantumAdmin, xmssRoot, …, registryNonce}` on their **own hardware** — a swapped root or admin address invalidates every signature; ceremony words are compared out-of-band; the Ledger flow headers distinguish `Register key` / `Sign approval` / `Rotate key` on-device; `registryNonce` kills stale/aborted sessions; `SIGN_ROTATION` shows the abandoned-leaf count.

**Residual risk:** owners who don't actually read their device screens (A6). This is a procedural control, deliberately made cheap (6 BIP-39 words, not hex).

### 2.4 Thief with the Administrator's Ledger

**Capabilities:** physical device. Without the PIN: 3 attempts, then the device wipes (zeroization). With the PIN (coerced/observed): a full signing oracle for both hybrid halves.

**What stops them (PIN known):** the thief can create pre-approvals, but every creation is a public on-chain event with the target fields visible; owners still control execution (threshold signatures) and any owner can revoke; the Administrator's organization triggers the emergency revocation path (`Active` → `Revoked` under governance timelock, then fresh registration — quantum-key-registry.md). ADMIN-class actions are additionally time-locked.

**Residual risk:** window between theft and revocation for TRANSFER-class approvals *that owners then also sign*. A stolen Ledger alone moves nothing — it removes only the quantum layer, leaving classical multisig intact. Detection: any pre-approval the service didn't orchestrate is a desync alarm.

### 2.5 Rogue Quantum Administrator

**Capabilities:** legitimate device, legitimate key, insider knowledge.

**Attacks:** approve transfers to self — but the Administrator cannot execute: owner threshold still required. Sabotage: refuse to sign (liveness), or burn leaves. Attempt self-serving ADMIN approvals (e.g., de-guard) — publicly evented + `ADMIN_TIMELOCK`; owners cancel.

**What stops them:** the Administrator is deliberately **not** a spending authority — the design is two independent authorization layers, and this adversary holds exactly one.

**Residual risk:** liveness. Mitigation: emergency de-guard exists precisely so a striking Administrator cannot hold funds hostage beyond 14 days.

### 2.6 Compromised minority of owners (below threshold)

Can propose transactions and spam signatures; cannot reach threshold; cannot touch the quantum layer; can *initiate* the owners-only de-guard only if threshold is met — which it is not. **Contained by the Safe's own model.** One compromised owner in a ceremony can refuse to sign (abort — nonce bump) but not substitute anything.

### 2.7 Colluding owner threshold (or quantum forgery of it — same thing)

**Capabilities:** everything the Safe can classically do.

**What stops them:** nothing permanently — **by design** (no-brick invariant: owners must always be able to eventually exit). The Guard converts "instant drain" into "14-day public, cancellable process": ADMIN pre-approvals need the Administrator's XMSS key, so the colluders' path is the owners-only emergency de-guard — time-locked, loudly evented, cancellable by the Administrator/watchers during the window.

**Residual risk:** if the collusion includes suppressing every watcher for 14 days, funds move. This is the accepted floor of the design; the timelock trades brick-risk for a detection window.

### 2.8 Owner threshold + Administrator collusion

Total compromise: both layers cooperate, funds move immediately and "legitimately". Out of scope — no on-chain system survives the collusion of all its authorization roles. Organizational control: separate the Administrator from owner governance (different people, different reporting lines).

### 2.9 Network-level adversary (mempool, RPC, relayer)

- **Front-running `registerQuantumKey`/`rotateQuantumKey`:** signatures bind `safe`, `chainid`, `registryNonce` — a copied transaction executes identically or reverts on the bumped nonce; nothing redirectable.
- **Front-running `createPreApproval`:** replaying it creates the same approval for the same Safe (idempotent by commitment/txHash); an attacker paying our gas is a gift.
- **Censorship (RPC/relayer/builder):** liveness only; validity windows may lapse and burn leaves (~1M budget absorbs this); nonce-order discipline in the queue limits cascade.
- **Reorgs:** leaf bitmap writes finalize with the chain; the service resyncs from chain before any advisory decision; "fail toward waste, never toward reuse."

### 2.10 Malicious ERC-20 / callback reentrancy

A token with hostile transfer hooks executes *after* the Guard's checks with the approval already consumed. The Guard uses transient reentrancy locks; `checkAfterExecution` closes the frame; approvals are exact-payload bound so nothing new can be smuggled mid-call. Policy allowlisting of tokens is the first-line control.

---

## 3. Trust-boundary summary

| Component compromised | Funds at risk? | Worst outcome | Recovery |
|---|---|---|---|
| Backend service (total) | No | Liveness loss, blind watcher | Redeploy; keys unaffected |
| Frontend / Safe App | No | Phished ceremony **if** owners skip device review | Abort ceremony, bump nonce |
| Relayer EOA | No | Lost gas funds (< 2 ETH policy) | Rotate relayer key |
| Administrator's Ledger (no PIN) | No | Device wiped after 3 attempts | Emergency rotation, new device |
| Administrator's Ledger + PIN | No (alone) | Quantum layer nullified until revocation | Revoke + re-register |
| One owner key | No | Noise | Owner rotation via Safe |
| Owner threshold (incl. quantum forgery) | **After 14 d** | De-guard then drain, unless cancelled | Watchers/Administrator cancel in window |
| Owners + Administrator | Yes, immediately | Total | None (by definition) |
| SHA-256 | Yes | XMSS forgery | None — rotate the planet |

The system's invariant, stated once: **no single compromised component — including a quantum computer holding every ECDSA key — moves funds without either the Administrator's physical Ledger or a 14-day public countdown.**

---

## 4. Quantum timeline rationale

Why hybrid now: Safe owners keep signing with ECDSA, so a quantum attacker can always *propose and co-sign* — the product's claim is narrower and honest: quantum forgery of classical signatures grants **zero spending power** because execution is gated on an XMSS-authorized pre-approval (hash-based, Grover-only degradation, 128-bit post-quantum). The classical half of the hybrid is not a security layer against quantum adversaries at all — it is a *hardware human-in-the-loop* anchor against host compromise. Each half covers the other's blind spot; that is the entire design.

---

## 5. Open item: the Watcher role (under-specified)

Assumptions A5 and the residual risks in §2.1/§2.7 all lean on watchers who observe `AdminPreApprovalCreated`, de-guard initiations, and rotation events, and can escalate or cancel within the timelock. Not yet specified: who runs watchers (self-hosted daemon? third-party watchtower network?), redundancy requirements (N independent operators, at least one outside the backend's blast radius), alert transport diversity (the backend must not be the single alert channel), authorized cancellers per event type, and response-time SLA versus the 48 h / 14 d windows. **This needs its own spec (`watcher-service.md`) before the timelock numbers can be defended.**
