# Fermion security: threat model, key custody, residual risks

This document says who Fermion defends against, which control stops each adversary, how
keys must be held, and what is left over. It covers both products, Fermion Wallet and
Fermion Guard, and the one Ledger app ("Fermion") that signs for both. Every security
claim in the other v2 documents should trace back to a row here.

**Status: unaudited.** The contracts, the ML-DSA verifier, the key factory and the Ledger
app have had no external audit, and none is planned before the first release (see
[release gates](./release.md#release-gates)). Nothing is deployed on a public network.
Do not put real funds behind any of it.

How to report a vulnerability: [`SECURITY.md`](../SECURITY.md).

## Contents

1. [System recap](#system-recap)
2. [Assumptions](#assumptions)
3. [Adversaries](#adversaries)
4. [Trust-boundary summary](#trust-boundary-summary)
5. [Key custody and hardware policy](#key-custody-and-hardware-policy)
6. [Residual risks](#residual-risks)

---

## System recap

Every authority in Fermion is a **hybrid signature**: an ECDSA (secp256k1) signature and an
ML-DSA signature (FIPS 204, pure, empty context) over the **same 32-byte EIP-712 digest**.
The contract accepts only when both verify
([hybrid signature](./fermion-wallet.md#hybrid-signature), [digest](./signer-requirements.md#digest)).

- **Fermion Wallet** is a post-quantum cold vault. It holds anything and sends ETH, ERC-20,
  ERC-721 and ERC-1155 (up to 8 legs per signature) only against a hybrid signature. It has
  no owners, no approve, no arbitrary call and no modules. It can also answer ERC-1271 as a
  Safe owner ([Safe owner](./fermion-wallet.md#safe-owner-erc-1271)).
- **Fermion Guard** is a Safe guard. Every Safe transaction needs a quantum approval from the
  Safe's one Quantum Administrator, in addition to the owners' threshold
  ([quantum approval](./fermion-guard.md#quantum-approval)). The only exceptions are the
  emergency-removal calls ([emergency removal](./fermion-guard.md#emergency-removal)).

The ECDSA half's key must be an EOA; it is checked only by ECDSA recovery. ERC-1271 appears
only inbound (the wallet answering as a Safe owner), never as a way to check the admin.

Both halves of every key come from the recovery phrase, one key per contract
([key derivation](./ledger-app.md#key-derivation)). ML-DSA is stateless, so there is no
signature counter to protect and no state to roll back.

Replay is stopped by a sequential nonce and a validity window in every signed struct:
`validFrom <= block.timestamp <= validUntil` and `validUntil - validFrom <= 24h`, checked on
chain ([replay and validity window](./fermion-wallet.md#replay-and-validity-window)).

## Assumptions

| # | Assumption | If it falls |
|---|---|---|
| A1 | ML-DSA (FIPS 204) is unforgeable, classically and against quantum adversaries, at the parameter set in use (44, 65 or 87) | The post-quantum half is void. Against a quantum attacker, everything is void |
| A2 | ECDSA/secp256k1 **may fail at any time**, to a quantum computer or to key theft | This is the design premise, not a failure. See [quantum attacker](#quantum-attacker-on-ecdsa) |
| A3 | The Ledger secure element resists physical key extraction and enforces its PIN | A stolen device becomes a signing oracle ([stolen device](#stolen-device)) |
| A4 | The Ledger SDK's ML-DSA does not leak the key through side channels | **Not established.** Ledger's SDK documents no side-channel hardening for ML-DSA; Fermion treats it as unhardened ([residual risks](#residual-risks)) |
| A5 | The deployed ML-DSA verifier computes exactly FIPS 204 verification | The ML-DSA half may be forgeable ([buggy verifier](#buggy-verifier)). Unaudited; the machine-checked equivalence proof is planned, not done |
| A6 | Ethereum consensus and the Safe contracts (1.3.0, 1.4.1, 1.5.0) behave as specified | Out of scope; inherited |
| A7 | The signer shows the human exactly what it signs, and the human reads it | Phishing by a host or UI ([compromised host](#compromised-host)) |
| A8 | At least one honest owner of a guarded Safe notices an emergency-removal request within its 14-day timelock | A removal requested by compromised owners completes unopposed ([compromised owners](#compromised-owners-case-1)) |
| A9 | The recovery phrase (and passphrase, if set) is known only to its holder | Total compromise of every key derived from it ([stolen phrase](#stolen-phrase)) |

A4 and A5 are the soft ones. Both are stated as residual risks rather than hidden.

---

## Adversaries

Each entry: what the adversary can do, what they try, what stops them, and what is left.

### Quantum attacker on ECDSA

**Can:** recover any secp256k1 private key from its public key. That covers every Safe owner
key, every relayer key, and the ECDSA half of every Fermion key once its public key has been
seen on chain. Cannot forge ML-DSA (A1).

**Tries:** sign a wallet transfer; forge the Safe owners' signatures; forge a quantum
approval; derive the ML-DSA key from the broken ECDSA key.

**Stopped by:**

- *Wallet transfers.* The wallet requires both halves. The attacker can produce the ECDSA
  half and not the ML-DSA half, so the transfer reverts.
- *Safe transactions.* Forged owner signatures reach the Guard, which finds no valid
  quantum approval and reverts. Removing the Guard with `setGuard` is itself a Safe
  transaction and needs a quantum approval like any other.
- *The key derivation.* The ECDSA key and the ML-DSA seed come from two separate hardened
  children of one node: the ECDSA key is child `0'` and the ML-DSA seed is
  `SHA-256(label ‖ private key of child 1')`. Breaking child `0'` reveals nothing about
  child `1'` or the parent ([key derivation](./ledger-app.md#key-derivation)). Deriving the
  ML-DSA seed from the ECDSA key's own node would let a quantum break of the classical half
  yield the post-quantum key, and is forbidden.
- *Emergency removal.* An attacker who forges the owner threshold can request emergency
  removal. That starts a public 14-day timelock, during which the Safe is frozen and the
  honest owners cancel ([emergency removal](./fermion-guard.md#emergency-removal)). A
  quantum attacker forges signatures; it does not take keys away from the honest owners, so
  this is case 1 below.

**Left over:** the attacker can grief by repeating removal requests; each one freezes the
Safe until cancelled. During a freeze the honest owners and the Quantum Administrator can
still move funds out with rescue transfers. The ECDSA half adds nothing against this
adversary: against a quantum attacker the ML-DSA half alone is the security.

### Compromised host

**Can:** fully control the computer, browser, SDK, RPC endpoint or Ledger Live instance that
talks to the device. Can show anything on screen, change any field before it reaches the
device, lie about chain state, and supply any time.

**Tries:** get a signature over a different transfer, a different Safe transaction, a longer
validity window, or a bare hash.

**Stopped by:**

- The device never signs a hash from the host. It receives the fields, shows them, and
  computes the digest itself from what it showed ([signing flows](./ledger-app.md#signing-flows),
  [display and refusal rules](./signer-requirements.md#display-and-refusal-rules)).
- The device refuses, before any screen, a Safe transaction with `operation` other than
  Call, non-zero `gasPrice`, `gasToken` or `refundReceiver`, or an unlimited token approval
  ([acceptance rules](./ledger-app.md#acceptance-rules)).
- The device refuses a validity window longer than 24 hours and shows both times in UTC. It
  has no trusted clock, so it cannot check that the window is current; the contract does.
- Keys never leave the device. A compromised host cannot sign without a human pressing the
  buttons.

**Left over:** the human must read the screens. A call the device cannot decode (no
Ledger-signed ERC-7730 descriptor) is **allowed after a strong warning** showing the target,
selector, value and full calldata with its hash. A user who accepts that warning on a
compromised host can sign anything a call can do, short of the hard refusals above. The host
can also withhold or delay signatures (liveness only).

### Phishing UI

**Can:** run a look-alike website, Safe App, Ledger Live app or device app; send links by
email or chat.

**Tries:** get the recovery phrase typed into a page; get a malicious device app installed;
get a signature over something misdescribed.

**Stopped by:**

- **No Fermion UI ever has a recovery-phrase field.** Restore happens only on the device. Any
  page that asks for the phrase is an attack, without exception.
- The device app is installed from the **Ledger Live catalog only**. A device app that Ledger
  OS allows to use Fermion's derivation path can derive the ML-DSA key, so a sideloaded or
  look-alike app is a key-theft tool.
- The web UI moves to a dedicated domain before mainnet. The github.io pages are previews
  only: they share an origin, and so WebHID permission and storage, with every other page
  under the same organisation.
- Misdescribed transactions are stopped by the device, as for a compromised host.

**Left over:** a user who types the phrase into a phishing page anyway has lost everything
derived from it. No control in Fermion can stop that after the fact.

### Compromised owners (case 1)

**Case 1** is the only owner-compromise case Fermion's threat model covers: some Safe owners
are compromised (or their signatures are forged), and the honest owners still hold working
keys.

**Can:** sign anything the compromised owners' keys can sign; reach the threshold.

**Tries:** move funds; remove the Guard; swap out the honest owners; burn the Safe nonce to
stop honest transactions.

**Stopped by:**

- Every Safe transaction, including owner changes and `setGuard`, needs a quantum approval.
  Owners alone move nothing.
- Emergency removal is the owners' only path that skips the quantum approval. It has a
  14-day timelock, and **only owners can cancel** it. The Quantum Administrator has no veto,
  so a lost or rogue device cannot hold the Safe hostage.
- While a removal is pending the Safe is **frozen** except for: cancel, the final removal
  after the timelock, and rescue transfers out (ETH, ERC-20, ERC-721, ERC-1155, batched
  through MultiSendCallOnly) that carry both a quantum approval and the owner threshold. This
  stops nonce griefing during the window.
- The event watcher reports removal requests by email or webhook; the Safe App also shows
  them ([emergency removal](./fermion-guard.md#emergency-removal)).

**Left over:** see case 2 in [residual risks](#residual-risks). Case 1 also relies on A8: if
nobody notices the request for 14 days, the removal completes.

### Stolen phrase

**Can:** derive every key the phrase protects, both halves, for every wallet and Safe it was
used for. If a BIP-39 passphrase is set, the phrase alone yields nothing; the thief needs
both.

**Tries:** sign transfers from every wallet; sign quantum approvals for every Safe.

**Stopped by:**

- *Fermion Wallet:* nothing on chain. Whoever's transfer is included first wins (sequential
  nonce). The holder should immediately move every balance to a new wallet under a new phrase.
- *Fermion Guard:* the thief holds the Quantum Administrator key but not the owners' keys;
  owners still have to sign. The administrator should rotate to a key from a new phrase
  ([key rotation](./fermion-guard.md#key-rotation)); if that is not possible, the owners use
  emergency removal and re-enroll with a new key.
- Rotation also bumps the key epoch, which kills every stored approval signed by the old key
  ([inline and stored approvals](./fermion-guard.md#inline-and-stored-approvals)).

**Left over:** for the wallet, a stolen phrase is a race the holder may lose. This is the
price of making the key recoverable; see [key custody](#key-custody-and-hardware-policy).

### Stolen device

**Can:** hold the physical device. Without the PIN, Ledger OS wipes the device after three
wrong attempts. With the PIN (watched or coerced), the device is a signing oracle for both
halves of every key on the phrase.

**Stopped by:**

- Without the PIN: nothing to stop; nothing is lost either. The keys are in the phrase, not
  only on the device. Restoring the phrase on a new device yields the same keys.
- With the PIN, *Fermion Guard:* the thief can make quantum approvals but cannot reach the
  owner threshold (case 1). The administrator restores the phrase on a new device and
  rotates away from the old key.
- With the PIN, *Fermion Wallet:* as for a stolen phrase. The holder restores the phrase on
  another device and moves the funds first.

**Left over:** a stolen device with its PIN is, for a Fermion Wallet, a race.

### Malicious relayer

**Can:** submit, delay, withhold or reorder transactions; see signed payloads before
inclusion.

**Stopped by:**

- `msg.sender` has no authority in either contract. The signed struct fixes every effect;
  a relayer can only submit it or not.
- No reimbursement. The wallet never pays a relayer from its balance, and the Guard path
  refuses Safe gas-refund fields, so there is nothing to drain through gas accounting.
- Front-running the same signed payload gives the same result; a second submission fails on
  the nonce.

**Left over:** liveness. A withheld transaction expires at `validUntil` and the user signs a
new one. The SDK's relayer interface is open, and the user's own EOA can always submit
([relayer interface](./sdk.md#relayer-interface)).

### Buggy verifier

**Can:** this is a defect, not a person. A verifier that accepts a forged ML-DSA signature,
or that rejects a valid one.

**Effects:**

- *Accepts forgeries:* the ML-DSA half is forgeable. A classical attacker is still stopped by
  the ECDSA half. A quantum attacker is not stopped at all.
- *Rejects valid signatures:* a Fermion Wallet cannot send, and has no other way out; its
  funds are stuck. A guarded Safe cannot get approvals; the owners use emergency removal.
- *Precomputed data out of step with the key:* the key factory computes its per-key data from
  the public key itself, never from caller input, and addresses it by the key's hash. A key
  with no precomputed data falls back to full verification.

**Mitigated by:** the verifier address is fixed at deployment, so nobody can switch a deployed
wallet or Safe to a different verifier. Moving to a fixed verifier means a new wallet (a
signed transfer) or re-enrollment. Differential testing against independent ML-DSA
implementations (AWS-LC, ZKNox) and a machine-checked proof of equivalence with FIPS 204 are
release work ([release gates](./release.md#release-gates)); the proof is not done.

**Left over:** until the proof exists and someone reviews it, A5 is an assumption.

---

## Trust-boundary summary

| Component compromised | Funds at risk? | Worst outcome | Recovery |
|---|---|---|---|
| ECDSA (quantum) | No | Grief by repeated removal requests on a guarded Safe | Owners cancel; rescue transfers |
| Host, browser, SDK, RPC | No, unless the human approves a warning screen | Signature over an undecodable call the human accepted | Read the device screen; refuse warnings you did not expect |
| Phishing page that got the phrase | **Yes** | Total for that phrase | Wallet: race to move funds. Guard: rotate or emergency removal |
| Some owners, honest owners keep keys (case 1) | No | 14-day freeze | Owners cancel |
| Owner threshold held exclusively by the attacker (case 2) | **Yes, after 14 days** | Guard removed, then drained | None on chain (residual) |
| Phrase | **Yes** | Total for that phrase | As for phishing |
| Device, no PIN | No | Device wiped | Restore phrase on a new device |
| Device + PIN | Wallet: **yes**. Guard: no | Wallet: drain race. Guard: approvals only | Restore and move (wallet); restore and rotate (guard) |
| Relayer | No | Delay | Resubmit through any other relayer or own EOA |
| Verifier accepts forgeries | Not alone; **yes** with a quantum attacker | ML-DSA half void | New wallet or re-enrollment |
| Verifier rejects valid signatures | Wallet: **stuck**. Guard: no | Liveness | Guard: emergency removal. Wallet: none |
| Quantum Administrator + owner threshold, colluding | Yes | Total | None by definition |

The invariant, stated once: **no single compromised component, including a quantum computer
holding every ECDSA key, moves funds without the ML-DSA key of that wallet or Safe, except a
guarded Safe's owners after a 14-day public emergency removal they were free to cancel.**

---

## Key custody and hardware policy

### The phrase is the single secret

Both halves of every Fermion key derive from the recovery phrase. This is a deliberate change
from the XMSS design, where the post-quantum key was generated inside the device and could not
be recovered.

| | Consequence |
|---|---|
| Backup | The phrase is the backup. Restoring it on any supported Ledger yields the same keys, and that is safe: ML-DSA is stateless, so there is no counter to roll back |
| Device loss | Costs nothing if the phrase is safe |
| App uninstall | Costs nothing; reinstalling derives the same keys |
| Phrase compromise | Total compromise of both halves of every key derived from it |
| Phrase loss + device loss | A Fermion Wallet's funds are gone. A guarded Safe's owners use emergency removal |

So the controls that used to protect the device now protect the phrase.

### Rules

1. **No UI ever asks for the phrase.** No Fermion web page, Safe App, Ledger Live app or SDK
   function has a phrase field or accepts a phrase. Restore happens only on the device.
2. **Ledger Live catalog only.** The Fermion device app is installed from Ledger Live's
   catalog. A sideloaded build may be used only with test keys, never with a phrase that
   protects real funds. Any app allowed Fermion's derivation path can derive the key.
3. **BIP-39 passphrase: recommended, not required**, for both products. It protects against a
   stolen phrase backup. It is a second secret that can be lost: lose it and the keys are gone
   exactly as if the phrase were lost. Store it separately from the phrase.
4. **One key per contract.** Every wallet and every guarded Safe gets a fresh derivation slot,
   with its own ECDSA key and its own ML-DSA key. No admin address is shared between
   contracts. Each key pays its own precomputation at setup (see the
   [measured facts](./v2-decisions.md#measured-facts-cite-these-do-not-retype-from-memory)).
5. **Hardened derivation.** The path is `m/<purpose>'/60'/<slot>'/<role>'/<paramSet>'`, all
   hardened; the ECDSA key is its child `0'` and the ML-DSA seed comes from child `1'`
   ([key derivation](./ledger-app.md#key-derivation)). The purpose number (placeholder `204'`)
   must be confirmed unregistered before release.
6. **ECDSA half is an EOA.** Contracts refuse an admin address with code.
7. **Hedged signing.** The device signs ML-DSA with fresh randomness (FIPS 204 hedged mode).
   Deterministic signing exists only in test builds, which must never hold real keys.
8. **The device is the trusted display.** The signer rebuilds every digest from the fields it
   shows ([signer requirements](./signer-requirements.md#display-and-refusal-rules)). A signer
   that signs a host-supplied hash does not conform.

### Devices

| Device | v2 status |
|---|---|
| Nano S Plus | Supported. ML-DSA-44/65 keygen + sign peaks at 10,092 B of stack (with `mldsa_optimization`), leaving 6.6 KB spare (Speculos) |
| Nano X | Fits only without the XMSS code and with a 2,048-byte heap (Speculos). No physical device tested; emulator only |
| Stax, Flex | Target (NBGL UI); not yet measured |

Real-device tests run on Nano S Plus and Flex or Stax. The device app ships ML-DSA-44 and
ML-DSA-65 only.

### Other signers

The contracts check only the two signatures, so any signer that meets the
[signer requirements](./signer-requirements.md#key-generation-and-backup) can be a Quantum
Administrator or a wallet key. The [nShield signer](./nshield-signer.md) is a design document
only; it would back up through its own Security World rather than a phrase.

---

## Residual risks

Known risks that v2 does not close. Each one is a decision, not an oversight.

| # | Risk | Why it stays | What the user can do |
|---|---|---|---|
| R1 | **Case 2:** an attacker who holds the owner threshold exclusively (honest owners have no working keys) removes the Guard after 14 days and drains the Safe | No on-chain rule can tell the attacker from the owners. The alternatives (an administrator veto, a recovery address) would let a lost or rogue device freeze the Safe forever | Keep owner keys independent; run the event watcher |
| R2 | **ML-DSA-87 is contract-only.** The contracts accept it, but no v2 signer produces it: the Ledger app ships 44 and 65, and the nShield signer is a design document | The Ledger build with 87 does not fit on Nano X and raises stack use for 44/65 too | Use 44 or 65 |
| R3 | **The verifier, key factory and contracts are unaudited** | No audit gate for v2 (owner's decision). The FIPS 204 equivalence proof is planned, not done | Do not put real funds behind v2 until you are satisfied |
| R4 | **No documented side-channel hardening** for ML-DSA in Ledger's SDK | Ledger documents none; Fermion treats it as unhardened | Keep physical custody of the device |
| R5 | **Private SDK symbols.** Seeded keygen and signing use Ledger's private `MLDSA_internal_*` symbols; the SDK is pinned at v26.6.5 (`87def514`) | No public seeded API exists yet; Ledger has been asked for one | None; an SDK change can break the app until fixed |
| R6 | **L2 per-transaction cap and same-address deployment are unverified on live networks.** All pre-release testing is on local chains with the EIP-7825 cap (2^24 = 16,777,216 gas) emulated | No public testnet deployment before release | Release notes state this ([release](./release.md#local-chain-testing)) |
| R7 | **Gas headroom under the cap.** ML-DSA-87's first transfer when it also stores both A parts measures 16.30M, about 0.48M under the cap (derived); gas repricing (Glamsterdam, Q4 2026) may change every figure | Measured on today's schedule | For 87, store the A parts ahead. Figures are re-measured after repricing |
| R8 | **Existing EOAs cannot be made post-quantum.** An EOA's ECDSA key keeps its authority, even with an EIP-7702 delegation | Protocol property | Move funds to a new Fermion address; update exchange withdrawal allowlists |
| R9 | **Mainnet cost.** ML-DSA verification costs millions of gas per signature (2.68M for a registered ML-DSA-44 key); cheap on L2s, expensive on mainnet until an ML-DSA precompile ships | Protocol property | Prefer an L2 |
| R10 | **Undecodable calls are signable** after a strong warning (guard approvals and Safe-owner signatures) | Refusing them would block legitimate contracts with no Ledger-signed descriptor | Treat the warning as a stop sign unless you expected it |
| R11 | **The phrase is the single secret** behind both halves | Recoverability was chosen over device-bound keys | Passphrase; separate, offline phrase storage |
| R12 | **Formal device model lags the spec.** The committed model still refuses undecodable calls; the spec allows them after a warning | Model update is phase-3 work | None needed; the spec is normative |
| R13 | **Derivation purpose `204'` is a placeholder** | Not yet checked against SLIP-44/BIP-43 usage | Wait for release; keys derived under a different purpose are different keys |
