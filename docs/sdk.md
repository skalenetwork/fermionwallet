# fermion-sdk

The client library shared by the Fermion web UI, the Ledger Live app and the Safe App. npm
package name: **`fermion-sdk`**. It replaces the old JavaScript prototype in `src/`.

It builds every payload the device signs, talks to the device, assembles the signatures the
contracts expect, registers keys with the key factory, hands signed transactions to whoever
submits them, and caches ERC-7730 descriptors.

**Status: specification.** The library is built in phase 4 ([phases](./release.md#branch-and-phases)).
The shapes below are the contract between the SDK and its three callers; names may still change
before phase 4, the behaviour may not. Unaudited.

The SDK does not define message formats. The EIP-712 types and domains belong to
[Fermion Wallet](./fermion-wallet.md#signed-messages) and
[Fermion Guard](./fermion-guard.md#quantum-approval); the device protocol belongs to the
[Ledger app](./ledger-app.md#signing-flows). Where this document shows a field list, the owner
document's type string is canonical.

## Contents

1. [Rules](#rules)
2. [Common types](#common-types)
3. [Keys and slots](#keys-and-slots)
4. [Signed payloads](#signed-payloads)
5. [Device transport](#device-transport)
6. [Signature assembly](#signature-assembly)
7. [Stored approvals](#stored-approvals)
8. [Factory registration](#factory-registration)
9. [Relayer interface](#relayer-interface)
10. [ERC-7730 descriptors](#erc-7730-descriptors)
11. [Errors](#errors)

---

## Rules

1. **No recovery phrase, ever.** No function accepts, stores or transmits a recovery phrase or
   passphrase. There is no "import from phrase". Restore happens on the device.
2. **No bare hashes.** The SDK never asks the device to sign a hash. It sends the fields; the
   device shows them and computes the digest itself
   ([display and refusal rules](./signer-requirements.md#display-and-refusal-rules)). The SDK also
   computes every digest locally, to check the returned signature before using it.
3. **Check before submit.** Every signature the device returns is verified locally (ECDSA by
   recovery against the expected address, ML-DSA against the expected public key) before it is
   handed to a relayer.
4. **No authority in `msg.sender`.** The SDK never assumes the submitting account matters. Gas is
   paid by the user's own EOA by default, or by any relayer; the wallet never reimburses.
5. **No third-party code at run time.** Dependencies are pinned by lockfile; no script is loaded
   from a CDN.

## Common types

```ts
type Hex = `0x${string}`;
type Address = Hex;               // 20 bytes, checksummed on output
type Bytes32 = Hex;

type ParamSet = 44 | 65 | 87;     // ML-DSA-44 default; 65 opt-in; 87 contract-only (no Ledger signer)
type Product = "wallet" | "guard";

/** Algorithm ids from pq-verifier-interface (PQAlgorithms). Fermion accepts these three only. */
const ALGORITHM = { 44: 0x0101n, 65: 0x0102n, 87: 0x0103n } as const;

/** Every signed struct carries a validity window; the contracts require
 *  validFrom <= block.timestamp <= validUntil and validUntil - validFrom <= 24 h. */
interface ValidityWindow {
  validFrom: bigint;              // unix seconds
  validUntil: bigint;             // unix seconds
}
const MAX_WINDOW_SECONDS = 86_400n;

interface ChainContext {
  chainId: bigint;
  rpc: Eip1193Provider;           // user-chosen; read-only use, never trusted for what to sign
}
```

`window(durationSeconds, from?)` builds a `ValidityWindow` from the host clock and throws
`WindowTooLong` above 24 hours. The host clock is not trusted for safety; the contract enforces
the window ([replay and validity window](./fermion-wallet.md#replay-and-validity-window)).

## Keys and slots

Each wallet and each guarded Safe has its own key, at a fresh slot
([key derivation](./ledger-app.md#key-derivation)).

```ts
interface KeyRef {
  product: Product;               // role 0' = wallet, 1' = guard
  slot: number;                   // counts up per contract
  paramSet: 44 | 65;              // what the Ledger app can produce
}

interface PublicKeys {
  key: KeyRef;
  ecdsaAddress: Address;          // the EOA half
  mldsaPublicKey: Hex;            // 1312 B (44) or 1952 B (65)
  algorithm: bigint;              // ALGORITHM[paramSet]
}

/** m/<purpose>'/60'/<slot>'/<role>'/<paramSet>', all hardened. Purpose is a placeholder (204'). */
function derivationPath(key: KeyRef): string;

/** Read both public keys of a slot from the device. */
function getPublicKeys(device: FermionDevice, key: KeyRef): Promise<PublicKeys>;

/** Find used slots: walks slots upward, asking the device for each key and the chain for a
 *  wallet or enrollment at it, and stops after `gapLimit` consecutive unused slots. */
function scanSlots(
  device: FermionDevice, chain: ChainContext, product: Product, paramSet: 44 | 65,
  opts?: { gapLimit?: number }
): Promise<{ used: PublicKeys[]; nextFree: KeyRef }>;
```

The derivation does not encode which parameter set a slot was created with beyond the path
component, so `scanSlots` is called per set.

## Signed payloads

Builders return a `Payload`: the typed data the device will show and sign, plus the digest the
SDK expects back. The device receives the fields, not the digest.

```ts
interface Payload<T> {
  kind: PayloadKind;
  domain: Eip712Domain;           // canonical in the owner document
  message: T;
  digest: Bytes32;                // computed locally; the device recomputes it from what it shows
  key: KeyRef;
}

type PayloadKind =
  | "wallet.transfer" | "wallet.nftTransfer" | "wallet.batch"
  | "wallet.safeOwner" | "wallet.message"
  | "guard.approval" | "guard.moduleApproval"
  | "guard.revoke" | "guard.rotate";
```

### Fermion Wallet

Canonical types: [signed messages](./fermion-wallet.md#signed-messages).

```ts
interface TransferFields extends ValidityWindow {
  token: Address;                 // address(0) = native ETH
  to: Address;
  amount: bigint;
  nonce: bigint;                  // the wallet's sequential nonce
}

interface NftTransferFields extends ValidityWindow {
  standard: 721 | 1155;
  collection: Address;
  tokenId: bigint;
  amount: bigint;                 // 1155 only; 1 for 721
  to: Address;
  nonce: bigint;
}

type Leg =
  | ({ type: "token" } & Omit<TransferFields, "nonce" | "validFrom" | "validUntil">)
  | ({ type: "nft" } & Omit<NftTransferFields, "nonce" | "validFrom" | "validUntil">);

interface BatchFields extends ValidityWindow {
  legs: Leg[];                    // 1..8, executed atomically
  nonce: bigint;                  // one nonce for the batch
}

function buildTransfer(w: WalletRef, f: TransferFields): Payload<TransferFields>;
function buildNftTransfer(w: WalletRef, f: NftTransferFields): Payload<NftTransferFields>;
function buildBatch(w: WalletRef, f: BatchFields): Payload<BatchFields>;   // throws BatchTooLarge above 8

/** The wallet as a Safe owner: the SafeTx is wrapped in the wallet's own EIP-712 domain
 *  (SafeHash(bytes32 hash)), so the signature is bound to this wallet. */
function buildSafeOwnerSignature(
  w: WalletRef, safe: Address, safeTx: SafeTx
): Payload<{ hash: Bytes32; safeTx: SafeTx; safe: Address }>;

/** Plain-text message (SIWE, ownership proofs), shown in full on the device and wrapped in the
 *  wallet's domain. No arbitrary EIP-712, no permits. */
function buildMessage(w: WalletRef, text: string): Payload<{ text: string }>;

interface WalletRef { address: Address; chainId: bigint; key: KeyRef; paramSet: ParamSet }
```

Fields that both a wallet and a Safe-owner signature carry (`validFrom`, `validUntil`) follow the
owner document; a Safe-owner signature relies on the Safe's own nonce inside the SafeTx hash
([Safe owner](./fermion-wallet.md#safe-owner-erc-1271)).

### Fermion Guard

Canonical types: [quantum approval](./fermion-guard.md#quantum-approval),
[modules](./fermion-guard.md#modules), [key rotation](./fermion-guard.md#key-rotation).

```ts
interface SafeTx {
  to: Address; value: bigint; data: Hex;
  operation: 0;                   // Call only; DelegateCall is refused before signing
  safeTxGas: bigint; baseGas: bigint;
  gasPrice: 0n; gasToken: "0x0000000000000000000000000000000000000000";
  refundReceiver: "0x0000000000000000000000000000000000000000";
  nonce: bigint;                  // the Safe's nonce
}

interface GuardRef { safe: Address; chainId: bigint; guard: Address; key: KeyRef; paramSet: ParamSet }

function buildApproval(g: GuardRef, tx: SafeTx, w: ValidityWindow): Payload<unknown>;

/** Module transactions have no safeTxHash or Safe nonce; the approval carries its own. */
function buildModuleApproval(
  g: GuardRef,
  call: { module: Address; to: Address; value: bigint; data: Hex },
  nonce: bigint, w: ValidityWindow
): Payload<unknown>;

function buildRevoke(g: GuardRef, safeTxHash: Bytes32, w: ValidityWindow): Payload<unknown>;

/** Rotation: the old key approves the hash of the new, already registered key. */
function buildRotate(g: GuardRef, newKey: PublicKeys, w: ValidityWindow): Payload<unknown>;
```

`unknown` marks message types the guard document defines; the SDK exposes them under the same
names once fixed.

The builders run the device's acceptance rules locally first
([acceptance rules](./ledger-app.md#acceptance-rules)) and throw the same refusal the device would,
so the user is not asked to plug in a device for a transaction it will refuse.

## Device transport

```ts
interface FermionDevice {
  readonly transport: "webhid" | "ledger-live";
  getAppConfig(): Promise<{ name: "Fermion"; version: string; paramSets: (44 | 65)[] }>;
  getPublicKeys(key: KeyRef): Promise<PublicKeys>;
  sign<T>(payload: Payload<T>, opts?: { descriptors?: SignedDescriptor[] }): Promise<HybridSignature>;
  close(): Promise<void>;
}

/** Browser: WebHID. Requires a user gesture; the browser remembers the permission per origin. */
function connectWebHid(): Promise<FermionDevice>;

/** Inside Ledger Live: Wallet API device exchange (needs Ledger's permission for custom APDUs). */
function connectLedgerLive(client: WalletApiClient): Promise<FermionDevice>;
```

Large values cross the transport in 255-byte chunks. Chunk counts
([measured facts](./v2-decisions.md#measured-facts-cite-these-do-not-retype-from-memory)):

| | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
|---|---|---|---|
| signature (bytes / chunks) | 2420 / 10 | 3309 / 13 | 4627 / 19 |
| public key (bytes / chunks) | 1312 / 6 | 1952 / 8 | 2592 / 11 |

ML-DSA-87 appears for completeness; the Ledger app does not produce it.

`sign` resolves only after the user confirms on the device. It rejects with `UserRejected` on a
refusal on the device, and with a `DeviceRefused` error carrying the device's reason when the
device's own rules refuse the payload.

## Signature assembly

```ts
interface HybridSignature {
  ecdsa: Hex;                     // 65 bytes, r ‖ s ‖ v
  mldsa: Hex;                     // 2420 / 3309 / 4627 bytes by parameter set
  algorithm: bigint;
}

/** Single-bytes form for ERC-1271 and for appending to Safe signatures: ecdsa ‖ mldsa.
 *  Length 65 + ML-DSA length = 2485 (44), 3374 (65), 4692 (87) bytes (derived). */
function encodeHybrid(sig: HybridSignature): Hex;
function decodeHybrid(bytes: Hex, algorithm: bigint): HybridSignature;
```

The encoding is specified in the [ERC draft](./erc-draft-hybrid-pq-signatures.md) and in
[hybrid signature](./fermion-wallet.md#hybrid-signature). Wallet transfers pass the two halves as
separate arguments; ERC-1271 and Safe signatures carry the concatenation.

### Inline Safe signatures

```ts
/** Owner signatures for execTransaction, with the quantum approval appended in the layout the
 *  guard defines (see inline-and-stored-approvals). */
function appendQuantumApproval(ownerSignatures: Hex, approval: HybridSignature): Hex;

/** A Fermion Wallet's owner signature in Safe's contract-signature form (v = 0, r = wallet
 *  address, dynamic part = encodeHybrid(sig)), merged into the sorted owner signatures. */
function encodeWalletOwnerSignature(wallet: Address, sig: HybridSignature): SafeSignaturePart;
function mergeOwnerSignatures(parts: SafeSignaturePart[]): Hex;
```

The appended layout is canonical in
[inline and stored approvals](./fermion-guard.md#inline-and-stored-approvals).

## Stored approvals

A stored approval is the same signed struct as an inline one, submitted ahead of execution so
any Safe front end's Execute button works.

```ts
function buildPreApproveTx(g: GuardRef, tx: SafeTx, approval: HybridSignature): UnsignedTx;

/** Revoke by the Quantum Administrator (hybrid-signed). */
function buildRevokeTx(g: GuardRef, safeTxHash: Bytes32, sig: HybridSignature): UnsignedTx;

/** Revoke by the Safe itself: an ordinary Safe transaction the guard does not require a
 *  quantum approval for (it only removes permission). */
function buildSafeRevokeTx(g: GuardRef, safeTxHash: Bytes32): SafeTx;

/** Read the stored approvals for a Safe, with their windows and whether the key epoch still
 *  matches (rotation kills old-key approvals). */
function listStoredApprovals(g: GuardRef, chain: ChainContext): Promise<StoredApproval[]>;
```

## Factory registration

Every key needs per-key precomputed data in `MLDSAKeyFactory` before fast verification. A key
without it still verifies, through the slower full verification.

```ts
/** Fermion Wallet creation: ONE transaction doing commitA + registerT + clone deployment.
 *  Run at creation, before any funds arrive. */
function buildWalletSetupTx(pk: PublicKeys, chain: ChainContext): Promise<{ tx: UnsignedTx; wallet: Address }>;

/** The wallet's address, from its key; the same on every supported chain. */
function predictWalletAddress(pk: PublicKeys): Address;

/** First transfer carries A in calldata; the factory checks it against the commitment and stores
 *  it. Returns undefined once A is stored. */
function aHatForFirstTransfer(pk: PublicKeys, chain: ChainContext): Promise<Hex | undefined>;

/** ML-DSA-87: store the two A parts in separate transactions ahead of the first transfer. */
function buildStoreAPartTxs(pk: PublicKeys): UnsignedTx[];

/** Fermion Guard enrollment and rotation: register the new key's precomputed data first. */
function buildRegisterKeyTxs(pk: PublicKeys): UnsignedTx[];   // registerA (two parts for 87) + registerT
```

Gas per path, for the user's information before they confirm
([measured facts](./v2-decisions.md#measured-facts-cite-these-do-not-retype-from-memory)):

| | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
|---|---|---|---|
| one-tx wallet setup | 5.55M | 9.53M | 14.99M |
| first transfer (stores A) | 5.90M | 9.56M | 16.30M (store A parts ahead) |
| later transfer | 2.82M | 3.83M | 5.60M |

## Relayer interface

Any party may submit a signed transaction; it carries no authority. The default submitter is the
user's own EOA through their browser wallet.

```ts
interface Relayer {
  readonly name: string;
  /** Submit; resolves with the transaction hash. Must not alter calldata. */
  submit(tx: UnsignedTx, chain: ChainContext): Promise<Hex>;
}

/** Built in: send through the connected EIP-1193 wallet (the user's EOA pays gas). */
function eoaRelayer(provider: Eip1193Provider): Relayer;

interface UnsignedTx { to: Address; data: Hex; value: bigint; chainId: bigint }
```

Third-party relayers implement `Relayer`. The SDK checks the submitted transaction's calldata
against what it built before trusting a reported hash. There is no reimbursement from the wallet,
so relayer payment is out of band.

## ERC-7730 descriptors

The device clear-signs contract calls using ERC-7730 descriptors. Only Ledger-signed descriptors
from Ledger's clear-signing registry are accepted, and the device verifies Ledger's signature.

```ts
interface SignedDescriptor { chainId: bigint; contract: Address; selector: Hex; blob: Hex; ledgerSignature: Hex }

interface DescriptorStore {
  /** Bundled descriptors (Fermion's own contracts and common protocols) first, then the cache,
   *  then an online fetch. */
  get(chainId: bigint, to: Address, selector: Hex): Promise<SignedDescriptor | undefined>;
  /** Fetch errors resolve to undefined plus a warning flag, never a throw. */
  lastFetchFailed: boolean;
}
```

The SDK passes descriptors to the device as they are; it never vouches for one. If no descriptor
is found, or the fetch fails, the call is still signable after the device's strong warning
showing target, selector, value and the full calldata with its hash. The UI must show the same
warning before sending the request to the device.

## Errors

All errors extend `FermionError` with a stable `code`.

| Code | Thrown when | Raised by |
|---|---|---|
| `DelegateCallRefused` | `operation` is not Call | SDK pre-check and device |
| `GasRefundRefused` | non-zero `gasPrice`, `gasToken` or `refundReceiver` | SDK pre-check and device |
| `UnlimitedApprovalRefused` | an approve or permit for an unlimited amount | SDK pre-check and device |
| `WindowTooLong` | `validUntil - validFrom` over 24 hours | SDK pre-check and device |
| `WindowNotCurrent` | the window has not started or has ended (by chain time) | SDK, before submit |
| `BatchTooLarge` | more than 8 legs | SDK pre-check |
| `AdminHasCode` | the ECDSA admin address has code | SDK pre-check (the contract also refuses) |
| `ParamSetUnsupported` | the device cannot produce the requested set (87 on Ledger) | SDK |
| `UserRejected` | the user rejected on the device | device |
| `DeviceRefused` | the device's rules refused the payload; carries the device's reason | device |
| `WrongApp`, `AppVersionUnsupported` | the open app is not Fermion, or too old | transport |
| `TransportError` | WebHID or Wallet API failure, disconnect, timeout | transport |
| `SignatureMismatch` | a returned signature fails local verification | SDK |
| `KeyNotRegistered` | no precomputed data; informational, verification falls back to the full path | SDK (warning) |
| `DescriptorUnavailable` | no Ledger-signed descriptor; informational, triggers the warning flow | SDK (warning) |
| `GasCapExceeded` | an estimate exceeds the 2^24 per-transaction cap | SDK, before submit |
| `RelayerMismatch` | a relayer reported a transaction that does not match what was built | SDK |
