# FermionWallet Service Deployment Specification: Gnosis Safe Integration

This document specifies the architecture, operational topology, contract deployment process, configuration requirements, and failover models for deploying the **FermionWallet Service** alongside **Gnosis Safe (Safe{Wallet})**.

---

## 1. System Architecture & Topology

```text
  +-----------------------------------------------------------------------+
  |                        Safe{Wallet} Client / UI                       |
  |  +---------------------------+       +-----------------------------+  |
  |  | Safe Multisig Owners (EOA)|       | FermionWallet Safe App (UI) |  |
  |  +-------------+-------------+       +--------------+--------------+  |
  +----------------|------------------------------------|-----------------+
                   | (Safe Transactions)                | (WebHID / Session API)
                   v                                    v
  +---------------------------------+    +--------------------------------+
  |   Gnosis Safe Transaction Svc   |<-->|  FermionWallet Add-on Service  |
  |   (REST API + WebSocket events) |    |  - Policy Engine               |
  +---------------------------------+    |  - Key Ceremony Coordinator    |
                   ^                     |  - Pre-Approval Orchestrator   |
                   |                     +---------------+----------------+
                   |                                     |
                   |               (Signs XMSS half)     v
                   |         +--------------------------------------------+
                   |         | Ledger (FermionWallet XMSS app)            |
                   |         |  - ST33 SE: XMSS seed + ECDSA key          |
                   |         |  - Monotonic Leaf Counter (SE NVRAM)       |
                   |         +-------------------+------------------------+
                   |                             |
                   | (Relays createPreApproval)  v
+------------------v-------------------------------------------------------+
|                       EVM Blockchain (Ethereum / L2)                     |
|                                                                          |
|  +------------------------+      execTransaction      +---------------+  |
|  |     Gnosis Safe        |-------------------------->| Target ERC20  |  |
|  |     Proxy Instance     |                           | / Receiver    |  |
|  +-----------+------------+                           +---------------+  |
|              |                                                           |
|              | checkTransaction() [ITransactionGuard]                    |
|              v                                                           |
|  +--------------------------------------------------------------------+  |
|  |  FermionWalletGuard — ONE deployed contract, one storage:          |  |
|  |    transaction guard + module guard (Safe >= 1.5)                  |  |
|  |    + QuantumKeyRegistry (keys, leaf bitmaps)       [abstract base] |  |
|  |    + PreApprovalEngine  (pre-approvals, queues)    [abstract base] |  |
|  |    + XMSS verifier (RFC 8391, internal library, inlined)           |  |
|  +--------------------------------------------------------------------+  |
+--------------------------------------------------------------------------+
```

---

## 2. On-Chain Contracts Deployment Sequence

FermionWallet deploys **one** contract per chain: `FermionWalletGuard`. The key registry and pre-approval engine are abstract base contracts compiled into it, and the XMSS verifier is an internal library inlined into its bytecode — none of them is deployed separately. The Guard is non-upgradeable and has no admin (see the Guard spec, "No global powers").

### 2.1 Deterministic Factory Deployment (Create2)

`contracts/script/Deploy.s.sol` deploys the Guard with `new FermionWalletGuard{salt: SALT}(...)`, which Forge routes through the deterministic deployment proxy, so the same constructor arguments and salt give the same address on every chain where that proxy exists. Target networks: Ethereum Mainnet, Arbitrum, Optimism, Base, Polygon.

Constructor arguments (all immutable), with the script's defaults, each overridable by environment variable:

| Argument | Env var | Default |
|---|---|---|
| `multiSendCallOnly` | `MULTISEND_CALL_ONLY` | Safe v1.4.1 `MultiSendCallOnly`, `0x9641d764fc13c8B624c04430C7356C1C7C8102e2` (the v1.3.0 deployment is `0x40A2aCCbd92BCA938b02010E17A5b8929b49130D`) |
| `adminTimelock` | `ADMIN_TIMELOCK` | 2 days |
| `emergencyTimelock` (also the key-revocation timelock) | `EMERGENCY_TIMELOCK` | 14 days; must exceed `adminTimelock` |
| `maxBatchLegs` | `MAX_BATCH_LEGS` | 100 |
| `maxCommitmentQueue` | `MAX_COMMITMENT_QUEUE` | 16 |
| CREATE2 salt | `SALT` | `keccak256("fermionwallet.guard.v1")` |

The script refuses to deploy if `MULTISEND_CALL_ONLY` has no code on the target chain.

### 2.2 Safe Integration Handshake
To enroll a client Safe:
1. **Key Ceremony**:
   * Quantum Administrator generates the root inside the Ledger's secure element (FermionWallet XMSS app).
   * Safe owners sign EIP-712 registration hash.
   * Safe owners first remove the fallback handler and any unguarded modules (ordinary Safe transactions, before the Guard is attached) — registration is refused otherwise.
   * Administrator calls `FermionWalletGuard.registerQuantumKey(...)`.
2. **Guard Activation**:
   * Safe owners execute multisig transaction:
     ```solidity
     Safe.setGuard(address(FermionWalletGuard));
     ```
   * Safe ≥ 1.5 with modules: also wire the module guard (the same address), before enabling any module:
     ```solidity
     Safe.setModuleGuard(address(FermionWalletGuard));
     ```

### 2.3 Canonical Deployments & Address Verification

With identical constructor arguments and salt, the Guard's **address** is identical on every supported chain. Its on-chain **code hash** (`EXTCODEHASH`) is not: the constructor writes immutables into the runtime code, including the EIP-712 domain separator and chain ID, so every deployment's code hash differs per chain. The authoritative source of truth is a signed `deployments.json` in this repository (mirrored in `fermionwallet.eth` ENS text records):

```json
{
  "version": "1.0.0",
  "contracts": {
    "FermionWalletGuard": {
      "address": "<filled at first mainnet deployment>",
      "constructorArgs": { "multiSendCallOnly": "0x…", "adminTimelock": 172800, "emergencyTimelock": 1209600, "maxBatchLegs": 100, "maxCommitmentQueue": 16 },
      "codehashByChain": { "1": "0x…", "42161": "0x…", "10": "0x…", "8453": "0x…", "137": "0x…" }
    }
  }
}
```

Rules:

* Addresses and per-chain code hashes are filled in **once**, at the audited-release deployment, and never changed for a given version; a new version means a new salt, a new address, and a new entry — no in-place upgrades.
* The Safe App and the backend refuse to operate against a Guard whose `EXTCODEHASH` does not match the chain's entry in `deployments.json` — copy-paste address verification alone is not sufficient.
* **Linking a deployment to a release:** each GitHub Release's `MANIFEST.txt` publishes the Guard's runtime code hash **with immutables zeroed**, plus `FermionWalletGuard.immutable-references.json`. To check that a deployed Guard is that release's code: fetch its runtime code, zero every byte range in the references file, hash, and compare.
* **Unsupported chains:** anyone can reproduce the address on a new chain by running `forge script script/Deploy.s.sol --broadcast` with the same arguments and salt, provided the deterministic deployment proxy and the chosen `MultiSendCallOnly` exist there. The deployment is permissionless; what makes it genuine is the code check above, not the deployer identity.

### 2.4 Safe App Distribution & Verification

The FermionWallet Safe App (the front end opened inside Safe{Wallet}) is distributed as follows:

* **Primary hosting:** `https://app.fermionwallet.io` — a static single-page bundle behind a CDN, chain-agnostic (the same URL serves all supported networks; the app reads the connected Safe's `chainId` and selects the matching `deployments.json` entry).
* **Integrity mirror:** every release is also pinned to IPFS; the CID is published in the GitHub release notes and in the `fermionwallet.eth` ENS `contenthash`. Users who distrust DNS can load the app via any IPFS gateway or `ipfs://` directly.
* **Manifest:** the bundle root serves the standard Safe App `manifest.json` (`name: "FermionWallet"`, `description`, `iconPath`), which is what Safe{Wallet} reads when the user selects *Apps → My custom apps → Add custom Safe App* and pastes the URL. Longer term, listing in the default Safe Apps registry (via PR to `safe-global/safe-apps-list`) removes the custom-URL step entirely; until that listing is merged, **the custom-URL flow is the only installation path and the URL must be obtained from this repository's README or the ENS record — never from a link in an email or chat message** (anti-phishing rule; see ui-help.md).
* **Phishing check built in:** on load, the app displays the Guard address it is configured with and its code hash next to the published values, and refuses to propose `setGuard` if they differ. A cloned app pointing at a look-alike Guard fails this check visibly.

---

## 3. Add-on Service Infrastructure Specification

The backend service is a horizontally scalable Node.js/TypeScript daemon interacting with the Safe Transaction Service and the Administrator's Ledger. **It holds no key material** — the Ledger is the only signer.

### 3.1 Component Breakdown

| Component | Responsibility | Tech Stack / Dependencies |
|---|---|---|
| **Queue Listener** | Polls/streams pending multisig approvals from Safe Transaction Service | Node.js, `@safe-global/safe-core-sdk`, WebSockets |
| **Policy Engine** | Checks proposed tx against off-chain limits, token allowlists, and schedules | TypeScript, Zod schema validation |
| **Ceremony API** | Coordinates multi-owner EIP-712 attestation gathering | Express / Fastify, Redis (ephemeral session state) |
| **Signer Gateway** | Interface with the Ledger FermionWallet XMSS app (sole signer) | `@ledgerhq/hw-transport-webhid` / node-hid |
| **Gas Relayer** | Submits `createPreApproval` transactions on-chain on behalf of the Admin | Ethers.js / Viem, Dedicated relayer wallet |

### 3.2 Environment Configuration (`.env.production`)

```ini
# --- Network & RPC ---
CHAIN_ID=1
RPC_URL=https://eth-mainnet.g.alchemy.com/v2/${ALCHEMY_API_KEY}
FALLBACK_RPC_URL=https://rpc.ankr.com/eth

# --- Pinned Contracts ---
SAFE_TRANSACTION_SERVICE_URL=https://safe-transaction-mainnet.safe.global/
FERMION_GUARD_ADDRESS=0x...
CANONICAL_MULTISEND_CALL_ONLY=0x9641d764fc13c8B624c04430C7356C1C7C8102e2   # must equal the Guard's MULTISEND_CALL_ONLY

# --- Security & Relaying ---
RELAYER_PRIVATE_KEY=0x...        # Hot wallet funded with ETH strictly for gas
ADMIN_PUBLIC_ADDRESS=0x...       # Quantum Administrator EOA / Ledger address
POLICY_CONFIG_PATH=/etc/fermion/policy.json

# --- Hardware Module / Signing (Ledger for MVP) ---
KEY_BACKEND_TYPE=LEDGER_BRIDGE   # MVP: Ledger Hardware Wallet (Nano S Plus / X / Stax / Flex via WebHID / USB)
LEDGER_TRANSPORT=node-hid        # Options: node-hid | webhid
LEAF_INDEX_STORAGE_PATH=/var/lib/fermion/leaf_state.db

# --- Alerts & Monitoring ---
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
PAGERDUTY_ROUTING_KEY=...
```

### 3.3 Deployment Runbook

The service ships as a single Docker image (`ghcr.io/skalenetwork/fermionwallet-service`) plus one PostgreSQL database. Reference deployment:

1. **Runtime:** any Docker host or Kubernetes; the Administrator's workstation variant (where the Ledger is physically plugged in) runs the same image with `LEDGER_TRANSPORT=node-hid`, while the always-on relayer/watcher instance runs headless with signing disabled. The two roles may be one machine for small teams.
2. **Database:** PostgreSQL 15+. Schema is created by the built-in migrator on first start (`npm run migrate` / entrypoint auto-migrate). Core tables: `pre_approvals` (id, safe, class, decoded fields, leaf_index, status, tx hashes, timestamps), `denials` (same key, reason, ledger denial receipt), `ceremony_sessions` (staged owner signatures, expiry), `audit_events` (append-only, hash-chained), `leaf_state` (advisory mirror of the SE counter, per quantumKeyId).
3. **RPC:** one standard JSON-RPC endpoint per chain (any provider; no private/mev-protected RPC required — pre-approvals are meaningless to front-run because they authorize only the exact bound transfer) plus the public Safe Transaction Service URL for that chain.
4. **Secrets:** only two — the relayer hot-wallet key (gas only; keep balance small) and the database credential. The service holds **no signing keys**; compromise of the host is a liveness problem, not a fund-loss problem (see threat-model.md).
5. **Access control:** the dashboard is served by the same daemon; operator accounts are provisioned by the Administrator (OIDC/SSO recommended). Safe owners authenticate to the ceremony/approval pages with a SIWE (Sign-In-With-Ethereum) challenge against their owner address — no separate password database for owners.
6. **Start order:** database → service (`docker run --env-file .env.production -p 8443:8443 …`) → verify `/healthz` reports RPC, Safe Transaction Service, and (on the signer host) Ledger transport all green → connect the Safe App to the service URL in *Settings → Backend*.
7. **Upgrades:** stateless container swap; migrations are forward-only; the SE leaf counter on the Ledger is authoritative, so no service state loss can cause leaf reuse.

---

## 4. Operational Workflows & Lifecycle

### 4.1 Automated Transaction Pre-Approval Lifecycle

1. **Detection**:
   * Queue Listener polls `GET /api/v1/safes/{safe_address}/multisig-transactions/?ordering=-created` for transactions reaching the signature threshold.
2. **Policy Verification**:
   * Evaluates calldata against `policy.json` rules (e.g. transfer caps, recipient whitelist).
3. **Hybrid Approval Collection**:
   * Sends alert to Administrator containing Safe transaction digest.
   * Admin reviews decoded payload on the Ledger screen; one physical confirmation releases both hybrid halves (EIP-712 ECDSA + XMSS) from the secure element.
4. **XMSS Signature Execution**:
   * The Ledger secure element reserves leaf `i`, commits the counter to `i+1` in SE NVRAM, then outputs the XMSS signature (counter-before-signature invariant).
5. **On-Chain Pre-Approval Mining**:
   * Relayer submits `createPreApproval` (or `createPayloadPreApproval` for batches).
   * Service monitors confirmation; upon inclusion, Safe App flags status as 🟢 **Ready to Execute**.

### 4.2 High Availability & Failover Architecture

* **Database (State Sync)**: PostgreSQL cluster with synchronous replication for ceremony state and audit logs.
* **Leaf-Index Counter**:
  * Authoritative monotonic counter lives in the Ledger secure element NVRAM; the service keeps only an advisory mirror.
  * **Fail-safe Rule**: In case of process restart or unknown transaction submission status, **the service increments the leaf index by +1** and queries the on-chain bitmap to confirm non-collision. Never re-attempt with an existing index.

---

## 5. Security & Deployment Hardening Checklist

- [ ] **Deterministic Verification**: Verify the `FermionWalletGuard` source on Etherscan / Sourcify, and check its runtime code against the release manifest (immutables zeroed) and `deployments.json`.
- [ ] **Relayer Isolation**: Relayer EOA holds minimal gas funds (< 2 ETH) and has zero administrative privileges in the smart contracts.
- [ ] **Safe App Manifest**: Serve the Safe App UI over HTTPS with strict Content-Security-Policy (CSP) restricting iframe parent embedding to `https://app.safe.global`.
- [ ] **Emergency Exit Drill**: Validate that Safe owners can run the emergency de-guard path (`requestEmergencyDeGuard`, then `Safe.setGuard(address(0))` after `EMERGENCY_TIMELOCK`) during an unannounced simulated service outage.
