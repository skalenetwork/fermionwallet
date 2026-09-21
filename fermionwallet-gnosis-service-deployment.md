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
|  +------------------------+                           +---------------+  |
|  |  FermionWalletGuard    |-------------------------->| XMSS Library  |  |
|  |  (Singleton Enforcer)  |      verifySignature      | (RFC 8391)    |  |
|  +-----------+------------+                           +---------------+  |
|              |                                                           |
|              | reads status / verifies root                              |
|              v                                                           |
|  +------------------------+                                              |
|  |  QuantumKeyRegistry    |                                              |
|  |  (On-Chain Bitmap Root)|                                              |
|  +------------------------+                                              |
+--------------------------------------------------------------------------+
```

---

## 2. On-Chain Contracts Deployment Sequence

FermionWallet utilizes a shared singleton architecture for its Guard and Registry.

### 2.1 Deterministic Factory Deployment (Create2)
Contracts must be deployed across target networks (Ethereum Mainnet, Arbitrum, Optimism, Base, Polygon) using the canonical Safe Create2 CallDeployer (`0x914d7Fec6aaC8cd50fEb5d7B9130d56ee2cb2e00` or standard Singleton Factory):

1. **Deploy [`XMSS.sol`](file:///d/fermionwallet/contracts/src/XMSS.sol)**:
   * Pure bytecode library verifier.
   * Immutable, no initializer.
2. **Deploy `QuantumKeyRegistry.sol`**:
   * Stores Safe-to-Key bindings, root commitments, and `BitMaps` for leaf consumption.
   * Pinned reference to canonical Safe `MultiSendCallOnly` address.
3. **Deploy `FermionWalletGuard.sol`**:
   * Implements `ITransactionGuard` and `IModuleGuard`.
   * References immutable `QuantumKeyRegistry` and `XMSS` library.
   * Constructor arguments:
     * `address _registry`: Deployed `QuantumKeyRegistry` address.
     * `address _multiSendCallOnly`: Canonical Safe `MultiSendCallOnly` (e.g. v1.4.1 `0x40A2aCCbd92BCA938b02010E17A5b8929b49130D`).

### 2.2 Safe Integration Handshake
To enroll a client Safe:
1. **Key Ceremony**:
   * Quantum Administrator generates the root inside the Ledger's secure element (FermionWallet XMSS app).
   * Safe owners sign EIP-712 registration hash.
   * Administrator calls `QuantumKeyRegistry.registerQuantumKey(...)`.
2. **Guard Activation**:
   * Safe owners execute multisig transaction:
     ```solidity
     Safe.setGuard(address(FermionWalletGuard));
     ```
   * *Optional but recommended*: Enable Module Guard if using automated agents:
     ```solidity
     Safe.setModuleGuard(address(FermionWalletGuard));
     ```

### 2.3 Canonical Deployments & Address Verification

Because all three contracts are deployed through the deterministic CREATE2 singleton factory with pinned salts and bytecode, **the canonical addresses are identical on every supported chain**. The authoritative source of truth is a signed `deployments.json` in this repository (and mirrored at `fermionwallet.eth` ENS text records):

```json
{
  "version": "1.0.0",
  "networks": { "1": {}, "42161": {}, "10": {}, "8453": {}, "137": {} },
  "contracts": {
    "XMSS":               { "address": "<filled at first mainnet deployment>", "codehash": "0x…" },
    "QuantumKeyRegistry": { "address": "<filled at first mainnet deployment>", "codehash": "0x…" },
    "FermionWalletGuard": { "address": "<filled at first mainnet deployment>", "codehash": "0x…" }
  }
}
```

Rules:

* Addresses are filled in **once**, at the audited-release deployment, and never changed for a given version; a new version means new salts, new addresses, and a new registry entry — no in-place upgrades (contracts are non-upgradeable by design).
* The Safe App and the backend refuse to operate against a Guard whose `EXTCODEHASH` does not match the published `codehash` — copy-paste address verification alone is not sufficient.
* **Unsupported chains:** anyone can reproduce the canonical addresses on a new chain by running `forge script script/Deploy.s.sol --broadcast` (provided in `contracts/script/`) against the same singleton factory — CREATE2 guarantees byte-identical addresses if the factory exists on that chain. The deployment is permissionless; what makes it "canonical" is the codehash match, not the deployer identity. Chains without the singleton factory are unsupported until the factory is deployed there (standard one-time presigned transaction).

### 2.4 Safe App Distribution & Verification

The FermionWallet Safe App (the front end opened inside Safe{Wallet}) is distributed as follows:

* **Primary hosting:** `https://app.fermionwallet.io` — a static single-page bundle behind a CDN, chain-agnostic (the same URL serves all supported networks; the app reads the connected Safe's `chainId` and selects the matching `deployments.json` entry).
* **Integrity mirror:** every release is also pinned to IPFS; the CID is published in the GitHub release notes and in the `fermionwallet.eth` ENS `contenthash`. Users who distrust DNS can load the app via any IPFS gateway or `ipfs://` directly.
* **Manifest:** the bundle root serves the standard Safe App `manifest.json` (`name: "FermionWallet"`, `description`, `iconPath`), which is what Safe{Wallet} reads when the user selects *Apps → My custom apps → Add custom Safe App* and pastes the URL. Longer term, listing in the default Safe Apps registry (via PR to `safe-global/safe-apps-list`) removes the custom-URL step entirely; until that listing is merged, **the custom-URL flow is the only installation path and the URL must be obtained from this repository's README or the ENS record — never from a link in an email or chat message** (anti-phishing rule; see ui-help.md).
* **Phishing check built in:** on load, the app displays the Guard/Registry addresses it is configured with and their codehashes next to the published canonical values, and refuses to propose `setGuard` if they differ. A cloned app pointing at a look-alike Guard fails this check visibly.

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
FERMION_REGISTRY_ADDRESS=0x...
CANONICAL_MULTISEND_CALL_ONLY=0x40A2aCCbd92BCA938b02010E17A5b8929b49130D

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

- [ ] **Deterministic Verification**: Verify `FermionWalletGuard` and `QuantumKeyRegistry` source bytecode matches verified contracts via Etherscan / Sourcify.
- [ ] **Relayer Isolation**: Relayer EOA holds minimal gas funds (< 2 ETH) and has zero administrative privileges in the smart contracts.
- [ ] **Safe App Manifest**: Serve the Safe App UI over HTTPS with strict Content-Security-Policy (CSP) restricting iframe parent embedding to `https://app.safe.global`.
- [ ] **Emergency Exit Drill**: Validate that Safe owners can initiate the time-locked de-guard emergency path (`Safe.setGuard(address(0))`) during an unannounced simulated service outage.
