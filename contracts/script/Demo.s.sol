// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";

import {Safe} from "@safe-global/safe-contracts/contracts/Safe.sol";
import {SafeProxyFactory} from "@safe-global/safe-contracts/contracts/proxies/SafeProxyFactory.sol";
import {MultiSendCallOnly} from "@safe-global/safe-contracts/contracts/libraries/MultiSendCallOnly.sol";
import {Enum} from "@safe-global/safe-contracts/contracts/libraries/Enum.sol";

import {FermionWalletGuard} from "../src/FermionWalletGuard.sol";
import {PreApprovalEngine} from "../src/PreApprovalEngine.sol";
import {XMSS} from "../src/XMSS.sol";

/// Minimal ERC-20 for the demo treasury.
contract DemoToken {
    string public constant name = "Demo USD";
    string public constant symbol = "dUSD";
    uint8 public constant decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);

    function mint(address to, uint256 amount) external {
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }
}

/// Self-contained demo driver, executed by the container against a local anvil.
/// Entry points (forge script -s):
///   setup()            deploy Safe v1.5.0 + Guard, register the XMSS key, set the Guard
///   blocked(uint256)   SIMULATION: owner-signed transfer with NO quantum approval → guard revert
///   approve(uint256)   create a hybrid ECDSA+XMSS pre-approval for a vendor payout
///   execute(uint256)   owner-signed execTransaction for that payout → allowed by the Guard
/// Mirrors the helpers in test/GuardIntegration.t.sol; XMSS signatures come from the
/// RFC 8391 reference implementation via FFI (py/sign_digest.py, demo key h = 4).
contract Demo is Script {
    // anvil default accounts (mnemonic "test test ... junk")
    uint256 internal constant DEPLOYER_PK = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 internal constant OWNER1_PK = 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d;
    uint256 internal constant OWNER2_PK = 0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a;
    uint256 internal constant OWNER3_PK = 0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6;
    uint256 internal constant LEDGER_PK = 0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a;

    uint32 internal constant H = 4; // 16 leaves — plenty for one demo session
    bytes32 internal constant PARAM_SET = keccak256("XMSS-SHA2_4_256-DEMO");
    string internal constant STATE = "demo-state/deployment.json";

    bytes32 internal constant APPROVE_KEY_TYPEHASH = keccak256(
        "ApproveQuantumKey(address safe,address quantumAdmin,bytes32 xmssRoot,bytes32 xmssSeed,uint32 treeHeight,bytes32 parameterSet,uint256 registryNonce,uint256 validUntil)"
    );
    bytes32 internal constant ATTEST_KEY_TYPEHASH = keccak256(
        "QuantumKeyAttestation(address safe,bytes32 xmssRoot,bytes32 xmssSeed,uint32 treeHeight,bytes32 parameterSet,uint256 registryNonce)"
    );
    bytes32 internal constant PRE_APPROVAL_TYPEHASH = keccak256(
        "PreApproval(address safe,uint8 approvalClass,address token,address recipient,uint256 amount,address target,uint256 value,bytes32 dataHash,uint64 validFrom,uint64 validTo,bytes32 nonce,bytes32 quantumKeyId,uint32 xmssLeafIndex,bytes32 policyHash,bytes32 txHash)"
    );
    bytes32 internal constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    Safe internal safe;
    FermionWalletGuard internal guard;
    DemoToken internal token;
    address internal vendor;
    bytes32 internal keyId;
    bytes32 internal xmssRoot;
    bytes32 internal xmssSeed;

    // ═════════════════════════════ setup ════════════════════════════════════

    function setup() external {
        vendor = vm.addr(0xCAFE);

        vm.startBroadcast(DEPLOYER_PK);
        Safe singleton = new Safe();
        SafeProxyFactory factory = new SafeProxyFactory();
        MultiSendCallOnly msco = new MultiSendCallOnly();
        token = new DemoToken();

        address[] memory owners = new address[](3);
        owners[0] = vm.addr(OWNER1_PK);
        owners[1] = vm.addr(OWNER2_PK);
        owners[2] = vm.addr(OWNER3_PK);
        bytes memory initializer = abi.encodeCall(
            Safe.setup, (owners, 2, address(0), "", address(0), address(0), 0, payable(address(0)))
        );
        safe = Safe(payable(factory.createProxyWithNonce(address(singleton), initializer, 0xFE47)));

        // Demo-friendly timelocks: ADMIN 60 s, emergency de-guard 120 s.
        guard = new FermionWalletGuard(
            address(msco), 60, 120, 4, 8, vm.addr(DEPLOYER_PK), vm.addr(DEPLOYER_PK)
        );

        token.mint(address(safe), 1_000_000 ether);
        (bool funded,) = payable(address(safe)).call{value: 10 ether}("");
        require(funded, "funding failed");

        // Key ceremony: owner-threshold co-signed registration + Ledger attestation.
        (xmssRoot, xmssSeed,) = _xmssSign(0, bytes32(uint256(1))); // root/seed extraction only
        keyId = _registerKey();

        // Wire the Guard (owner-signed Safe self-call).
        _safeExec(address(safe), 0, abi.encodeWithSignature("setGuard(address)", address(guard)));
        vm.stopBroadcast();

        string memory o = "demo";
        vm.serializeAddress(o, "safe", address(safe));
        vm.serializeAddress(o, "guard", address(guard));
        vm.serializeAddress(o, "token", address(token));
        vm.serializeAddress(o, "vendor", vendor);
        vm.serializeAddress(o, "quantumAdmin", vm.addr(LEDGER_PK));
        vm.serializeBytes32(o, "keyId", keyId);
        vm.serializeBytes32(o, "xmssRoot", xmssRoot);
        string memory json = vm.serializeBytes32(o, "xmssSeed", xmssSeed);
        vm.writeJson(json, STATE);
        console2.log("DEMO_READY safe=%s guard=%s", address(safe), address(guard));
    }

    // ═════════════════════════════ flows ════════════════════════════════════

    /// Simulation only (run WITHOUT --broadcast): a fully owner-signed transfer that
    /// carries no quantum pre-approval. The Guard must revert it.
    function blocked(uint256 tokens) external {
        _load();
        bytes memory data = abi.encodeCall(DemoToken.transfer, (vendor, tokens * 1 ether));
        bytes32 txHash = safe.getTransactionHash(
            address(token), 0, data, Enum.Operation.Call, 0, 0, 0, address(0), address(0), safe.nonce()
        );
        try safe.execTransaction(
            address(token), 0, data, Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), _ownerSigs(txHash)
        ) {
            console2.log("RESULT UNEXPECTED_EXECUTION");
        } catch (bytes memory err) {
            console2.log("RESULT BLOCKED");
            console2.log("REVERT_DATA");
            console2.logBytes(err);
        }
    }

    /// Hybrid-sign (Ledger ECDSA + XMSS via FFI) and store a TRANSFER pre-approval.
    function approve(uint256 tokens) external {
        _load();
        uint32 leaf = _freeLeaf();

        PreApprovalEngine.PreApprovalRequest memory req;
        req.safe = address(safe);
        req.token = address(token);
        req.recipient = vendor;
        req.amount = tokens * 1 ether;
        req.validFrom = uint64(block.timestamp);
        req.validTo = uint64(block.timestamp) + 1 days;
        req.nonce = keccak256(abi.encode(vm.unixTime(), leaf));
        req.quantumKeyId = keyId;
        req.xmssLeafIndex = leaf;
        req.policyHash = keccak256("demo-policy-v1");
        req.txHash = bytes32(0); // Tier 2: field-matched

        bytes32 digest = _guardDigest(
            keccak256(
                abi.encode(
                    PRE_APPROVAL_TYPEHASH,
                    req.safe,
                    uint8(0),
                    req.token,
                    req.recipient,
                    req.amount,
                    req.target,
                    req.value,
                    req.dataHash,
                    req.validFrom,
                    req.validTo,
                    req.nonce,
                    req.quantumKeyId,
                    req.xmssLeafIndex,
                    req.policyHash,
                    req.txHash
                )
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(LEDGER_PK, digest);
        (,, bytes memory xmssSig) = _xmssSign(leaf, digest);

        vm.startBroadcast(DEPLOYER_PK); // the relayer
        bytes32 id = guard.createPreApproval(req, abi.encodePacked(r, s, v), xmssSig);
        vm.stopBroadcast();

        console2.log("RESULT APPROVED leaf=%s", uint256(leaf));
        console2.log("APPROVAL_ID");
        console2.logBytes32(id);
    }

    /// Owner-signed execTransaction of the pre-approved payout.
    function execute(uint256 tokens) external {
        _load();
        vm.startBroadcast(DEPLOYER_PK);
        _safeExec(address(token), 0, abi.encodeCall(DemoToken.transfer, (vendor, tokens * 1 ether)));
        vm.stopBroadcast();
        console2.log("RESULT EXECUTED vendorBalance=%s", token.balanceOf(vendor) / 1 ether);
    }

    // ═════════════════════════════ helpers ══════════════════════════════════

    function _load() internal {
        string memory j = vm.readFile(STATE);
        safe = Safe(payable(vm.parseJsonAddress(j, ".safe")));
        guard = FermionWalletGuard(vm.parseJsonAddress(j, ".guard"));
        token = DemoToken(vm.parseJsonAddress(j, ".token"));
        vendor = vm.parseJsonAddress(j, ".vendor");
        keyId = vm.parseJsonBytes32(j, ".keyId");
        xmssRoot = vm.parseJsonBytes32(j, ".xmssRoot");
        xmssSeed = vm.parseJsonBytes32(j, ".xmssSeed");
    }

    function _freeLeaf() internal view returns (uint32) {
        for (uint32 i = 0; i < uint32(1) << H; ++i) {
            if (!guard.isLeafUsed(keyId, i)) return i;
        }
        revert("demo key exhausted - restart the container");
    }

    function _xmssSign(uint32 leaf, bytes32 digest)
        internal
        returns (bytes32 root, bytes32 seed, bytes memory encodedSig)
    {
        string[] memory cmd = new string[](5);
        cmd[0] = "python3";
        cmd[1] = "py/sign_digest.py";
        cmd[2] = vm.toString(uint256(H));
        cmd[3] = vm.toString(uint256(leaf));
        cmd[4] = vm.toString(digest);
        bytes memory blob = vm.ffi(cmd);
        require(blob.length == 32 * (3 + 67 + H), "ffi blob size");

        XMSS.Signature memory sig;
        sig.leafIdx = leaf;
        root = _word(blob, 0);
        seed = _word(blob, 1);
        sig.r = _word(blob, 2);
        for (uint256 i = 0; i < 67; ++i) {
            sig.wotsSig[i] = _word(blob, 3 + i);
        }
        sig.authPath = new bytes32[](H);
        for (uint256 i = 0; i < H; ++i) {
            sig.authPath[i] = _word(blob, 70 + i);
        }
        encodedSig = abi.encode(sig);
    }

    function _word(bytes memory blob, uint256 i) private pure returns (bytes32 w) {
        assembly ("memory-safe") {
            w := mload(add(add(blob, 32), mul(i, 32)))
        }
    }

    function _guardDigest(bytes32 structHash) internal view returns (bytes32) {
        bytes32 domain = keccak256(
            abi.encode(DOMAIN_TYPEHASH, keccak256("FermionWalletGuard"), keccak256("1"), block.chainid, address(guard))
        );
        return keccak256(abi.encodePacked(hex"1901", domain, structHash));
    }

    function _ownerSigs(bytes32 digest) internal pure returns (bytes memory) {
        uint256[3] memory pks = [OWNER1_PK, OWNER2_PK, OWNER3_PK];
        address[3] memory addrs = [vm.addr(OWNER1_PK), vm.addr(OWNER2_PK), vm.addr(OWNER3_PK)];
        for (uint256 i = 0; i < 3; ++i) {
            for (uint256 j = i + 1; j < 3; ++j) {
                if (addrs[j] < addrs[i]) {
                    (addrs[i], addrs[j]) = (addrs[j], addrs[i]);
                    (pks[i], pks[j]) = (pks[j], pks[i]);
                }
            }
        }
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(pks[0], digest);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(pks[1], digest);
        return abi.encodePacked(r1, s1, v1, r2, s2, v2);
    }

    function _safeExec(address to, uint256 value, bytes memory data) internal {
        bytes32 txHash = safe.getTransactionHash(
            to, value, data, Enum.Operation.Call, 0, 0, 0, address(0), address(0), safe.nonce()
        );
        safe.execTransaction(
            to, value, data, Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), _ownerSigs(txHash)
        );
    }

    function _ledgerAttestation(uint256 nonce) internal view returns (bytes memory) {
        bytes32 digest = _guardDigest(
            keccak256(abi.encode(ATTEST_KEY_TYPEHASH, address(safe), xmssRoot, xmssSeed, H, PARAM_SET, nonce))
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(LEDGER_PK, digest);
        return abi.encodePacked(r, s, v);
    }

    function _registerKey() internal returns (bytes32) {
        address ledger = vm.addr(LEDGER_PK);
        uint256 nonce = guard.registryNonce(address(safe));
        uint256 validUntil = block.timestamp + 1 days;
        bytes32 digest = _guardDigest(
            keccak256(
                abi.encode(
                    APPROVE_KEY_TYPEHASH, address(safe), ledger, xmssRoot, xmssSeed, H, PARAM_SET, nonce, validUntil
                )
            )
        );
        return guard.registerQuantumKey(
            address(safe), ledger, xmssRoot, xmssSeed, H, PARAM_SET, validUntil, _ledgerAttestation(nonce), _ownerSigs(digest)
        );
    }
}
