// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC20Mock as MockToken} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {DoubleEndedQueue} from "@openzeppelin/contracts/utils/structs/DoubleEndedQueue.sol";

import {Safe} from "@safe-global/safe-contracts/contracts/Safe.sol";
import {SafeProxyFactory} from "@safe-global/safe-contracts/contracts/proxies/SafeProxyFactory.sol";
import {MultiSendCallOnly} from "@safe-global/safe-contracts/contracts/libraries/MultiSendCallOnly.sol";
import {Enum} from "@safe-global/safe-contracts/contracts/libraries/Enum.sol";

import {FermionWalletGuard} from "../../src/FermionWalletGuard.sol";
import {PreApprovalEngine} from "../../src/PreApprovalEngine.sol";
import {XMSS} from "../../src/XMSS.sol";

/// Test-only view extension: exposes the Tier-2 queues so properties can assert on them.
/// Adds views only — the enforcement code under test is the production contract's.
contract FermionWalletGuardHarness is FermionWalletGuard {
    using DoubleEndedQueue for DoubleEndedQueue.Bytes32Deque;

    constructor(address msco, uint64 adminTl, uint64 emergencyTl, uint32 maxLegs, uint32 maxQueue)
        FermionWalletGuard(msco, adminTl, emergencyTl, maxLegs, maxQueue)
    {}

    function queueLength(bytes32 commitment) external view returns (uint256) {
        return _queue[commitment].length();
    }

    function queueAt(bytes32 commitment, uint256 i) external view returns (bytes32) {
        return _queue[commitment].at(i);
    }

    function commitmentOf(bytes32 id) external view returns (bytes32) {
        return _commitment(_approvals[id]);
    }
}

/// Runs several fully signed Safe transactions inside ONE call frame (shared transient
/// storage), catching each failure, then a final probe transaction whose revert data
/// reveals the Guard's view of the depth counter.
contract FrameRunner {
    struct SafeCall {
        address to;
        uint256 value;
        bytes data;
        uint8 operation;
        uint256 safeTxGas;
        bytes sigs;
    }

    Safe internal immutable SAFE;

    constructor(Safe safe_) {
        SAFE = safe_;
    }

    function run(SafeCall[] calldata calls) external returns (bool[] memory ok, bytes[] memory err) {
        ok = new bool[](calls.length);
        err = new bytes[](calls.length);
        for (uint256 i = 0; i < calls.length; ++i) {
            try SAFE.execTransaction(
                calls[i].to,
                calls[i].value,
                calls[i].data,
                Enum.Operation(calls[i].operation),
                calls[i].safeTxGas,
                0,
                0,
                address(0),
                payable(address(0)),
                calls[i].sigs
            ) returns (bool s) {
                ok[i] = s;
            } catch (bytes memory e) {
                err[i] = e;
            }
        }
    }
}

/// Shared fixture for the property suites: a real Safe v1.5.0 proxy (2-of-3), the real
/// MultiSendCallOnly, the Guard (view harness), a registered h = 5 XMSS key, and a
/// batch FFI signer so pools of hybrid-signed approvals can be generated in setUp.
abstract contract PropertyBase is Test {
    uint256 internal constant OWNER1_PK = 0xA1;
    uint256 internal constant OWNER2_PK = 0xA2;
    uint256 internal constant OWNER3_PK = 0xA3;
    uint256 internal constant LEDGER_PK = 0x1ED6E4;
    address internal owner1 = vm.addr(OWNER1_PK);
    address internal owner2 = vm.addr(OWNER2_PK);
    address internal owner3 = vm.addr(OWNER3_PK);
    address internal ledger = vm.addr(LEDGER_PK);
    address internal relayer = makeAddr("relayer");
    address internal stranger = makeAddr("stranger");
    address internal recipient = makeAddr("recipient");
    address internal recipient2 = makeAddr("recipient2");
    address internal module = makeAddr("module");

    uint64 internal constant ADMIN_TIMELOCK = 2 days;
    uint64 internal constant EMERGENCY_TIMELOCK = 7 days;
    uint32 internal constant MAX_BATCH_LEGS = 4;
    uint32 internal constant MAX_QUEUE = 4;
    uint32 internal constant H = 5; // 32 leaves
    uint64 internal constant T0 = 1_800_000_000;
    bytes32 internal constant PARAM_SET = keccak256("XMSS-SHA2_5_256-TEST");

    bytes32 internal constant APPROVE_KEY_TYPEHASH = keccak256(
        "ApproveQuantumKey(address safe,address quantumAdmin,bytes32 xmssRoot,bytes32 xmssSeed,uint32 treeHeight,bytes32 parameterSet,uint256 registryNonce,uint256 validUntil)"
    );
    bytes32 internal constant ATTEST_KEY_TYPEHASH = keccak256(
        "QuantumKeyAttestation(address safe,bytes32 xmssRoot,bytes32 xmssSeed,uint32 treeHeight,bytes32 parameterSet,uint256 registryNonce)"
    );
    bytes32 internal constant REVOKE_KEY_TYPEHASH = keccak256(
        "RequestKeyRevocation(address safe,bytes32 quantumKeyId,uint256 registryNonce,uint256 validUntil)"
    );
    bytes32 internal constant PRE_APPROVAL_TYPEHASH = keccak256(
        "PreApproval(address safe,uint8 approvalClass,address token,address recipient,uint256 amount,address target,uint256 value,bytes32 dataHash,uint64 validFrom,uint64 validTo,bytes32 nonce,bytes32 quantumKeyId,uint32 xmssLeafIndex,bytes32 policyHash,bytes32 txHash)"
    );
    bytes32 internal constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    /// keccak256("fallback_manager.handler.address")
    bytes32 internal constant FALLBACK_SLOT = 0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5;
    /// keccak256("guard_manager.guard.address")
    bytes32 internal constant GUARD_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;

    uint8 internal constant C_TRANSFER = 0;
    uint8 internal constant C_PAYLOAD = 1;
    uint8 internal constant C_ADMIN = 2;

    Safe internal safe;
    MultiSendCallOnly internal msco;
    FermionWalletGuardHarness internal guard;
    MockToken internal token;
    MockToken internal token2;
    bytes32 internal keyId;
    bytes32 internal xmssRoot;
    bytes32 internal xmssSeed;
    uint256 internal approvalNonce;

    /// Deploy + enroll + attach. `withModule`: wire the Guard as module guard and enable
    /// `module` first (Safe v1.5 module path), before the Guard is attached.
    function _deployFixture(bool withModule) internal {
        vm.warp(T0);
        Safe singleton = new Safe();
        SafeProxyFactory factory = new SafeProxyFactory();
        msco = new MultiSendCallOnly();
        token = new MockToken();
        token2 = new MockToken();

        address[] memory owners = new address[](3);
        owners[0] = owner1;
        owners[1] = owner2;
        owners[2] = owner3;
        safe = Safe(
            payable(
                factory.createProxyWithNonce(
                    address(singleton),
                    abi.encodeCall(Safe.setup, (owners, 2, address(0), "", address(0), address(0), 0, payable(address(0)))),
                    0xF3E
                )
            )
        );
        guard = new FermionWalletGuardHarness(address(msco), ADMIN_TIMELOCK, EMERGENCY_TIMELOCK, MAX_BATCH_LEGS, MAX_QUEUE);
        token.mint(address(safe), type(uint128).max);
        token2.mint(address(safe), type(uint128).max);
        vm.deal(address(safe), 1_000_000 ether);

        _safeExec(address(0xDEAD), 0, "", Enum.Operation.Call); // nonce >= 1
        if (withModule) {
            _safeExec(address(safe), 0, abi.encodeWithSignature("setModuleGuard(address)", address(guard)), Enum.Operation.Call);
            _safeExec(address(safe), 0, abi.encodeWithSignature("enableModule(address)", module), Enum.Operation.Call);
        }

        (xmssRoot, xmssSeed) = _xmssRootSeed();
        keyId = _registerKey();
        _safeExec(address(safe), 0, abi.encodeWithSignature("setGuard(address)", address(guard)), Enum.Operation.Call);
    }

    // ── XMSS (batch FFI) ────────────────────────────────────────────────────

    function _xmssRootSeed() internal returns (bytes32 root, bytes32 seed) {
        bytes memory blob = _ffiBatch(new uint32[](0), new bytes32[](0));
        root = _word(blob, 0);
        seed = _word(blob, 1);
    }

    /// Sign `digests[i]` with leaf `leaves[i]`, one FFI call for the whole batch.
    function _xmssSignBatch(uint32[] memory leaves, bytes32[] memory digests) internal returns (bytes[] memory sigs) {
        bytes memory blob = _ffiBatch(leaves, digests);
        uint256 per = 1 + 67 + H;
        sigs = new bytes[](leaves.length);
        for (uint256 k = 0; k < leaves.length; ++k) {
            uint256 base = 2 + k * per;
            XMSS.Signature memory sig;
            sig.leafIdx = leaves[k];
            sig.r = _word(blob, base);
            for (uint256 i = 0; i < 67; ++i) {
                sig.wotsSig[i] = _word(blob, base + 1 + i);
            }
            sig.authPath = new bytes32[](H);
            for (uint256 i = 0; i < H; ++i) {
                sig.authPath[i] = _word(blob, base + 68 + i);
            }
            sigs[k] = abi.encode(sig);
        }
    }

    function _ffiBatch(uint32[] memory leaves, bytes32[] memory digests) private returns (bytes memory blob) {
        string[] memory cmd = new string[](3 + leaves.length);
        cmd[0] = "python3";
        cmd[1] = "test/ffi/sign_batch.py";
        cmd[2] = vm.toString(uint256(H));
        for (uint256 i = 0; i < leaves.length; ++i) {
            cmd[3 + i] = string.concat(vm.toString(uint256(leaves[i])), ":", vm.toString(digests[i]));
        }
        blob = vm.ffi(cmd);
        require(blob.length == 32 * (2 + leaves.length * (1 + 67 + H)), "ffi blob size");
    }

    function _word(bytes memory blob, uint256 i) internal pure returns (bytes32 w) {
        assembly ("memory-safe") {
            w := mload(add(add(blob, 32), mul(i, 32)))
        }
    }

    // ── Safe helpers ────────────────────────────────────────────────────────

    function _guardDigest(bytes32 structHash) internal view returns (bytes32) {
        bytes32 domain = keccak256(
            abi.encode(DOMAIN_TYPEHASH, keccak256("FermionWalletGuard"), keccak256("1"), block.chainid, address(guard))
        );
        return keccak256(abi.encodePacked(hex"1901", domain, structHash));
    }

    function _ownerSigs(bytes32 digest) internal view returns (bytes memory) {
        uint256[3] memory pks = [OWNER1_PK, OWNER2_PK, OWNER3_PK];
        address[3] memory addrs = [owner1, owner2, owner3];
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

    function _txHash(address to, uint256 value, bytes memory data, Enum.Operation op, uint256 safeTxGas, uint256 nonce)
        internal
        view
        returns (bytes32)
    {
        return safe.getTransactionHash(to, value, data, op, safeTxGas, 0, 0, address(0), address(0), nonce);
    }

    function _safeExec(address to, uint256 value, bytes memory data, Enum.Operation op) internal {
        bytes memory sigs = _ownerSigs(_txHash(to, value, data, op, 0, safe.nonce()));
        safe.execTransaction(to, value, data, op, 0, 0, 0, address(0), payable(address(0)), sigs);
    }

    /// Owner-signed execTransaction that never reverts the caller: (executed, revertData).
    function _tryExec(address to, uint256 value, bytes memory data, Enum.Operation op, uint256 safeTxGas)
        internal
        returns (bool ok, bytes memory err)
    {
        bytes memory sigs = _ownerSigs(_txHash(to, value, data, op, safeTxGas, safe.nonce()));
        try safe.execTransaction(to, value, data, op, safeTxGas, 0, 0, address(0), payable(address(0)), sigs) returns (
            bool s
        ) {
            ok = s;
        } catch (bytes memory e) {
            err = e;
        }
    }

    function _tryModuleExec(address to, uint256 value, bytes memory data, Enum.Operation op)
        internal
        returns (bool ok, bytes memory err)
    {
        vm.prank(module);
        try safe.execTransactionFromModule(to, value, data, op) returns (bool s) {
            ok = s;
        } catch (bytes memory e) {
            err = e;
        }
    }

    function _leg(address to, uint256 value, bytes memory data) internal pure returns (bytes memory) {
        return abi.encodePacked(uint8(0), to, value, data.length, data);
    }

    function _sel(bytes memory err) internal pure returns (bytes4 s) {
        if (err.length >= 4) s = bytes4(err);
    }

    // ── Registration ────────────────────────────────────────────────────────

    function _registerKey() internal returns (bytes32) {
        uint256 nonce = guard.registryNonce(address(safe));
        uint256 validUntil = vm.getBlockTimestamp() + 1 days;
        bytes32 digest = _guardDigest(
            keccak256(
                abi.encode(APPROVE_KEY_TYPEHASH, address(safe), ledger, xmssRoot, xmssSeed, H, PARAM_SET, nonce, validUntil)
            )
        );
        bytes32 attest = _guardDigest(
            keccak256(abi.encode(ATTEST_KEY_TYPEHASH, address(safe), xmssRoot, xmssSeed, H, PARAM_SET, nonce))
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(LEDGER_PK, attest);
        vm.prank(relayer);
        return guard.registerQuantumKey(
            address(safe), ledger, xmssRoot, xmssSeed, H, PARAM_SET, validUntil, abi.encodePacked(r, s, v), _ownerSigs(digest)
        );
    }

    // ── Pre-approvals ───────────────────────────────────────────────────────

    function _transferReq(address token_, address to, uint256 amount, uint32 leaf, uint64 from, uint64 to_, bytes32 pin)
        internal
        returns (PreApprovalEngine.PreApprovalRequest memory req)
    {
        req.safe = address(safe);
        req.token = token_;
        req.recipient = to;
        req.amount = amount;
        req.validFrom = from;
        req.validTo = to_;
        req.nonce = bytes32(++approvalNonce);
        req.quantumKeyId = keyId;
        req.xmssLeafIndex = leaf;
        req.policyHash = keccak256("policy-v1");
        req.txHash = pin;
    }

    function _payloadReq(address target, uint256 value, bytes32 dataHash, uint32 leaf, uint64 from, uint64 to_, bytes32 pin)
        internal
        returns (PreApprovalEngine.PreApprovalRequest memory req)
    {
        req.safe = address(safe);
        req.target = target;
        req.value = value;
        req.dataHash = dataHash;
        req.validFrom = from;
        req.validTo = to_;
        req.nonce = bytes32(++approvalNonce);
        req.quantumKeyId = keyId;
        req.xmssLeafIndex = leaf;
        req.policyHash = keccak256("policy-v1");
        req.txHash = pin;
    }

    function _digest(PreApprovalEngine.PreApprovalRequest memory req, uint8 class_) internal view returns (bytes32) {
        return _guardDigest(
            keccak256(
                abi.encode(
                    PRE_APPROVAL_TYPEHASH,
                    req.safe,
                    class_,
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
    }

    function _ecdsa(bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(LEDGER_PK, digest);
        return abi.encodePacked(r, s, v);
    }

    /// Hybrid-sign a list of requests (one FFI call).
    function _signAll(PreApprovalEngine.PreApprovalRequest[] memory reqs, uint8[] memory classes)
        internal
        returns (bytes[] memory ecdsaSigs, bytes[] memory xmssSigs)
    {
        uint32[] memory leaves = new uint32[](reqs.length);
        bytes32[] memory digests = new bytes32[](reqs.length);
        ecdsaSigs = new bytes[](reqs.length);
        for (uint256 i = 0; i < reqs.length; ++i) {
            leaves[i] = reqs[i].xmssLeafIndex;
            digests[i] = _digest(reqs[i], classes[i]);
            ecdsaSigs[i] = _ecdsa(digests[i]);
        }
        xmssSigs = _xmssSignBatch(leaves, digests);
    }

    function _submit(
        PreApprovalEngine.PreApprovalRequest memory req,
        uint8 class_,
        bytes memory ecdsaSig,
        bytes memory xmssSig
    ) internal returns (bytes32) {
        if (class_ == C_TRANSFER) return guard.createPreApproval(req, ecdsaSig, xmssSig);
        if (class_ == C_PAYLOAD) return guard.createPayloadPreApproval(req, ecdsaSig, xmssSig);
        return guard.createAdminPreApproval(req, ecdsaSig, xmssSig);
    }

    /// Sign and create in one go.
    function _createSigned(PreApprovalEngine.PreApprovalRequest memory req, uint8 class_) internal returns (bytes32) {
        PreApprovalEngine.PreApprovalRequest[] memory reqs = new PreApprovalEngine.PreApprovalRequest[](1);
        uint8[] memory classes = new uint8[](1);
        reqs[0] = req;
        classes[0] = class_;
        (bytes[] memory e, bytes[] memory x) = _signAll(reqs, classes);
        vm.prank(relayer);
        return _submit(req, class_, e[0], x[0]);
    }

    function _transferData(address to, uint256 amount) internal pure returns (bytes memory) {
        return abi.encodeCall(IERC20.transfer, (to, amount));
    }
}
