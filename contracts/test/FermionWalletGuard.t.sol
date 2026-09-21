// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Enum} from "@safe-global/safe-contracts/contracts/libraries/Enum.sol";
import {ITransactionGuard} from "@safe-global/safe-contracts/contracts/base/GuardManager.sol";

import {FermionWalletGuard} from "../src/FermionWalletGuard.sol";
import {PreApprovalEngine} from "../src/PreApprovalEngine.sol";
import {QuantumKeyRegistry} from "../src/QuantumKeyRegistry.sol";
import {XMSS} from "../src/XMSS.sol";

/// Minimal Safe stand-in reproducing the parts of Safe v1.5.0 `execTransaction` the
/// Guard depends on: hash with the current nonce, increment, checkTransaction, call,
/// then checkAfterExecution on the SAME (cached) guard — even if the call removed it.
contract MockSafe {
    address public guard;
    uint256 public nonce;
    mapping(address => bool) public isOwner;

    constructor(address owner) {
        isOwner[owner] = true;
    }

    receive() external payable {}

    /// Test bootstrap only (a real Safe sets its guard through execTransaction).
    function setGuardDirect(address g) external {
        guard = g;
    }

    function setGuard(address g) external {
        require(msg.sender == address(this), "only self");
        guard = g;
    }

    function getTransactionHash(
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation,
        uint256,
        uint256,
        uint256,
        address,
        address,
        uint256 _nonce
    ) public view returns (bytes32) {
        return keccak256(abi.encode(address(this), to, value, keccak256(data), operation, _nonce));
    }

    function checkSignatures(address, bytes32, bytes memory signatures) external pure {
        require(keccak256(signatures) == keccak256("owners-ok"), "GS026");
    }

    function getModulesPaginated(address, uint256) external pure returns (address[] memory array, address next) {
        array = new address[](0);
        next = address(0x1);
    }

    function getStorageAt(uint256, uint256) external pure returns (bytes memory) {
        return abi.encode(address(0));
    }

    function exec(address to, uint256 value, bytes memory data) external returns (bool success) {
        bytes32 txHash = this.getTransactionHash(to, value, data, Enum.Operation.Call, 0, 0, 0, address(0), address(0), nonce);
        nonce++;
        address g = guard;
        if (g != address(0)) {
            ITransactionGuard(g).checkTransaction(
                to, value, data, Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", msg.sender
            );
        }
        bytes memory ret;
        (success, ret) = to.call{value: value}(data);
        if (g != address(0)) ITransactionGuard(g).checkAfterExecution(txHash, success);
        if (!success) {
            assembly ("memory-safe") {
                revert(add(ret, 32), mload(ret))
            }
        }
    }
}

contract MockToken {
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract Placeholder {}

contract FermionWalletGuardTest is Test {
    uint64 constant ADMIN_TIMELOCK = 48 hours;
    uint64 constant EMERGENCY_TIMELOCK = 14 days;

    bytes32 constant APPROVE_KEY_TYPEHASH = keccak256(
        "ApproveQuantumKey(address safe,address quantumAdmin,bytes32 xmssRoot,bytes32 xmssSeed,uint32 treeHeight,bytes32 parameterSet,uint256 registryNonce,uint256 validUntil)"
    );
    bytes32 constant ROTATE_KEY_TYPEHASH = keccak256(
        "RotateQuantumKey(address safe,bytes32 oldQuantumKeyId,address newQuantumAdmin,bytes32 newXmssRoot,bytes32 newXmssSeed,uint32 treeHeight,bytes32 parameterSet,uint256 registryNonce,uint256 validUntil)"
    );
    bytes32 constant ATTEST_KEY_TYPEHASH = keccak256(
        "QuantumKeyAttestation(address safe,bytes32 xmssRoot,bytes32 xmssSeed,uint32 treeHeight,bytes32 parameterSet,uint256 registryNonce)"
    );
    bytes32 constant PRE_APPROVAL_TYPEHASH = keccak256(
        "PreApproval(address safe,uint8 approvalClass,address token,address recipient,uint256 amount,address target,uint256 value,bytes32 dataHash,uint64 validFrom,uint64 validTo,bytes32 nonce,bytes32 quantumKeyId,uint32 xmssLeafIndex,bytes32 policyHash,bytes32 txHash)"
    );
    bytes32 constant PARAM_SET = keccak256("XMSS-SHA2_4_256-test");

    FermionWalletGuard guard;
    MockSafe safe;
    MockToken token;

    uint256 adminPk = 0xA11CE;
    address admin;
    address owner = makeAddr("owner");
    address stranger = makeAddr("stranger");
    address guardian = makeAddr("guardian");
    address recipient = makeAddr("recipient");

    bytes32 keyId;
    uint32 treeHeight = 4;
    uint32 nextLeaf;
    uint256 approvalNonce;

    function setUp() public {
        admin = vm.addr(adminPk);
        guard = new FermionWalletGuard(
            address(new Placeholder()), ADMIN_TIMELOCK, EMERGENCY_TIMELOCK, 100, 16, address(this), guardian
        );
        safe = new MockSafe(owner);
        token = new MockToken();
        token.mint(address(safe), 1_000_000);

        keyId = _register(safe, 4);
        safe.setGuardDirect(address(guard));
    }

    // ── Fix 1: owners pause and revoke fast, without a quantum approval ──────

    function test_singleOwnerPausesSafeDirectly() public {
        vm.prank(owner);
        guard.pauseSafe(address(safe));
        assertTrue(guard.safePaused(address(safe)));

        _approveTransfer(500, bytes32(0));
        vm.expectRevert(abi.encodeWithSelector(FermionWalletGuard.SafePausedError.selector, address(safe)));
        safe.exec(address(token), 0, _transferData(500));
    }

    function test_strangerCannotPauseSafe() public {
        vm.prank(stranger);
        vm.expectRevert(QuantumKeyRegistry.NotAuthorized.selector);
        guard.pauseSafe(address(safe));
    }

    function test_enrolledSafeCannotPauseEveryoneGlobally() public {
        vm.prank(address(safe));
        vm.expectRevert(QuantumKeyRegistry.NotAuthorized.selector);
        guard.pause();
    }

    function test_safePausesItselfWithoutQuantumApproval() public {
        safe.exec(address(guard), 0, abi.encodeCall(guard.pauseSafe, (address(safe))));
        assertTrue(guard.safePaused(address(safe)));
    }

    function test_singleOwnerRevokesApprovalDirectly() public {
        bytes32 id = _approveTransfer(500, bytes32(0));
        vm.prank(owner);
        guard.revokePreApproval(id);

        vm.expectRevert();
        safe.exec(address(token), 0, _transferData(500));
    }

    function test_safeRevokesApprovalWithoutQuantumApproval() public {
        bytes32 id = _approveTransfer(500, bytes32(0));
        safe.exec(address(guard), 0, abi.encodeCall(guard.revokePreApproval, (id)));
        assertTrue(guard.getPreApproval(id).revoked);
    }

    function test_strangerCannotRevoke() public {
        bytes32 id = _approveTransfer(500, bytes32(0));
        vm.prank(stranger);
        vm.expectRevert(QuantumKeyRegistry.NotAuthorized.selector);
        guard.revokePreApproval(id);
    }

    function test_unpauseSafeIsTimelockedSafeGovernance() public {
        vm.prank(owner);
        guard.pauseSafe(address(safe));

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(FermionWalletGuard.SafeNotPaused.selector, owner));
        guard.requestUnpauseSafe(); // an owner EOA is not the Safe

        safe.exec(address(guard), 0, abi.encodeCall(guard.requestUnpauseSafe, ()));
        vm.expectRevert();
        safe.exec(address(guard), 0, abi.encodeCall(guard.unpauseSafe, ()));

        vm.warp(block.timestamp + ADMIN_TIMELOCK);
        safe.exec(address(guard), 0, abi.encodeCall(guard.unpauseSafe, ()));
        assertFalse(guard.safePaused(address(safe)));
    }

    function test_newPauseCancelsPendingUnpause() public {
        vm.prank(owner);
        guard.pauseSafe(address(safe));
        safe.exec(address(guard), 0, abi.encodeCall(guard.requestUnpauseSafe, ()));
        vm.prank(owner);
        guard.pauseSafe(address(safe));
        assertEq(guard.safeUnpauseExecutableAt(address(safe)), 0);
    }

    // ── Fix 2: quantum-approved Guard removal works while paused ─────────────

    function test_adminApprovedRemovalWorksWhileSafePaused() public {
        _approveAdminRemoval();
        vm.prank(owner);
        guard.pauseSafe(address(safe));

        vm.warp(block.timestamp + ADMIN_TIMELOCK + 1);
        safe.exec(address(safe), 0, abi.encodeWithSignature("setGuard(address)", address(0)));
        assertEq(safe.guard(), address(0));
    }

    function test_adminApprovedRemovalWorksWhileGloballyPaused() public {
        _approveAdminRemoval();
        vm.prank(guardian);
        guard.pause();

        vm.warp(block.timestamp + ADMIN_TIMELOCK + 1);
        safe.exec(address(safe), 0, abi.encodeWithSignature("setGuard(address)", address(0)));
        assertEq(safe.guard(), address(0));
    }

    function test_unapprovedRemovalStillBlockedWhilePaused() public {
        vm.prank(owner);
        guard.pauseSafe(address(safe));
        vm.expectRevert(); // no ADMIN approval, no matured emergency request
        safe.exec(address(safe), 0, abi.encodeWithSignature("setGuard(address)", address(0)));
    }

    // ── Fix 3: a matured emergency request is consumed by the removal ────────

    function test_emergencyRemovalClearsRequest() public {
        safe.exec(address(guard), 0, abi.encodeCall(guard.requestEmergencyDeGuard, ()));
        vm.warp(block.timestamp + EMERGENCY_TIMELOCK);
        safe.exec(address(safe), 0, abi.encodeWithSignature("setGuard(address)", address(0)));
        assertEq(safe.guard(), address(0));
        assertEq(guard.emergencyDeGuardExecutableAt(address(safe)), 0);

        // Guard re-enabled later: removing it again needs a fresh request or approval.
        safe.setGuardDirect(address(guard));
        vm.expectRevert();
        safe.exec(address(safe), 0, abi.encodeWithSignature("setGuard(address)", address(0)));
    }

    function test_adminPathRemovalAlsoClearsPendingEmergencyRequest() public {
        safe.exec(address(guard), 0, abi.encodeCall(guard.requestEmergencyDeGuard, ()));
        _approveAdminRemoval();
        vm.warp(block.timestamp + ADMIN_TIMELOCK + 1);
        safe.exec(address(safe), 0, abi.encodeWithSignature("setGuard(address)", address(0)));
        assertEq(guard.emergencyDeGuardExecutableAt(address(safe)), 0);
    }

    // ── Fix 4: the Administrator's key alone cannot veto the owners' exits ───

    function test_adminKeyCannotCancelEmergencyDeGuard() public {
        safe.exec(address(guard), 0, abi.encodeCall(guard.requestEmergencyDeGuard, ()));
        vm.prank(admin);
        vm.expectRevert(QuantumKeyRegistry.NotAuthorized.selector);
        guard.cancelEmergencyDeGuard(address(safe));

        safe.exec(address(guard), 0, abi.encodeCall(guard.cancelEmergencyDeGuard, (address(safe))));
        assertEq(guard.emergencyDeGuardExecutableAt(address(safe)), 0);
    }

    function test_adminKeyCannotCancelKeyRevocation() public {
        guard.requestKeyRevocation(address(safe), block.timestamp + 1 days, "owners-ok");
        vm.prank(admin);
        vm.expectRevert(QuantumKeyRegistry.NotAuthorized.selector);
        guard.cancelKeyRevocation(address(safe));

        safe.exec(address(guard), 0, abi.encodeCall(guard.cancelKeyRevocation, (address(safe))));
        assertEq(guard.keyRevocationExecutableAt(address(safe)), 0);
    }

    // ── Fix 5: routine rotation keeps already-issued approvals executable ────

    function test_approvalSurvivesRoutineRotation() public {
        _approveTransfer(700, bytes32(0));
        _rotate(5);

        safe.exec(address(token), 0, _transferData(700));
        assertEq(token.balanceOf(recipient), 700);
    }

    // ── Fix 6: a dead pin can be replaced; a live one cannot ─────────────────

    function test_expiredPinCanBeReplaced() public {
        bytes32 txHash = _nextTxHash(address(token), _transferData(300));
        _approveTransfer(300, txHash);
        vm.warp(block.timestamp + 16 minutes); // past the 15-minute window

        _approveTransfer(300, txHash);
        safe.exec(address(token), 0, _transferData(300));
        assertEq(token.balanceOf(recipient), 300);
    }

    function test_livePinCannotBeReplaced() public {
        bytes32 txHash = _nextTxHash(address(token), _transferData(300));
        _approveTransfer(300, txHash);
        vm.expectRevert(
            abi.encodeWithSelector(PreApprovalEngine.TxHashAlreadyPinned.selector, address(safe), txHash)
        );
        this.approveTransferExternal(300, txHash);
    }

    function approveTransferExternal(uint256 amount, bytes32 txHash) external returns (bytes32) {
        return _approveTransfer(amount, txHash);
    }

    // ── Fix 7: an XMSS root can be registered only once, ever ────────────────

    function test_duplicateRootRejected() public {
        MockSafe other = new MockSafe(owner);
        (bytes32 root,,) = _xmss(4, 0, bytes32(0));
        vm.expectRevert(abi.encodeWithSelector(QuantumKeyRegistry.RootAlreadyRegistered.selector, root));
        this.registerExternal(other, 4);
    }

    function registerExternal(MockSafe s, uint32 h) external returns (bytes32) {
        return _register(s, h);
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    function _register(MockSafe s, uint32 h) internal returns (bytes32 id) {
        (bytes32 root, bytes32 seed,) = _xmss(h, 0, bytes32(0));
        uint256 regNonce = guard.registryNonce(address(s));
        bytes memory attestation = _sign(
            keccak256(abi.encode(ATTEST_KEY_TYPEHASH, address(s), root, seed, h, PARAM_SET, regNonce))
        );
        id = guard.registerQuantumKey(
            address(s), admin, root, seed, h, PARAM_SET, block.timestamp + 1 days, attestation, "owners-ok"
        );
    }

    function _rotate(uint32 newHeight) internal {
        (bytes32 newRoot, bytes32 newSeed,) = _xmss(newHeight, 0, bytes32(0));
        uint256 regNonce = guard.registryNonce(address(safe));
        uint256 validUntil = block.timestamp + 1 days;
        bytes32 digest = _typed(
            keccak256(
                abi.encode(
                    ROTATE_KEY_TYPEHASH,
                    address(safe),
                    keyId,
                    admin,
                    newRoot,
                    newSeed,
                    newHeight,
                    PARAM_SET,
                    regNonce,
                    validUntil
                )
            )
        );
        (,, bytes memory oldProof) = _xmss(treeHeight, nextLeaf++, digest);
        bytes memory attestation = _sign(
            keccak256(abi.encode(ATTEST_KEY_TYPEHASH, address(safe), newRoot, newSeed, newHeight, PARAM_SET, regNonce))
        );
        keyId = guard.rotateQuantumKey(
            address(safe), admin, newRoot, newSeed, newHeight, PARAM_SET, validUntil, oldProof, attestation, "owners-ok"
        );
        treeHeight = newHeight;
        nextLeaf = 0;
    }

    function _approveTransfer(uint256 amount, bytes32 txHash) internal returns (bytes32) {
        PreApprovalEngine.PreApprovalRequest memory req = _baseRequest(txHash);
        req.token = address(token);
        req.recipient = recipient;
        req.amount = amount;
        (bytes memory ecdsa, bytes memory xmss) = _signRequest(req, 0);
        return guard.createPreApproval(req, ecdsa, xmss);
    }

    function _approveAdminRemoval() internal returns (bytes32) {
        PreApprovalEngine.PreApprovalRequest memory req = _baseRequest(bytes32(0));
        req.target = address(safe);
        req.dataHash = keccak256(abi.encodeWithSignature("setGuard(address)", address(0)));
        req.validFrom = uint64(block.timestamp) + ADMIN_TIMELOCK;
        req.validTo = req.validFrom + 1 days;
        (bytes memory ecdsa, bytes memory xmss) = _signRequest(req, 2);
        return guard.createAdminPreApproval(req, ecdsa, xmss);
    }

    function _baseRequest(bytes32 txHash) internal returns (PreApprovalEngine.PreApprovalRequest memory req) {
        req.safe = address(safe);
        req.validFrom = uint64(block.timestamp);
        req.validTo = uint64(block.timestamp) + 15 minutes;
        req.nonce = bytes32(++approvalNonce);
        req.quantumKeyId = keyId;
        req.xmssLeafIndex = nextLeaf;
        req.txHash = txHash;
    }

    function _signRequest(PreApprovalEngine.PreApprovalRequest memory req, uint8 class_)
        internal
        returns (bytes memory ecdsa, bytes memory xmss)
    {
        bytes32 digest = _typed(
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
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(adminPk, digest);
        ecdsa = abi.encodePacked(r, s, v);
        (,, xmss) = _xmss(treeHeight, nextLeaf++, digest);
    }

    function _nextTxHash(address to, bytes memory data) internal view returns (bytes32) {
        return safe.getTransactionHash(to, 0, data, Enum.Operation.Call, 0, 0, 0, address(0), address(0), safe.nonce());
    }

    function _transferData(uint256 amount) internal view returns (bytes memory) {
        return abi.encodeCall(MockToken.transfer, (recipient, amount));
    }

    function _sign(bytes32 structHash) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(adminPk, _typed(structHash));
        return abi.encodePacked(r, s, v);
    }

    function _typed(bytes32 structHash) internal view returns (bytes32) {
        bytes32 domain = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("FermionWalletGuard"),
                keccak256("1"),
                block.chainid,
                address(guard)
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", domain, structHash));
    }

    /// Sign `digest` at `leaf` with the deterministic height-`h` test key (py/sign_digest.py).
    function _xmss(uint32 h, uint32 leaf, bytes32 digest)
        internal
        returns (bytes32 root, bytes32 seed, bytes memory encoded)
    {
        string[] memory cmd = new string[](5);
        cmd[0] = "python3";
        cmd[1] = "py/sign_digest.py";
        cmd[2] = vm.toString(h);
        cmd[3] = vm.toString(leaf);
        cmd[4] = vm.toString(digest);
        bytes memory out = vm.ffi(cmd);

        XMSS.Signature memory sig;
        sig.leafIdx = leaf;
        sig.authPath = new bytes32[](h);
        root = _word(out, 0);
        seed = _word(out, 1);
        sig.r = _word(out, 2);
        for (uint256 i = 0; i < 67; ++i) {
            sig.wotsSig[i] = _word(out, 3 + i);
        }
        for (uint256 i = 0; i < h; ++i) {
            sig.authPath[i] = _word(out, 70 + i);
        }
        encoded = abi.encode(sig);
    }

    function _word(bytes memory b, uint256 i) internal pure returns (bytes32 w) {
        assembly ("memory-safe") {
            w := mload(add(add(b, 32), mul(i, 32)))
        }
    }
}
