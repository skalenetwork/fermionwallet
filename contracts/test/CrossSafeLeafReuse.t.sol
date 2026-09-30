// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.24;

import {FermionGuardTest, MockSafe} from "./FermionGuard.t.sol";
import {PreApprovalEngine} from "../src/PreApprovalEngine.sol";
import {QuantumKeyRegistry} from "../src/QuantumKeyRegistry.sol";

/// One XMSS key, several Safes: the used-leaf bitmap must be shared.
///
/// Covers: [QKR-009], [QKR-009a]
///
/// The device attests one key per Safe (ledger-ui.md: "attestation is repeated per
/// Safe"), and root identity is scoped per Safe, so the same key legitimately has a
/// different `quantumKeyId` on each Safe. If leaf accounting followed the
/// registration rather than the key, every Safe would start with an empty bitmap and
/// one one-time leaf could sign two different digests — the condition that makes
/// WOTS+ forgeable, and exactly what this bitmap exists to prevent.
contract CrossSafeLeafReuseTest is FermionGuardTest {
    MockSafe safeB;
    bytes32 keyIdB;

    /// Sign a TRANSFER request with the test key at an explicit leaf (the base class's
    /// helper always advances to the next unused one).
    function _signAt(PreApprovalEngine.PreApprovalRequest memory req, uint32 leaf)
        internal
        returns (bytes memory ecdsa, bytes memory xmss)
    {
        bytes32 digest = _typed(
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
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(adminPk, digest);
        ecdsa = abi.encodePacked(r, s, v);
        (,, xmss) = _xmss(treeHeight, leaf, digest);
    }

    function _registerSameKeyOnSecondSafe() internal {
        safeB = new MockSafe(owner);
        token.mint(address(safeB), 1_000_000);
        keyIdB = _register(safeB, treeHeight); // same deterministic test key as `safe`
        safeB.setGuardDirect(address(guard));
    }

    function test_sameKeyOnTwoSafes_hasDistinctRegistrationsButOneRoot() public {
        _registerSameKeyOnSecondSafe();
        assertTrue(keyIdB != keyId, "each Safe gets its own quantumKeyId");
        assertEq(
            guard.getKey(keyIdB).xmssRoot,
            guard.getKey(keyId).xmssRoot,
            "and both registrations are the same physical XMSS key"
        );
    }

    /// A leaf spent on one Safe is spent everywhere.
    function test_leafConsumedOnOneSafe_cannotBeReusedOnAnother() public {
        _registerSameKeyOnSecondSafe();

        _approveTransfer(100, bytes32(0)); // consumes leaf `nextLeaf` (0) under keyId
        assertTrue(guard.isLeafUsed(keyId, 0), "leaf 0 is used on the first Safe");
        assertTrue(guard.isLeafUsed(keyIdB, 0), "and is therefore used for the key everywhere");

        // The same leaf, offered to the second Safe, must be refused.
        PreApprovalEngine.PreApprovalRequest memory req;
        req.safe = address(safeB);
        req.token = address(token);
        req.recipient = recipient;
        req.amount = 999;
        req.validFrom = uint64(block.timestamp);
        req.validTo = uint64(block.timestamp) + 15 minutes;
        req.nonce = bytes32(uint256(0xB0B));
        req.quantumKeyId = keyIdB;
        req.xmssLeafIndex = 0;
        (bytes memory ecdsa, bytes memory xmss) = _signAt(req, 0);

        vm.expectRevert(abi.encodeWithSelector(QuantumKeyRegistry.LeafAlreadyUsed.selector, keyIdB, uint32(0)));
        guard.createPreApproval(req, ecdsa, xmss);
    }

    /// The next unused leaf still works on the second Safe: sharing the bitmap must
    /// not block a key that is legitimately used by two Safes in turn.
    function test_unusedLeafStillWorksOnTheOtherSafe() public {
        _registerSameKeyOnSecondSafe();
        _approveTransfer(100, bytes32(0)); // leaf 0

        PreApprovalEngine.PreApprovalRequest memory req;
        req.safe = address(safeB);
        req.token = address(token);
        req.recipient = recipient;
        req.amount = 55;
        req.validFrom = uint64(block.timestamp);
        req.validTo = uint64(block.timestamp) + 15 minutes;
        req.nonce = bytes32(uint256(0xB0C));
        req.quantumKeyId = keyIdB;
        req.xmssLeafIndex = 1;
        (bytes memory ecdsa, bytes memory xmss) = _signAt(req, 1);

        guard.createPreApproval(req, ecdsa, xmss);
        assertTrue(guard.isLeafUsed(keyId, 1), "leaf 1 is now spent for the key everywhere");
    }
}
