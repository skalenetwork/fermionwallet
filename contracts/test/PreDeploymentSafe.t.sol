// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.24;

import {FermionGuardTest, MockSafe} from "./FermionGuard.t.sol";
import {QuantumKeyRegistry} from "../src/QuantumKeyRegistry.sol";

/// A Safe that does not exist yet cannot have its key slot claimed.
///
/// Covers: [QKR-005], [QKR-007]
///
/// `registerQuantumKey` is permissionless and takes `safe` as calldata; the only thing
/// authenticating that address is the Safe's own `checkSignatures`. A Safe's address is
/// predictable long before it is deployed (`SafeProxyFactory.createProxyWithNonce` is
/// CREATE2), so if that call succeeded against a codeless address, anyone could spend one
/// transaction of gas to become the `quantumAdmin` of a Safe that does not exist yet —
/// blocking the real owners' enrollment with `SafeAlreadyEnrolled`, and closing the
/// no-timelock detach that an unenrolled Safe relies on to undo a misordered setup.
///
/// What stops it is not a check anyone wrote. `ISafeLegacySignatures.checkSignatures` has
/// no return values, so solc keeps the `extcodesize` guard it elides for calls whose
/// returndata gets decoded, and the call reverts with empty data before any signature
/// logic runs. That is load-bearing and invisible: give the interface a return value,
/// wrap the call in `try/catch`, or lower it to a raw `call`, and squatting opens with no
/// test failing. Hence this file.
contract PreDeploymentSafeTest is FermionGuardTest {
    /// Everything the call needs, built before `vm.expectRevert` is armed — the cheat code
    /// applies to the very next call, and the setup below makes several of its own.
    function _registrationArgs(address target)
        internal
        returns (bytes32 root, bytes32 seed, bytes memory attestation)
    {
        (root, seed,) = _xmss(treeHeight, 0, bytes32(0));
        uint256 regNonce = guard.registryNonce(target);
        attestation =
            _sign(keccak256(abi.encode(ATTEST_KEY_TYPEHASH, target, root, seed, treeHeight, PARAM_SET, regNonce)));
    }

    function _expectRegistrationToRevert(address target) internal {
        (bytes32 root, bytes32 seed, bytes memory attestation) = _registrationArgs(target);
        vm.expectRevert();
        guard.registerQuantumKey(
            target, admin, root, seed, treeHeight, PARAM_SET, block.timestamp + 1 days, attestation, "owners-ok"
        );
    }

    /// The whole point: an address with no code cannot be enrolled, whoever asks.
    function test_registrationForACodelessAddressReverts() public {
        address notYetDeployed = makeAddr("counterfactual-safe");
        assertEq(notYetDeployed.code.length, 0, "the target must have no code for this test to mean anything");

        _expectRegistrationToRevert(notYetDeployed);

        assertEq(guard.safeToQuantumKey(notYetDeployed), bytes32(0), "no key slot was claimed");
        assertFalse(guard.enrolledSafe(notYetDeployed), "and the address is not enrolled");
    }

    /// …and it stays unenrolled once it is deployed, so the real owners can enroll it
    /// themselves. This is the half that would be lost if the guard above ever went away:
    /// the damage is not the failed call, it is the sticky enrollment flag it would set.
    function test_theRealSafeCanStillEnrollAfterwards() public {
        address notYetDeployed = makeAddr("counterfactual-safe");
        _expectRegistrationToRevert(notYetDeployed);

        MockSafe deployed = new MockSafe(owner);
        bytes32 id = _register(deployed, treeHeight);
        assertTrue(id != bytes32(0), "the Safe enrolls normally once it exists");
        assertEq(guard.safeToQuantumKey(address(deployed)), id);
    }

    /// The same protection covers a plain EOA — there is no code there either, and an
    /// attacker who could enroll one would be able to mint `quantumKeyId`s at will.
    function test_registrationForAnEoaReverts() public {
        _expectRegistrationToRevert(makeAddr("just-an-eoa"));
    }
}
