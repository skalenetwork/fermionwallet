// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {MultiSendCallOnly} from "@safe-global/safe-contracts/contracts/libraries/MultiSendCallOnly.sol";

import {FermionGuard} from "../src/FermionGuard.sol";
import {Deploy} from "../script/Deploy.s.sol";

/// Deploy.s.sol end to end: the deterministic address the deployment docs promise
/// (same args + salt ⇒ same address on every chain id, including the OP-stack ones
/// where forge does not reroute `new{salt}` through the CREATE2 proxy), the
/// immutables read back from the deployed code, and the parameter guard rails.
contract DeployScriptTest is Test {
    address internal constant CANONICAL_MSCO = 0x9641d764fc13c8B624c04430C7356C1C7C8102e2;
    /// Runtime code of the deterministic deployment proxy (Arachnid).
    bytes internal constant PROXY_CODE =
        hex"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf3";

    function setUp() public {
        if (CREATE2_FACTORY.code.length == 0) vm.etch(CREATE2_FACTORY, PROXY_CODE);
        vm.etch(CANONICAL_MSCO, address(new MultiSendCallOnly()).code);
    }

    function _expected(bytes32 salt) internal pure returns (address) {
        bytes memory initCode = abi.encodePacked(
            type(FermionGuard).creationCode,
            abi.encode(CANONICAL_MSCO, uint64(2 days), uint64(14 days), uint32(100), uint32(16))
        );
        return vm.computeCreate2Address(salt, keccak256(initCode), CREATE2_FACTORY);
    }

    /// Covers: [GRD-080]
    function test_DefaultDeployment_SameAddressOnEveryTargetChain() public {
        address expected = _expected(keccak256("fermionguard.guard.v1"));
        uint256[6] memory chains = [uint256(1), 10, 8453, 42161, 137, 31337];
        bytes32[6] memory codehashes;
        for (uint256 i = 0; i < chains.length; ++i) {
            uint256 snap = vm.snapshotState();
            vm.chainId(chains[i]);
            FermionGuard guard = new Deploy().run();
            assertEq(address(guard), expected, "CREATE2 address must not depend on the chain");
            assertGt(address(guard).code.length, 0);
            assertEq(guard.MULTISEND_CALL_ONLY(), CANONICAL_MSCO);
            assertEq(guard.ADMIN_TIMELOCK(), 2 days);
            assertEq(guard.EMERGENCY_TIMELOCK(), 14 days);
            assertEq(guard.EMERGENCY_ROTATION_TIMELOCK(), 14 days);
            assertEq(guard.MAX_BATCH_LEGS(), 100);
            assertEq(guard.MAX_COMMITMENT_QUEUE(), 16);
            (, , , uint256 domainChainId, address verifyingContract, , ) = guard.eip712Domain();
            assertEq(domainChainId, chains[i]);
            assertEq(verifyingContract, expected);
            codehashes[i] = address(guard).codehash;
            vm.revertToState(snap);
        }
        // EXTCODEHASH differs per chain (chain id / domain separator immutables), which
        // is why deployments.json records it per chain.
        for (uint256 i = 0; i < chains.length; ++i) {
            for (uint256 j = i + 1; j < chains.length; ++j) {
                assertTrue(codehashes[i] != codehashes[j]);
            }
        }
    }

    function test_SecondRunIsIdempotent() public {
        FermionGuard first = new Deploy().run();
        FermionGuard second = new Deploy().run();
        assertEq(address(first), address(second));
    }

    function test_CustomParams_AppliedAndReadBack() public {
        address msco = address(new MultiSendCallOnly());
        bytes32 salt = bytes32(uint256(1));
        FermionGuard guard = new Deploy().deploy(msco, 3600, 86400, 7, 3, salt);
        bytes memory initCode = abi.encodePacked(
            type(FermionGuard).creationCode,
            abi.encode(msco, uint64(3600), uint64(86400), uint32(7), uint32(3))
        );
        assertEq(address(guard), vm.computeCreate2Address(salt, keccak256(initCode), CREATE2_FACTORY));
        assertEq(guard.MULTISEND_CALL_ONLY(), msco);
        assertEq(guard.ADMIN_TIMELOCK(), 3600);
        assertEq(guard.EMERGENCY_TIMELOCK(), 86400);
        assertEq(guard.EMERGENCY_ROTATION_TIMELOCK(), 86400);
        assertEq(guard.MAX_BATCH_LEGS(), 7);
        assertEq(guard.MAX_COMMITMENT_QUEUE(), 3);
    }

    /// Covers: [GRD-075], [GRD-113]
    function test_RejectsBadParams() public {
        Deploy d = new Deploy();
        bytes32 salt = keccak256("fermionguard.guard.v1");

        vm.expectRevert(bytes("EMERGENCY_TIMELOCK must exceed ADMIN_TIMELOCK"));
        d.deploy(CANONICAL_MSCO, 1 days, 1 days, 100, 16, salt);

        vm.expectRevert(bytes("MAX_BATCH_LEGS and MAX_COMMITMENT_QUEUE must be > 0"));
        d.deploy(CANONICAL_MSCO, 2 days, 14 days, 100, 0, salt);

        vm.expectRevert(bytes("MultiSendCallOnly not deployed on this chain"));
        d.deploy(address(0xdead), 2 days, 14 days, 100, 16, salt);
    }
}
