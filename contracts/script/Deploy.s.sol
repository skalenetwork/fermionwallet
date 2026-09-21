// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {FermionWalletGuard} from "../src/FermionWalletGuard.sol";

/// @title FermionWallet deterministic deployment
/// @notice Deploys the FermionWalletGuard singleton (which embeds the
///         QuantumKeyRegistry and PreApprovalEngine) via CREATE2 through the
///         ERC-2470-style singleton factory, so the canonical address is
///         identical on every chain where the factory exists.
///
/// Environment variables (all have production defaults except the roles):
///   MULTISEND_CALL_ONLY   canonical Safe MultiSendCallOnly (default v1.4.1)
///   ADMIN_TIMELOCK        seconds (default 2 days)
///   EMERGENCY_TIMELOCK    seconds (default 7 days)
///   MAX_BATCH_LEGS        default 8
///   MAX_COMMITMENT_QUEUE  default 16
///   GOVERNANCE_ADMIN      required — DEFAULT_ADMIN_ROLE holder
///   GUARDIAN              required — PAUSER_ROLE holder
///   SALT                  CREATE2 salt (default keccak256("fermionwallet.guard.v1"))
contract Deploy is Script {
    // Canonical Safe MultiSendCallOnly v1.4.1 (same address on all supported chains).
    address internal constant DEFAULT_MULTISEND = 0x9641d764fc13c8B624c04430C7356C1C7C8102e2;

    function run() external returns (FermionWalletGuard guard) {
        address multiSend = vm.envOr("MULTISEND_CALL_ONLY", DEFAULT_MULTISEND);
        uint64 adminTimelock = uint64(vm.envOr("ADMIN_TIMELOCK", uint256(2 days)));
        uint64 emergencyTimelock = uint64(vm.envOr("EMERGENCY_TIMELOCK", uint256(7 days)));
        uint32 maxBatchLegs = uint32(vm.envOr("MAX_BATCH_LEGS", uint256(8)));
        uint32 maxCommitmentQueue = uint32(vm.envOr("MAX_COMMITMENT_QUEUE", uint256(16)));
        address governanceAdmin = vm.envAddress("GOVERNANCE_ADMIN");
        address guardian = vm.envAddress("GUARDIAN");
        bytes32 salt = vm.envOr("SALT", keccak256("fermionwallet.guard.v1"));

        require(multiSend.code.length > 0, "MultiSendCallOnly not deployed on this chain");

        vm.startBroadcast();
        // new{salt: ...} routes through the CREATE2 deployer configured for the
        // broadcast (forge uses the deterministic deployment proxy by default),
        // giving chain-independent addresses for identical bytecode + salt.
        guard = new FermionWalletGuard{salt: salt}(
            multiSend,
            adminTimelock,
            emergencyTimelock,
            maxBatchLegs,
            maxCommitmentQueue,
            governanceAdmin,
            guardian
        );
        vm.stopBroadcast();

        console2.log("FermionWalletGuard deployed at:", address(guard));
        console2.log("  codehash:");
        console2.logBytes32(address(guard).codehash);
        console2.log("  multiSendCallOnly:", multiSend);
        console2.log("  adminTimelock:", adminTimelock);
        console2.log("  emergencyTimelock:", emergencyTimelock);
        console2.log("  governanceAdmin:", governanceAdmin);
        console2.log("  guardian:", guardian);
    }
}
