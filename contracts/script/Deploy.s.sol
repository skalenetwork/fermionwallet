// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {FermionWalletGuard} from "../src/FermionWalletGuard.sol";

/// @title FermionWallet deterministic deployment
/// @notice Deploys the FermionWalletGuard singleton (which embeds the
///         QuantumKeyRegistry and PreApprovalEngine) with CREATE2 through the
///         deterministic deployment proxy 0x4e59b44847b379578588920cA78FbF26c0B4956C,
///         so the address is identical on every chain where that proxy exists and the
///         constructor args, salt and compiled bytecode match.
///
///         The proxy is called EXPLICITLY (calldata = salt ‖ initcode) instead of via
///         `new FermionWalletGuard{salt: ...}`. Forge only reroutes `new{salt}` through
///         the proxy on some chains: on OP-stack chain ids (Optimism 10, Base 8453)
///         forge 1.8.3 broadcasts `new{salt}` as a plain CREATE from the deployer EOA,
///         landing at a nonce-dependent address that differs from the one the script
///         simulated and logged. The explicit call behaves the same everywhere, and the
///         script asserts the Guard ended up at the predicted address.
///
///         Idempotent: if the predicted address already holds code (someone deployed
///         this exact version on this chain already), nothing is broadcast.
///
/// Environment variables (all optional; production defaults):
///   MULTISEND_CALL_ONLY   canonical Safe MultiSendCallOnly (default v1.4.1)
///   ADMIN_TIMELOCK        seconds (default 2 days)
///   EMERGENCY_TIMELOCK    seconds (default 14 days — the published owners-only exit delay)
///   MAX_BATCH_LEGS        default 100 (spec default; user guide advertises 100-leg batches)
///   MAX_COMMITMENT_QUEUE  default 16
///   SALT                  CREATE2 salt (default keccak256("fermionwallet.guard.v1"))
contract Deploy is Script {
    // Canonical Safe MultiSendCallOnly v1.4.1 (same address on all supported chains).
    address internal constant DEFAULT_MULTISEND = 0x9641d764fc13c8B624c04430C7356C1C7C8102e2;
    // CREATE2_FACTORY (forge-std Base) is the deterministic deployment proxy above.

    function run() external returns (FermionWalletGuard) {
        return deploy(
            vm.envOr("MULTISEND_CALL_ONLY", DEFAULT_MULTISEND),
            _u64(vm.envOr("ADMIN_TIMELOCK", uint256(2 days)), "ADMIN_TIMELOCK"),
            _u64(vm.envOr("EMERGENCY_TIMELOCK", uint256(14 days)), "EMERGENCY_TIMELOCK"),
            _u32(vm.envOr("MAX_BATCH_LEGS", uint256(100)), "MAX_BATCH_LEGS"),
            _u32(vm.envOr("MAX_COMMITMENT_QUEUE", uint256(16)), "MAX_COMMITMENT_QUEUE"),
            vm.envOr("SALT", keccak256("fermionwallet.guard.v1"))
        );
    }

    /// The deployment itself, with explicit parameters (`run` reads them from the env).
    function deploy(
        address multiSend,
        uint64 adminTimelock,
        uint64 emergencyTimelock,
        uint32 maxBatchLegs,
        uint32 maxCommitmentQueue,
        bytes32 salt
    ) public returns (FermionWalletGuard guard) {
        require(multiSend.code.length > 0, "MultiSendCallOnly not deployed on this chain");
        require(CREATE2_FACTORY.code.length > 0, "deterministic deployment proxy not deployed on this chain");
        // The constructor enforces this too, but its reason is lost inside the factory call.
        require(emergencyTimelock > adminTimelock, "EMERGENCY_TIMELOCK must exceed ADMIN_TIMELOCK");
        // Zero caps deploy a Guard that can never batch / never field-match (every
        // batch reverts BatchTooLarge, every Tier-2 create CommitmentQueueFull).
        require(maxBatchLegs > 0 && maxCommitmentQueue > 0, "MAX_BATCH_LEGS and MAX_COMMITMENT_QUEUE must be > 0");

        bytes memory initCode = abi.encodePacked(
            type(FermionWalletGuard).creationCode,
            abi.encode(multiSend, adminTimelock, emergencyTimelock, maxBatchLegs, maxCommitmentQueue)
        );
        address predicted = vm.computeCreate2Address(salt, keccak256(initCode), CREATE2_FACTORY);
        guard = FermionWalletGuard(predicted);

        if (predicted.code.length > 0) {
            console2.log("FermionWalletGuard already deployed at:", predicted, "(nothing broadcast)");
        } else {
            vm.startBroadcast();
            (bool ok,) = CREATE2_FACTORY.call(abi.encodePacked(salt, initCode));
            vm.stopBroadcast();
            require(ok && predicted.code.length > 0, "CREATE2 deployment failed");
            console2.log("FermionWalletGuard deployed at:", predicted);
        }

        // Read back what the chain holds, not what the script meant to deploy.
        require(guard.MULTISEND_CALL_ONLY() == multiSend, "MULTISEND_CALL_ONLY mismatch");
        require(guard.ADMIN_TIMELOCK() == adminTimelock, "ADMIN_TIMELOCK mismatch");
        require(guard.EMERGENCY_TIMELOCK() == emergencyTimelock, "EMERGENCY_TIMELOCK mismatch");
        require(guard.MAX_BATCH_LEGS() == maxBatchLegs, "MAX_BATCH_LEGS mismatch");
        require(guard.MAX_COMMITMENT_QUEUE() == maxCommitmentQueue, "MAX_COMMITMENT_QUEUE mismatch");

        // Everything deployments.json records for this chain.
        console2.log("  chainId:", block.chainid);
        console2.log("  salt:");
        console2.logBytes32(salt);
        console2.log("  EXTCODEHASH:");
        console2.logBytes32(predicted.codehash);
        console2.log("  multiSendCallOnly:", multiSend);
        console2.log("  adminTimelock:", adminTimelock);
        console2.log("  emergencyTimelock:", emergencyTimelock);
        console2.log("  maxBatchLegs:", maxBatchLegs);
        console2.log("  maxCommitmentQueue:", maxCommitmentQueue);
    }

    /// Env values are read as uint256; an explicit narrowing cast would silently
    /// truncate an out-of-range value into a different, valid-looking parameter.
    function _u64(uint256 v, string memory name) private pure returns (uint64) {
        require(v <= type(uint64).max, string.concat(name, " does not fit uint64"));
        return uint64(v);
    }

    function _u32(uint256 v, string memory name) private pure returns (uint32) {
        require(v <= type(uint32).max, string.concat(name, " does not fit uint32"));
        return uint32(v);
    }
}
