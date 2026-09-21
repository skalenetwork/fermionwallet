// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {MultiSendCallOnly} from "@safe-global/safe-contracts/contracts/libraries/MultiSendCallOnly.sol";

import {Safe} from "@safe-global/safe-contracts/contracts/Safe.sol";
import {SafeProxyFactory} from "@safe-global/safe-contracts/contracts/proxies/SafeProxyFactory.sol";

import {FermionWalletGuard} from "../src/FermionWalletGuard.sol";

/// The v1.4.1 surface this test needs (identical ABI in v1.4.1 and v1.5.0).
interface ISafe141 {
    function setup(
        address[] calldata owners,
        uint256 threshold,
        address to,
        bytes calldata data,
        address fallbackHandler,
        address paymentToken,
        uint256 payment,
        address payable paymentReceiver
    ) external;
}

interface ISafeProxyFactory141 {
    function createProxyWithNonce(address singleton, bytes memory initializer, uint256 saltNonce)
        external
        returns (address proxy);
}

/// Legacy (pre-bytes32) EIP-1271 contract wallet — the interface Safe v1.3.0/v1.4.1
/// call for contract-owner signatures: `isValidSignature(bytes data, bytes sig)`.
/// Approves exact messages (by preimage), like a Safe owner's signMessage.
contract LegacyContractOwner {
    mapping(bytes32 => bool) public approved;

    function approveMessage(bytes calldata message) external {
        approved[keccak256(message)] = true;
    }

    function isValidSignature(bytes memory data, bytes memory) external view returns (bytes4) {
        return approved[keccak256(data)] ? bytes4(0x20c13b0b) : bytes4(0);
    }

    /// Current EIP-1271 (Safe v1.5.0 calls this with the digest itself).
    function isValidSignature(bytes32 digest, bytes memory) external view returns (bytes4) {
        return approved[digest] ? bytes4(0x1626ba7e) : bytes4(0);
    }
}

/// Registry ceremonies against a REAL legacy Safe, whose `checkSignatures(bytes32,
/// bytes data, bytes)` hands `data` — not the hash — to contract owners.
abstract contract LegacySafeRegistryTest is Test {
    uint256 internal constant OWNER_PK = 0xB1;
    uint256 internal constant LEDGER_PK = 0x1ED6E4;
    address internal owner = vm.addr(OWNER_PK);
    address internal ledger = vm.addr(LEDGER_PK);

    bytes32 internal constant ROOT = keccak256("root");
    bytes32 internal constant SEED = keccak256("seed");
    uint32 internal constant H = 4;
    bytes32 internal constant PARAM_SET = keccak256("XMSS-SHA2_4_256-TEST");

    bytes32 internal constant APPROVE_KEY_TYPEHASH = keccak256(
        "ApproveQuantumKey(address safe,address quantumAdmin,bytes32 xmssRoot,bytes32 xmssSeed,uint32 treeHeight,bytes32 parameterSet,uint256 registryNonce,uint256 validUntil)"
    );
    bytes32 internal constant ATTEST_KEY_TYPEHASH = keccak256(
        "QuantumKeyAttestation(address safe,bytes32 xmssRoot,bytes32 xmssSeed,uint32 treeHeight,bytes32 parameterSet,uint256 registryNonce)"
    );
    bytes32 internal constant REVOKE_KEY_TYPEHASH = keccak256(
        "RequestKeyRevocation(address safe,bytes32 quantumKeyId,uint256 registryNonce,uint256 validUntil)"
    );
    bytes32 internal constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    address internal safe;
    FermionWalletGuard internal guard;
    LegacyContractOwner internal wallet;

    function setUp() public {
        vm.warp(1_800_000_000);
        wallet = new LegacyContractOwner();
        (address singleton, address factoryAddr) = _singletonAndFactory();
        ISafeProxyFactory141 factory = ISafeProxyFactory141(factoryAddr);
        address[] memory owners = new address[](2);
        owners[0] = owner;
        owners[1] = address(wallet);
        bytes memory init =
            abi.encodeCall(ISafe141.setup, (owners, 2, address(0), "", address(0), address(0), 0, payable(address(0))));
        safe = factory.createProxyWithNonce(singleton, init, 1);
        guard = new FermionWalletGuard(address(new MultiSendCallOnly()), 2 days, 7 days, 4, 8);
    }

    /// Directory of the Safe/SafeProxyFactory creation bytecode for this version.
    function _vectorDir() internal pure virtual returns (string memory);

    function _singletonAndFactory() internal virtual returns (address singleton, address factory) {
        singleton = _deploy(string.concat(_vectorDir(), "/Safe.bin"));
        factory = _deploy(string.concat(_vectorDir(), "/SafeProxyFactory.bin"));
    }

    /// A contract owner of a legacy Safe co-signs the key ceremony by approving the
    /// EIP-712 message itself (0x1901 ‖ domain ‖ structHash). v1.4.1 requires
    /// keccak256(data) == dataHash for contract signatures (GS027); v1.3.0 hands
    /// `data` to the owner unchecked. The registry used to pass empty `data`, so such
    /// a Safe could never enroll.
    function test_ContractOwnerCoSignsRegistration() public {
        bytes32 structHash = _approveKeyStruct(block.timestamp + 1 days);
        wallet.approveMessage(_preimage(structHash));
        bytes32 keyId = _register(structHash, block.timestamp + 1 days);
        assertEq(guard.safeToQuantumKey(safe), keyId);
    }

    /// Same for the owner-governed emergency revocation request — and the contract
    /// owner's approval is per message: one it never approved is rejected (GS024).
    function test_ContractOwnerCoSignsRevocationRequest() public {
        bytes32 structHash = _approveKeyStruct(block.timestamp + 1 days);
        wallet.approveMessage(_preimage(structHash));
        bytes32 keyId = _register(structHash, block.timestamp + 1 days);

        uint256 validUntil = block.timestamp + 1 days;
        bytes32 revokeStruct =
            keccak256(abi.encode(REVOKE_KEY_TYPEHASH, safe, keyId, guard.registryNonce(safe), validUntil));
        bytes memory sigs = _sigs(_digest(revokeStruct));
        vm.expectRevert(bytes("GS024")); // not yet approved by the contract owner
        guard.requestKeyRevocation(safe, validUntil, sigs);

        wallet.approveMessage(_preimage(revokeStruct));
        guard.requestKeyRevocation(safe, validUntil, sigs);
        assertEq(guard.keyRevocationKeyId(safe), keyId);
    }

    // ── helpers ─────────────────────────────────────────────────────────────

    function _deploy(string memory binPath) internal returns (address a) {
        bytes memory code = vm.parseBytes(vm.trim(vm.readFile(binPath)));
        assembly {
            a := create(0, add(code, 32), mload(code))
        }
        require(a != address(0) && a.code.length > 0, "deploy failed");
    }

    function _approveKeyStruct(uint256 validUntil) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                APPROVE_KEY_TYPEHASH,
                safe,
                ledger,
                ROOT,
                SEED,
                H,
                PARAM_SET,
                guard.registryNonce(safe),
                validUntil
            )
        );
    }

    function _register(bytes32 structHash, uint256 validUntil) internal returns (bytes32) {
        uint256 nonce = guard.registryNonce(safe);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            LEDGER_PK,
            _digest(keccak256(abi.encode(ATTEST_KEY_TYPEHASH, safe, ROOT, SEED, H, PARAM_SET, nonce)))
        );
        return guard.registerQuantumKey(
            safe, ledger, ROOT, SEED, H, PARAM_SET, validUntil, abi.encodePacked(r, s, v), _sigs(_digest(structHash))
        );
    }

    function _domain() internal view returns (bytes32) {
        return keccak256(
            abi.encode(DOMAIN_TYPEHASH, keccak256("FermionWalletGuard"), keccak256("1"), block.chainid, address(guard))
        );
    }

    function _preimage(bytes32 structHash) internal view returns (bytes memory) {
        return abi.encodePacked(hex"1901", _domain(), structHash);
    }

    function _digest(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(_preimage(structHash));
    }

    /// Owner signatures sorted by owner address: the EOA's ECDSA signature and the
    /// contract owner's v = 0 signature (dynamic part: empty signature bytes).
    function _sigs(bytes32 digest) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_PK, digest);
        bytes memory eoaSig = abi.encodePacked(r, s, v);
        bytes memory contractSig = abi.encodePacked(bytes32(uint256(uint160(address(wallet)))), uint256(130), uint8(0));
        bytes memory head = owner < address(wallet) ? bytes.concat(eoaSig, contractSig) : bytes.concat(contractSig, eoaSig);
        return bytes.concat(head, abi.encode(uint256(0))); // contract signature: length 0
    }
}

/// test/vectors/safe-v1.4.1/*.bin: creation bytecode of Safe.sol and
/// proxies/SafeProxyFactory.sol at github.com/safe-global/safe-smart-account tag v1.4.1
/// (bf943f80), unmodified source, solc 0.8.37, optimizer 200 runs, no via-IR (the
/// v1.4.1 sources hit stack-too-deep under this repo's via-IR profile).
contract LegacySafe141Test is LegacySafeRegistryTest {
    function _vectorDir() internal pure override returns (string memory) {
        return "test/vectors/safe-v1.4.1";
    }
}

/// test/vectors/safe-v1.3.0/*.bin: creation bytecode of GnosisSafe.sol and
/// proxies/GnosisSafeProxyFactory.sol at github.com/safe-global/safe-smart-account tag
/// v1.3.0 (186a21a7), unmodified source, solc 0.8.20, optimizer 200 runs, no via-IR.
/// v1.3.0 has no GS027 check: it passes `data` straight to the owner's legacy
/// isValidSignature(bytes,bytes), which must see the exact EIP-712 preimage.
contract LegacySafe130Test is LegacySafeRegistryTest {
    function _vectorDir() internal pure override returns (string memory) {
        return "test/vectors/safe-v1.3.0";
    }
}

/// Control: Safe v1.5.0 (this repo's lib) ignores `data` in the legacy overload and
/// asks contract owners isValidSignature(bytes32 digest, bytes) — the same ceremony
/// must keep working there.
contract Safe150ContractOwnerTest is LegacySafeRegistryTest {
    function _vectorDir() internal pure override returns (string memory) {
        return "";
    }

    function _singletonAndFactory() internal override returns (address, address) {
        return (address(new Safe()), address(new SafeProxyFactory()));
    }
}
