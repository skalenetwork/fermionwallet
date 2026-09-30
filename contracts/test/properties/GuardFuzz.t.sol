// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ERC20Mock as MockToken} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";
import {Enum} from "@safe-global/safe-contracts/contracts/libraries/Enum.sol";

import {FermionGuard} from "../../src/FermionGuard.sol";
import {PreApprovalEngine, NO_MATCHING_PRE_APPROVAL} from "../../src/PreApprovalEngine.sol";
import {QuantumKeyRegistry} from "../../src/QuantumKeyRegistry.sol";
import {PropertyBase, FermionGuardHarness} from "./PropertyBase.sol";

/// Stateless property (fuzz) tests over a real Safe v1.5.0 with the Guard wired as both
/// transaction guard and module guard. Hybrid-signed approvals are created ONCE in setUp
/// (one batch FFI call); every fuzz run starts from that snapshot, so no property here
/// needs a fresh XMSS signature per run.
contract GuardFuzzTest is PropertyBase {
    // Approvals created in setUp.
    bytes32 internal idA; // TRANSFER token → recipient, 1000, Tier-2
    bytes32 internal idB; // PAYLOAD native send → recipient, 5 wei, Tier-2
    bytes32 internal idC; // PAYLOAD MultiSendCallOnly batch, Tier-2
    bytes32 internal idD; // TRANSFER token → recipient, 3000, Tier-1 pinned (safeTxGas 0, current nonce)
    bytes32 internal idW; // TRANSFER token → recipient2, 777, window [T0 + 1 d, T0 + 2 d]
    bytes32 internal idP; // TRANSFER token → recipient2, 888, same window, Tier-1 pinned
    bytes internal batchData;

    uint256 internal constant AMT_A = 1000;
    uint256 internal constant VAL_B = 5;
    uint256 internal constant AMT_D = 3000;
    uint256 internal constant AMT_W = 777;
    uint256 internal constant AMT_P = 888;
    uint64 internal constant W_FROM = T0 + 1 days;
    uint64 internal constant W_TO = T0 + 2 days;

    function setUp() public {
        _deployFixture(true);
        batchData = abi.encodeWithSignature(
            "multiSend(bytes)",
            abi.encodePacked(
                _leg(address(token), 0, _transferData(recipient, 7)), _leg(address(token2), 0, _transferData(recipient2, 8))
            )
        );
        bytes32 pinD = _txHash(address(token), 0, _transferData(recipient, AMT_D), Enum.Operation.Call, 0, safe.nonce());

        bytes32 pinP = _txHash(address(token), 0, _transferData(recipient2, AMT_P), Enum.Operation.Call, 0, safe.nonce());

        PreApprovalEngine.PreApprovalRequest[] memory reqs = new PreApprovalEngine.PreApprovalRequest[](6);
        uint8[] memory classes = new uint8[](6);
        uint64 to_ = T0 + 2 days;
        reqs[0] = _transferReq(address(token), recipient, AMT_A, 0, T0, to_, bytes32(0));
        reqs[1] = _payloadReq(recipient, VAL_B, keccak256(""), 1, T0, to_, bytes32(0));
        reqs[2] = _payloadReq(address(msco), 0, keccak256(batchData), 2, T0, to_, bytes32(0));
        reqs[3] = _transferReq(address(token), recipient, AMT_D, 3, T0, to_, pinD);
        reqs[4] = _transferReq(address(token), recipient2, AMT_W, 4, W_FROM, W_TO, bytes32(0));
        reqs[5] = _transferReq(address(token), recipient2, AMT_P, 5, W_FROM, W_TO, pinP);
        classes[1] = C_PAYLOAD;
        classes[2] = C_PAYLOAD;
        (bytes[] memory e, bytes[] memory x) = _signAll(reqs, classes);
        vm.startPrank(relayer);
        idA = _submit(reqs[0], classes[0], e[0], x[0]);
        idB = _submit(reqs[1], classes[1], e[1], x[1]);
        idC = _submit(reqs[2], classes[2], e[2], x[2]);
        idD = _submit(reqs[3], classes[3], e[3], x[3]);
        idW = _submit(reqs[4], classes[4], e[4], x[4]);
        idP = _submit(reqs[5], classes[5], e[5], x[5]);
        vm.stopPrank();
    }

    function _ids() internal view returns (bytes32[6] memory) {
        return [idA, idB, idC, idD, idW, idP];
    }

    function _usedCount() internal view returns (uint256 n) {
        bytes32[6] memory ids = _ids();
        for (uint256 i = 0; i < 6; ++i) {
            if (guard.getPreApproval(ids[i]).used) ++n;
        }
    }

    // ═════════ P1: no execution without consumption (escape hatch excepted) ═════════

    /// Arbitrary owner-signed Safe transactions (target, value, calldata shape, operation,
    /// safeTxGas) under arbitrary Guard-relevant state. Whatever executes is either a
    /// spec-listed escape-hatch call (and then consumes nothing), or it consumed exactly
    /// one approval.
    /// forge-config: default.fuzz.runs = 1024
    /// Covers: [GRD-054], [GRD-072], [GRD-116]
    function testFuzz_NothingExecutesWithoutConsumingAnApproval(
        uint8 toSel,
        address rnd,
        uint256 value,
        uint8 selSel,
        address arg,
        bytes calldata tail,
        uint8 shape,
        bool delegate,
        bool withSafeTxGas,
        uint8 state,
        bool viaModule
    ) public {
        _enterState(state % 4);

        address to = _pickTarget(toSel, rnd);
        bytes4 sel = _pickSelector(selSel, rnd);
        bytes memory data = _shape(shape, sel, arg, tail);
        if (value % 3 == 0) value = 0;
        else value = bound(value, 1, 1000 ether);
        Enum.Operation op = delegate ? Enum.Operation.DelegateCall : Enum.Operation.Call;

        uint256 usedBefore = _usedCount();
        bool ok;
        if (viaModule) {
            (ok,) = _tryModuleExec(to, value, data, op);
        } else {
            (ok,) = _tryExec(to, value, data, op, withSafeTxGas ? 1_000_000 : 0);
        }
        uint256 consumed = _usedCount() - usedBefore;

        bool escape = !viaModule && _isEscape(to, value, data, op, state % 4);
        if (escape) assertEq(consumed, 0, "escape call consumed an approval");
        if (ok && !escape) assertEq(consumed, 1, "executed without consuming exactly one approval");
        assertLe(consumed, 1, "one transaction consumed several approvals");
        assertEq(uint256(vm.load(address(safe), FALLBACK_SLOT)), 0, "guarded Safe acquired a fallback handler");
    }

    /// 0 normal, 1 paused, 2 emergency de-guard requested, 3 emergency de-guard matured.
    function _enterState(uint8 s) internal {
        if (s == 1) {
            _safeExec(address(guard), 0, abi.encodeCall(FermionGuard.pauseSafe, (address(safe))), Enum.Operation.Call);
        } else if (s >= 2) {
            _safeExec(address(guard), 0, abi.encodeCall(FermionGuard.requestEmergencyDeGuard, ()), Enum.Operation.Call);
            if (s == 3) vm.warp(vm.getBlockTimestamp() + EMERGENCY_TIMELOCK);
        }
    }

    /// Independent restatement of the spec's escape-hatch family (guard-module.md,
    /// "Emergency de-guard path — mechanism").
    function _isEscape(address to, uint256 value, bytes memory data, Enum.Operation op, uint8 state)
        internal
        view
        returns (bool)
    {
        if (op != Enum.Operation.Call || value != 0 || data.length < 4) return false;
        bytes4 s = bytes4(data);
        if (to == address(guard)) {
            if (data.length == 4) {
                return s == FermionGuard.requestEmergencyDeGuard.selector
                    || s == FermionGuard.requestUnpauseSafe.selector || s == FermionGuard.unpauseSafe.selector;
            }
            if (data.length == 36) {
                return s == FermionGuard.cancelEmergencyDeGuard.selector || s == FermionGuard.pauseSafe.selector
                    || s == PreApprovalEngine.revokePreApproval.selector
                    || s == QuantumKeyRegistry.cancelKeyRevocation.selector;
            }
            return false;
        }
        if (to == address(safe) && state == 3 && data.length >= 36 && s == bytes4(keccak256("setGuard(address)"))) {
            return _argWord(data) == 0;
        }
        return false;
    }

    function _argWord(bytes memory data) internal pure returns (uint256 w) {
        assembly ("memory-safe") {
            w := mload(add(data, 36))
        }
    }

    function _pickTarget(uint8 s, address rnd) internal view returns (address) {
        uint8 k = s % 8;
        if (k == 0) return address(token);
        if (k == 1) return address(guard);
        if (k == 2) return address(safe);
        if (k == 3) return address(msco);
        if (k == 4) return recipient;
        if (k == 5) return address(0);
        if (k == 6) return address(token2);
        return rnd;
    }

    function _pickSelector(uint8 s, address rnd) internal pure returns (bytes4) {
        bytes4[20] memory sels = [
            IERC20.transfer.selector,
            IERC20.approve.selector,
            IERC20.transferFrom.selector,
            bytes4(keccak256("increaseAllowance(address,uint256)")),
            bytes4(keccak256("setGuard(address)")),
            bytes4(keccak256("setFallbackHandler(address)")),
            bytes4(keccak256("enableModule(address)")),
            bytes4(keccak256("setModuleGuard(address)")),
            FermionGuard.pauseSafe.selector,
            FermionGuard.requestEmergencyDeGuard.selector,
            FermionGuard.requestUnpauseSafe.selector,
            FermionGuard.unpauseSafe.selector,
            FermionGuard.cancelEmergencyDeGuard.selector,
            PreApprovalEngine.revokePreApproval.selector,
            QuantumKeyRegistry.cancelKeyRevocation.selector,
            FermionGuard.setSelectorPolicy.selector,
            bytes4(keccak256("multiSend(bytes)")),
            bytes4(keccak256("addOwnerWithThreshold(address,uint256)")),
            MockToken.mint.selector,
            bytes4(bytes20(rnd))
        ];
        return sels[s % 20];
    }

    function _shape(uint8 shape, bytes4 sel, address arg, bytes calldata tail) internal pure returns (bytes memory) {
        uint8 k = shape % 6;
        if (k == 0) return "";
        if (k == 1) return abi.encodePacked(sel);
        if (k == 2) return abi.encodePacked(sel, uint256(uint160(arg)));
        if (k == 3) return abi.encodePacked(sel, uint256(uint160(arg)), tail);
        if (k == 4) return tail;
        return abi.encodePacked(sel, uint256(uint160(arg)), uint256(1000));
    }

    // ═════════════ P2: matching is exact — no near-miss ever executes ═════════════

    /// Take one approved transaction and perturb exactly one bound field (amount/value ±δ,
    /// recipient, token/target, operation, trailing calldata) or an unbound one (safeTxGas,
    /// execution path). Executes iff the approval's binding is untouched; on success
    /// exactly that approval is consumed and exactly the approved effect happens.
    /// forge-config: default.fuzz.runs = 1024
    /// Covers: [GRD-057], [GRD-058], [GRD-117], [GRD-120], [ENG-036]
    /// The `amount` argument of an ERC-20 `transfer(address,uint256)` payload.
    function _transferAmount(bytes memory data) internal pure returns (uint256 amount) {
        assembly ("memory-safe") {
            amount := mload(add(data, 68)) // 32 length + 4 selector + 32 recipient
        }
    }

    function testFuzz_MatchingIsExact(uint8 base, uint8 mutation, uint256 delta, address other, bytes calldata junk, bool viaModule)
        public
    {
        base = base % 4; // 0 = A transfer, 1 = B native, 2 = C batch, 3 = D pinned transfer
        mutation = mutation % 8;
        delta = bound(delta, 1, 1e30);
        vm.assume(other != recipient && other != address(0) && other != address(token) && other != address(token2));
        vm.assume(other != address(safe) && other != address(guard) && other != address(msco));
        vm.assume(junk.length > 0);

        (address to, uint256 value, bytes memory data, Enum.Operation op) = _baseTx(base);
        uint256 safeTxGas = 0;

        if (mutation == 1 || mutation == 2) {
            // amount (transfer) / value (native, batch) ± δ
            bool up = mutation == 1;
            if (base == 0 || base == 3) {
                uint256 amt = base == 0 ? AMT_A : AMT_D;
                data = _transferData(recipient, up ? amt + delta : amt - (1 + delta % amt));
            } else if (up || value == 0) {
                value = value + 1 + (delta % 1000 ether);
            } else {
                value = value - (1 + delta % value);
            }
        } else if (mutation == 3) {
            if (base == 1) to = other; // native: recipient is the target
            else if (base == 2) data = _batchWithSecondRecipient(other);
            else data = _transferData(other, base == 0 ? AMT_A : AMT_D);
        } else if (mutation == 4) {
            to = base == 1 ? other : (base == 2 ? other : address(token2)); // token / target swap
        } else if (mutation == 5) {
            op = op == Enum.Operation.Call ? Enum.Operation.DelegateCall : Enum.Operation.Call;
        } else if (mutation == 6) {
            data = bytes.concat(data, junk);
        } else if (mutation == 7) {
            safeTxGas = 1 + (delta % 1e6); // unbound for Tier-2, part of the Tier-1 pin
        }

        // A mutation can land exactly on ANOTHER approval's transaction, and then the Guard
        // is right to let it through — "matching is exact" says an approval authorizes one
        // set of fields, not that every mutation of one transaction is refused. The
        // fixture holds A (1000 to `recipient`) and D (3000 to `recipient`, pinned), so
        // `base = A, mutation = amount + 2000` reconstructs D byte for byte, including its
        // pinned `safeTxHash`, and executes. The fuzzer found that with a seed after this
        // test had been green all day; it is the expectation that was wrong, not the Guard.
        if ((base == 0 || base == 3) && (mutation == 1 || mutation == 2)) {
            uint256 mutated = _transferAmount(data);
            vm.assume(mutated != AMT_A && mutated != AMT_D);
        }

        // Owner path: safeTxGas is bound only by the Tier-1 pin. Module path: Tier-2 only
        // (no pin, safeTxGas does not exist), and never a delegatecall (no batch).
        bool expected = viaModule
            ? base <= 1 && (mutation == 0 || mutation == 7)
            : mutation == 0 || (mutation == 7 && base != 3);

        uint256 balR = token.balanceOf(recipient);
        uint256 ethR = recipient.balance;
        bool ok;
        if (viaModule) (ok,) = _tryModuleExec(to, value, data, op);
        else (ok,) = _tryExec(to, value, data, op, safeTxGas);

        assertEq(ok, expected, "execution outcome differs from exact-match expectation");
        bytes32[6] memory ids = _ids();
        for (uint256 i = 0; i < 4; ++i) {
            assertEq(guard.getPreApproval(ids[i]).used, ok && i == base, "wrong approval consumed");
        }
        if (ok) {
            if (base == 0) assertEq(token.balanceOf(recipient), balR + AMT_A);
            if (base == 1) assertEq(recipient.balance, ethR + VAL_B);
            if (base == 2) assertEq(token.balanceOf(recipient), balR + 7);
            if (base == 3) assertEq(token.balanceOf(recipient), balR + AMT_D);
        } else {
            assertEq(token.balanceOf(recipient), balR);
            assertEq(recipient.balance, ethR);
        }
    }

    function _baseTx(uint8 base) internal view returns (address, uint256, bytes memory, Enum.Operation) {
        if (base == 0) return (address(token), 0, _transferData(recipient, AMT_A), Enum.Operation.Call);
        if (base == 1) return (recipient, VAL_B, "", Enum.Operation.Call);
        if (base == 2) return (address(msco), 0, batchData, Enum.Operation.DelegateCall);
        return (address(token), 0, _transferData(recipient, AMT_D), Enum.Operation.Call);
    }

    function _batchWithSecondRecipient(address r2) internal view returns (bytes memory) {
        return abi.encodeWithSignature(
            "multiSend(bytes)",
            abi.encodePacked(_leg(address(token), 0, _transferData(recipient, 7)), _leg(address(token2), 0, _transferData(r2, 8)))
        );
    }

    // ═════════ P3: MultiSend batches — the Guard's decoder vs MultiSend's own ═════════

    struct Leg {
        uint8 op;
        address to;
        uint256 value;
        bytes data;
    }

    /// Random batches (arbitrary targets, selectors, calldata lengths, operations, leg
    /// counts) plus structural corruptions (truncation, suffix, over/under-stated leg
    /// lengths). Soundness: whenever the Guard's structural checks pass (it proceeds to
    /// approval matching), every leg MultiSendCallOnly would actually execute — decoded
    /// here with MultiSend's own lenient loop — is a permitted CALL. Completeness: every
    /// well-formed, policy-clean batch within the leg cap passes.
    /// forge-config: default.fuzz.runs = 2048
    /// Covers: [GRD-106], [GRD-107], [GRD-108], [GRD-109], [GRD-128]
    function testFuzz_BatchDecoderSoundAndComplete(uint256 seed, uint8 nLegs, uint8 corruption, uint8 k) public {
        uint256 n = nLegs % 7;
        bytes memory packed;
        bool policyClean = true;
        for (uint256 i = 0; i < n; ++i) {
            Leg memory l = _randomLeg(uint256(keccak256(abi.encode(seed, i))));
            if (!_legPermitted(l.op, l.to, l.data)) policyClean = false;
            packed = bytes.concat(packed, abi.encodePacked(l.op, l.to, l.value, l.data.length, l.data));
        }
        uint8 c = corruption % 5;
        uint256 kk = uint256(k) % 40 + 1;
        if (c == 1 && packed.length > 0) {
            // truncate
            uint256 cut = kk > packed.length ? packed.length : kk;
            assembly ("memory-safe") {
                mstore(packed, sub(mload(packed), cut))
            }
        } else if (c == 2) {
            packed = bytes.concat(packed, new bytes(kk)); // smuggled suffix
        } else if (c >= 3 && n > 0) {
            // over/under-state the first leg's dataLength
            uint256 len;
            assembly ("memory-safe") {
                len := mload(add(packed, 85))
            }
            uint256 newLen = c == 3 ? len + kk : (kk > len ? 0 : len - kk);
            assembly ("memory-safe") {
                mstore(add(packed, 85), newLen)
            }
        } else {
            c = 0;
        }
        bytes memory data = abi.encodeWithSignature("multiSend(bytes)", packed);

        vm.prank(address(safe));
        (bool passed, bytes memory err) = address(guard).call(
            abi.encodeCall(
                FermionGuard.checkTransaction,
                (address(msco), 0, data, Enum.Operation.DelegateCall, 0, 0, 0, address(0), payable(address(0)), "", relayer)
            )
        );
        assertFalse(passed, "unapproved batch accepted");
        bool structuralPass = keccak256(err) == keccak256(abi.encodeWithSignature("Error(string)", NO_MATCHING_PRE_APPROVAL));

        if (structuralPass) {
            // Soundness against MultiSend's actual interpretation of the blob.
            (Leg[] memory legs, uint256 count) = _multiSendView(packed);
            assertLe(count, MAX_BATCH_LEGS, "more legs than MAX_BATCH_LEGS");
            for (uint256 i = 0; i < count; ++i) {
                assertTrue(_legPermitted(legs[i].op, legs[i].to, legs[i].data), "forbidden leg passed the Guard");
            }
        }
        if (c == 0 && policyClean && n <= MAX_BATCH_LEGS) {
            assertTrue(structuralPass, "well-formed, policy-clean batch rejected");
        }
    }

    function _randomLeg(uint256 r) internal view returns (Leg memory l) {
        l.op = r % 17 == 0 ? 1 : 0;
        uint256 t = (r >> 8) % 9;
        address[9] memory targets = [
            address(token),
            address(token2),
            recipient,
            address(safe),
            address(0),
            address(guard),
            address(msco),
            address(uint160(r >> 96)),
            recipient2
        ];
        l.to = targets[t];
        l.value = (r >> 16) % 4 == 0 ? (r >> 40) % 1 ether : 0;
        uint256 kind = (r >> 24) % 7;
        if (kind == 0) l.data = "";
        else if (kind == 1) l.data = new bytes(1 + (r >> 32) % 3); // 1–3 bytes
        else if (kind == 2) l.data = _transferData(recipient, (r >> 48) % 1e18);
        else if (kind == 3) l.data = abi.encodeCall(IERC20.approve, (recipient, 1));
        else if (kind == 4) l.data = abi.encodeCall(MockToken.mint, (recipient, 1));
        else if (kind == 5) l.data = abi.encodeCall(IERC20.transferFrom, (address(safe), recipient, 1));
        else l.data = abi.encodePacked(bytes4(uint32(r >> 64)), bytes32(r));
    }

    /// Policy for one executed leg (spec, "Batch" + dispatch rules).
    function _legPermitted(uint8 op, address to, bytes memory data) internal view returns (bool) {
        if (op != 0) return false;
        if (to == address(safe) || to == address(0) || to == address(guard) || to == address(msco)) return false;
        if (data.length == 0) return true;
        if (data.length < 4) return false;
        bytes4 s = bytes4(data);
        if (
            s == IERC20.approve.selector || s == IERC20.transferFrom.selector
                || s == bytes4(keccak256("increaseAllowance(address,uint256)")) || s == bytes4(0xd505accf)
        ) return false;
        return guard.allowedSelectors(address(safe), s);
    }

    /// MultiSendCallOnly's own loop, transcribed: read headers at i while i < length,
    /// advance by 85 + dataLength; bytes beyond the blob read as zero.
    function _multiSendView(bytes memory blob) internal pure returns (Leg[] memory legs, uint256 count) {
        legs = new Leg[](64);
        uint256 i = 0;
        while (i + 32 < blob.length && count < 64) { // MultiSend: `lt(i, length)` with i from 0x20
            Leg memory l;
            l.op = uint8(_byteAt(blob, i));
            uint256 toWord;
            for (uint256 b = 0; b < 20; ++b) {
                toWord = (toWord << 8) | _byteAt(blob, i + 1 + b);
            }
            l.to = address(uint160(toWord));
            uint256 len;
            for (uint256 b = 0; b < 32; ++b) {
                len = (len << 8) | _byteAt(blob, i + 53 + b);
            }
            if (len > blob.length) len = blob.length; // beyond the blob MultiSend reads garbage; cap the view
            l.data = new bytes(len);
            for (uint256 b = 0; b < len; ++b) {
                l.data[b] = bytes1(uint8(_byteAt(blob, i + 85 + b)));
            }
            legs[count++] = l;
            i += 85 + len;
        }
    }

    function _byteAt(bytes memory b, uint256 i) internal pure returns (uint256) {
        return i < b.length ? uint8(b[i]) : 0;
    }

    // ═══════════════════ P4: validity windows at the boundaries ═══════════════════

    /// Execution at time t succeeds iff validFrom <= t <= validTo (both inclusive) — for
    /// a Tier-2 approval (owner and module path) and a Tier-1 pinned one.
    /// forge-config: default.fuzz.runs = 512
    /// Covers: [GRD-118], [ENG-034]
    function testFuzz_ValidityWindowEnforcedAtBoundaries(uint8 pick, uint64 rnd, uint8 path) public {
        uint64[6] memory probes = [W_FROM - 1, W_FROM, W_TO, W_TO + 1, T0 + (rnd % 3 days), W_FROM + (rnd % 1 days)];
        uint64 t = probes[pick % 6];
        vm.warp(t);
        path = path % 3; // 0 owner Tier-2, 1 module Tier-2, 2 owner Tier-1 pin
        bytes memory pay = _transferData(recipient2, path == 2 ? AMT_P : AMT_W);
        bool ok;
        if (path == 1) (ok,) = _tryModuleExec(address(token), 0, pay, Enum.Operation.Call);
        else (ok,) = _tryExec(address(token), 0, pay, Enum.Operation.Call, 0);
        assertEq(ok, t >= W_FROM && t <= W_TO, "window boundary not enforced");
        assertEq(guard.getPreApproval(path == 2 ? idP : idW).used, ok);
    }

    /// Creation-time window and ADMIN-timelock rules for arbitrary (validFrom, validTo,
    /// now). Checked before any signature work, so a garbage signature isolates them:
    /// a request passing every time rule dies on the ECDSA half instead.
    /// forge-config: default.fuzz.runs = 1024
    /// Covers: [GRD-059], [GRD-111], [ENG-026], [ENG-029]
    function testFuzz_CreationTimeRules(uint64 from, uint64 to_, uint32 nowOffset, uint8 class_) public {
        vm.warp(uint256(T0) + nowOffset);
        uint64 nowTs = uint64(vm.getBlockTimestamp());
        class_ = class_ % 3;
        // Keep the interesting region dense: around now and around each other.
        from = uint64(bound(from, nowTs - 10 days, nowTs + 10 days));
        to_ = uint64(bound(to_, uint256(from) > 1 hours ? from - 1 hours : 0, uint256(from) + 3 days));

        PreApprovalEngine.PreApprovalRequest memory req;
        req.safe = address(safe);
        if (class_ == C_TRANSFER) {
            req.token = address(token);
            req.recipient = recipient;
            req.amount = 1;
        } else {
            req.target = class_ == C_ADMIN ? address(safe) : recipient;
        }
        req.validFrom = from;
        req.validTo = to_;
        req.nonce = keccak256(abi.encode(from, to_, nowOffset));
        req.quantumKeyId = keyId;

        bytes memory expectedErr;
        if (class_ == C_ADMIN && uint256(from) < uint256(nowTs) + ADMIN_TIMELOCK) {
            expectedErr = abi.encodeWithSelector(
                PreApprovalEngine.AdminTimelockNotRespected.selector, from, nowTs + ADMIN_TIMELOCK
            );
        } else if (to_ <= from || to_ - from < 15 minutes || to_ <= nowTs) {
            expectedErr = abi.encodeWithSelector(PreApprovalEngine.InvalidWindow.selector, from, to_);
        } else {
            expectedErr = abi.encodeWithSelector(PreApprovalEngine.InvalidEcdsaSignature.selector);
        }
        vm.expectRevert(expectedErr);
        _submit(req, class_, "", "");
    }

    // ═══════════════ P5: timelocks and cooldowns cannot be shortened ═══════════════

    /// Unpause executes iff at least ADMIN_TIMELOCK elapsed since the (latest) request;
    /// single-key re-pauses in between never cancel or shorten the pending request.
    /// forge-config: default.fuzz.runs = 512
    /// Covers: [GRD-093], [GRD-094], [GRD-095], [GRD-132]
    function testFuzz_UnpauseTimelock(uint32 d1, uint32 d2, bool ownerRepauses, bool rerequest, uint32 d3) public {
        d1 = uint32(bound(d1, 0, 3 * ADMIN_TIMELOCK));
        d2 = uint32(bound(d2, 0, 3 * ADMIN_TIMELOCK));
        d3 = uint32(bound(d3, 0, ADMIN_TIMELOCK));
        vm.prank(owner1);
        guard.pauseSafe(address(safe));
        vm.warp(vm.getBlockTimestamp() + d1);
        _safeExec(address(guard), 0, abi.encodeCall(FermionGuard.requestUnpauseSafe, ()), Enum.Operation.Call);
        uint256 requestedAt = vm.getBlockTimestamp();
        if (ownerRepauses) {
            vm.warp(vm.getBlockTimestamp() + d3);
            vm.prank(owner2);
            guard.pauseSafe(address(safe)); // no cooldown yet: allowed, but must not reset the request
        }
        if (rerequest) {
            vm.warp(vm.getBlockTimestamp() + d3);
            uint64 before = guard.safeUnpauseExecutableAt(address(safe));
            _safeExec(address(guard), 0, abi.encodeCall(FermionGuard.requestUnpauseSafe, ()), Enum.Operation.Call);
            assertGe(guard.safeUnpauseExecutableAt(address(safe)), before, "re-request shortened the unpause timelock");
            requestedAt = vm.getBlockTimestamp();
        }
        vm.warp(vm.getBlockTimestamp() + d2);
        (bool ok,) = _tryExec(address(guard), 0, abi.encodeCall(FermionGuard.unpauseSafe, ()), Enum.Operation.Call, 0);
        assertEq(ok, vm.getBlockTimestamp() >= requestedAt + ADMIN_TIMELOCK, "unpause timelock");
        assertEq(guard.safePaused(address(safe)), !ok);
        if (ok) {
            // Cooldown: single keys cannot re-pause for ADMIN_TIMELOCK; the Safe always can.
            uint256 unpausedAt = vm.getBlockTimestamp();
            vm.warp(vm.getBlockTimestamp() + d3);
            vm.prank(owner3);
            (bool paused,) = address(guard).call(abi.encodeCall(FermionGuard.pauseSafe, (address(safe))));
            assertEq(paused, vm.getBlockTimestamp() >= unpausedAt + ADMIN_TIMELOCK, "pause cooldown");
            vm.prank(ledger);
            (bool pausedByAdmin,) = address(guard).call(abi.encodeCall(FermionGuard.pauseSafe, (address(safe))));
            assertEq(pausedByAdmin, vm.getBlockTimestamp() >= unpausedAt + ADMIN_TIMELOCK, "admin pause cooldown");
            vm.prank(stranger);
            (bool pausedByStranger,) = address(guard).call(abi.encodeCall(FermionGuard.pauseSafe, (address(safe))));
            assertFalse(pausedByStranger);
        }
    }

    /// The owner-only Guard removal unlocks iff EMERGENCY_TIMELOCK elapsed since the
    /// latest request; re-requests only ever push the unlock later.
    /// forge-config: default.fuzz.runs = 512
    /// Covers: [GRD-075], [GRD-077], [GRD-078]
    function testFuzz_EmergencyDeGuardTimelock(uint32 d, uint32 gap, bool rerequest) public {
        d = uint32(bound(d, 0, 3 * EMERGENCY_TIMELOCK));
        gap = uint32(bound(gap, 0, EMERGENCY_TIMELOCK));
        _safeExec(address(guard), 0, abi.encodeCall(FermionGuard.requestEmergencyDeGuard, ()), Enum.Operation.Call);
        uint256 requestedAt = vm.getBlockTimestamp();
        if (rerequest) {
            vm.warp(vm.getBlockTimestamp() + gap);
            uint64 before = guard.emergencyDeGuardExecutableAt(address(safe));
            _safeExec(address(guard), 0, abi.encodeCall(FermionGuard.requestEmergencyDeGuard, ()), Enum.Operation.Call);
            assertGe(guard.emergencyDeGuardExecutableAt(address(safe)), before);
            requestedAt = vm.getBlockTimestamp();
        }
        vm.warp(vm.getBlockTimestamp() + d);
        (bool ok,) =
            _tryExec(address(safe), 0, abi.encodeWithSignature("setGuard(address)", address(0)), Enum.Operation.Call, 0);
        assertEq(ok, vm.getBlockTimestamp() >= requestedAt + EMERGENCY_TIMELOCK, "emergency timelock");
        assertEq(uint256(vm.load(address(safe), GUARD_SLOT)) == 0, ok);
        if (ok) assertEq(guard.emergencyDeGuardExecutableAt(address(safe)), 0, "request outlived the removal");
    }

    /// Emergency key revocation executes iff EMERGENCY_ROTATION_TIMELOCK elapsed.
    /// forge-config: default.fuzz.runs = 256
    /// Covers: [GRD-122], [QKR-020], [QKR-023], [ENG-035]
    function testFuzz_KeyRevocationTimelock(uint32 d) public {
        d = uint32(bound(d, 0, 3 * EMERGENCY_TIMELOCK));
        uint256 validUntil = vm.getBlockTimestamp() + 1 days;
        bytes32 digest = _guardDigest(
            keccak256(abi.encode(REVOKE_KEY_TYPEHASH, address(safe), keyId, guard.registryNonce(address(safe)), validUntil))
        );
        vm.prank(relayer);
        guard.requestKeyRevocation(address(safe), validUntil, _ownerSigs(digest));
        uint256 requestedAt = vm.getBlockTimestamp();
        vm.warp(vm.getBlockTimestamp() + d);
        (bool ok,) = address(guard).call(abi.encodeCall(QuantumKeyRegistry.executeKeyRevocation, (address(safe))));
        assertEq(ok, vm.getBlockTimestamp() >= requestedAt + EMERGENCY_TIMELOCK);
        if (ok) {
            // Every approval under the revoked key is dead immediately.
            (bool executed,) = _tryExec(address(token), 0, _transferData(recipient, AMT_A), Enum.Operation.Call, 0);
            assertFalse(executed);
        }
    }

    /// Gas refunds are refused for every transaction, escape calls included.
    /// forge-config: default.fuzz.runs = 256
    /// Covers: [GRD-074], [GRD-079]
    function testFuzz_GasRefundAlwaysRejected(uint256 gasPrice, uint256 baseGas, bool escapeCall, bool refundInToken) public {
        gasPrice = bound(gasPrice, 1, 1e30);
        baseGas = bound(baseGas, 0, 1e6);
        (address to, bytes memory data) = escapeCall
            ? (address(guard), abi.encodeCall(FermionGuard.requestEmergencyDeGuard, ()))
            : (address(token), _transferData(recipient, AMT_A));
        address gasToken = refundInToken ? address(token) : address(0);
        bytes32 h = safe.getTransactionHash(
            to, 0, data, Enum.Operation.Call, 0, baseGas, gasPrice, gasToken, stranger, safe.nonce()
        );
        bytes memory sigs = _ownerSigs(h);
        vm.expectRevert(FermionGuard.GasRefundForbidden.selector);
        safe.execTransaction(to, 0, data, Enum.Operation.Call, 0, baseGas, gasPrice, gasToken, payable(stranger), sigs);
    }

    // ═════ P6: a guarded Safe never acquires a fallback handler (ERC-1271 bypass) ═════

    /// `setFallbackHandler(h)` for any non-zero h is rejected before approval matching —
    /// whatever trails the argument (Safe's ABI decoder ignores trailing calldata), on the
    /// owner path and the module path alike.
    /// forge-config: default.fuzz.runs = 512
    /// Covers: [GRD-043], [GRD-052], [GRD-053], [GRD-055]
    function testFuzz_FallbackHandlerInstallRejectedBeforeMatching(address handler, bytes calldata tail, bool viaModule)
        public
    {
        vm.assume(handler != address(0));
        bytes memory data = abi.encodePacked(abi.encodeWithSignature("setFallbackHandler(address)", handler), tail);
        vm.expectRevert(abi.encodeWithSelector(FermionGuard.FallbackHandlerForbidden.selector, address(safe), handler));
        vm.prank(address(safe));
        if (viaModule) {
            guard.checkModuleTransaction(address(safe), 0, data, Enum.Operation.Call, module);
        } else {
            guard.checkTransaction(
                address(safe), 0, data, Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", relayer
            );
        }
    }

    /// End to end: even a matching, timelock-elapsed ADMIN approval cannot install a
    /// handler by padding the calldata the Guard pattern-matches on.
    /// Covers: [GRD-052], [GRD-053]
    function test_PaddedSetFallbackHandler_WithAdminApproval_Rejected() public {
        address handler = makeAddr("compatHandler");
        bytes memory data =
            abi.encodePacked(abi.encodeWithSignature("setFallbackHandler(address)", handler), bytes32(uint256(0xbeef)));
        PreApprovalEngine.PreApprovalRequest memory req =
            _payloadReq(address(safe), 0, keccak256(data), 10, T0 + ADMIN_TIMELOCK, T0 + ADMIN_TIMELOCK + 1 days, bytes32(0));
        _createSigned(req, C_ADMIN);
        vm.warp(T0 + ADMIN_TIMELOCK + 1);
        (bool ok, bytes memory err) = _tryExec(address(safe), 0, data, Enum.Operation.Call, 0);
        assertFalse(ok, "padded setFallbackHandler executed");
        assertEq(err, abi.encodeWithSelector(FermionGuard.FallbackHandlerForbidden.selector, address(safe), handler));
        assertEq(uint256(vm.load(address(safe), FALLBACK_SLOT)), 0);
    }

    /// End to end: a padded ADMIN-approved `setGuard(other)` still ends this Guard's
    /// tenure, so a pending emergency de-guard request must not survive it.
    /// Covers: [GRD-053], [GRD-078]
    function test_PaddedSetGuard_ClearsPendingEmergencyRequest() public {
        FermionGuardHarness other =
            new FermionGuardHarness(address(msco), ADMIN_TIMELOCK, EMERGENCY_TIMELOCK, MAX_BATCH_LEGS, MAX_QUEUE);
        _safeExec(address(guard), 0, abi.encodeCall(FermionGuard.requestEmergencyDeGuard, ()), Enum.Operation.Call);
        bytes memory data = abi.encodePacked(abi.encodeWithSignature("setGuard(address)", address(other)), bytes4(0));
        PreApprovalEngine.PreApprovalRequest memory req =
            _payloadReq(address(safe), 0, keccak256(data), 10, T0 + ADMIN_TIMELOCK, T0 + ADMIN_TIMELOCK + 1 days, bytes32(0));
        _createSigned(req, C_ADMIN);
        vm.warp(T0 + ADMIN_TIMELOCK + 1);
        _safeExec(address(safe), 0, data, Enum.Operation.Call);
        assertEq(address(uint160(uint256(vm.load(address(safe), GUARD_SLOT)))), address(other));
        assertEq(guard.emergencyDeGuardExecutableAt(address(safe)), 0, "emergency request outlived the Guard's tenure");
    }
}
