// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.24;

import {ERC20Mock as MockToken} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";
import {Safe} from "@safe-global/safe-contracts/contracts/Safe.sol";
import {MultiSendCallOnly} from "@safe-global/safe-contracts/contracts/libraries/MultiSendCallOnly.sol";
import {Enum} from "@safe-global/safe-contracts/contracts/libraries/Enum.sol";

import {FermionWalletGuard} from "../../src/FermionWalletGuard.sol";
import {PreApprovalEngine} from "../../src/PreApprovalEngine.sol";
import {QuantumKeyRegistry} from "../../src/QuantumKeyRegistry.sol";
import {PropertyBase, FermionWalletGuardHarness, FrameRunner} from "./PropertyBase.sol";

/// A "token" whose transfer re-enters Safe.execTransaction with pre-signed inner
/// transactions (catching and recording each outcome) — nested execution probe.
contract ReenteringToken {
    Safe internal immutable SAFE;
    address[] internal tos;
    bytes[] internal datas;
    uint256[] internal gasArr;
    bytes[] internal sigArr;
    bool[] internal okArr;
    bytes[] internal errArr;

    constructor(Safe safe_) {
        SAFE = safe_;
    }

    function arm(FrameRunner.SafeCall[] calldata calls) external {
        delete tos;
        delete datas;
        delete gasArr;
        delete sigArr;
        delete okArr;
        delete errArr;
        for (uint256 i = 0; i < calls.length; ++i) {
            tos.push(calls[i].to);
            datas.push(calls[i].data);
            gasArr.push(calls[i].safeTxGas);
            sigArr.push(calls[i].sigs);
        }
    }

    function transfer(address, uint256) external returns (bool) {
        for (uint256 i = 0; i < tos.length; ++i) {
            try SAFE.execTransaction(
                tos[i], 0, datas[i], Enum.Operation.Call, gasArr[i], 0, 0, address(0), payable(address(0)), sigArr[i]
            ) returns (bool s) {
                okArr.push(s);
                errArr.push("");
            } catch (bytes memory e) {
                okArr.push(false);
                errArr.push(e);
            }
        }
        return true;
    }

    function results() external view returns (bool[] memory, bytes[] memory) {
        return (okArr, errArr);
    }
}

/// Stateful handler. Holds a pool of hybrid-signed approvals (signed once, in the
/// constructor) that anyone may relay in any order, and a reference model of what the
/// Guard must do. Every action predicts its outcome from the model, performs it on the
/// real Safe + Guard, and records any disagreement in `failure` (checked by invariants).
contract GuardHandler is PropertyBase {
    struct Entry {
        PreApprovalEngine.PreApprovalRequest req;
        uint8 class_;
        bytes ecdsa;
        bytes xmss;
        bytes32 id;
        bytes32 commitment; // Tier-2 commitment (also computed for pinned entries)
        // model
        bool submitted;
        uint256 order;
        bool used;
        bool revoked;
        uint64 usedAt;
    }

    Entry[] internal pool;
    Entry internal reserve; // never relayed by the handler: the liveness probe
    uint256 internal submitCount;
    mapping(bytes32 txHash => uint256 idxPlusOne) internal pinHolder;

    // Pause / emergency model.
    bool internal mPaused;
    uint64 internal mUnpauseAt;
    uint64 internal mCooldownUntil;
    uint64 internal mEmergencyAt;

    // Ghosts.
    uint256 public ghostChecked; //   non-escape Safe/module transactions that executed
    uint256 public ghostProbes;
    uint256 public ghostSubmits;
    uint256 public ghostExecs;
    string public failure;

    FrameRunner internal runner;
    ReenteringToken internal rtoken;
    uint256 internal constant PIN_AMOUNT = 5e18;
    address internal other = makeAddr("other");

    constructor(
        Safe safe_,
        FermionWalletGuardHarness guard_,
        MockToken token_,
        MockToken token2_,
        MultiSendCallOnly msco_,
        bytes32 keyId_
    ) {
        safe = safe_;
        guard = guard_;
        token = token_;
        token2 = token2_;
        msco = msco_;
        keyId = keyId_;
        runner = new FrameRunner(safe_);
        rtoken = new ReenteringToken(safe_);
        _buildPool();
    }

    // ── Pool ────────────────────────────────────────────────────────────────

    function _buildPool() internal {
        PreApprovalEngine.PreApprovalRequest[] memory reqs = new PreApprovalEngine.PreApprovalRequest[](30);
        uint8[] memory classes = new uint8[](30);
        uint32 leaf = 0;
        uint256 k = 0;
        // X: TRANSFER token → recipient, 1e18 — nine entries, mixed windows (the cap is 4).
        uint64[2][9] memory wx = [
            [T0, T0 + 1 days],
            [T0, T0 + 3 days],
            [T0 + 6 hours, T0 + 2 days],
            [T0 + 1 days, T0 + 4 days],
            [T0, T0 + 15 minutes],
            [T0 + 2 days, T0 + 5 days],
            [T0, T0 + 5 days],
            [T0 + 12 hours, T0 + 13 hours],
            [T0 + 3 days, T0 + 6 days]
        ];
        for (uint256 i = 0; i < 9; ++i) {
            reqs[k++] = _transferReq(address(token), recipient, 1e18, leaf++, wx[i][0], wx[i][1], bytes32(0));
        }
        // Y: TRANSFER token → recipient, 2e18.
        for (uint256 i = 0; i < 3; ++i) {
            reqs[k++] = _transferReq(address(token), recipient, 2e18, leaf++, T0 + uint64(i) * 1 days, T0 + uint64(i + 2) * 1 days, bytes32(0));
        }
        // Z: PAYLOAD native 1 ether → recipient2.
        for (uint256 i = 0; i < 3; ++i) {
            classes[k] = C_PAYLOAD;
            reqs[k++] = _payloadReq(recipient2, 1 ether, keccak256(""), leaf++, T0, T0 + uint64(i + 1) * 2 days, bytes32(0));
        }
        // Tier-1 pins: transfer(recipient2, 5e18) at nonces n+1..n+6, plus a second pin
        // for the n+2 hash (a live pin must never be replaced).
        uint256 n = safe.nonce();
        for (uint256 i = 1; i <= 6; ++i) {
            bytes32 h = _txHash(address(token), 0, _transferData(recipient2, PIN_AMOUNT), Enum.Operation.Call, 0, n + i);
            reqs[k++] = _transferReq(address(token), recipient2, PIN_AMOUNT, leaf++, T0, T0 + 4 days, h);
        }
        {
            bytes32 h2 = _txHash(address(token), 0, _transferData(recipient2, PIN_AMOUNT), Enum.Operation.Call, 0, n + 2);
            reqs[k++] = _transferReq(address(token), recipient2, PIN_AMOUNT, leaf++, T0 + 1 hours, T0 + 4 days, h2);
        }
        // More X entries (so the queue refills after the early ones die).
        for (uint256 i = 0; i < 2; ++i) {
            reqs[k++] = _transferReq(address(token), recipient, 1e18, leaf++, T0 + 4 days, T0 + 7 days, bytes32(0));
        }
        // Transfers of the re-entering token (the nested-execution probe's outer tx).
        uint64[2][3] memory wr = [[T0, T0 + 3 days], [T0, T0 + 6 days], [T0 + 2 days, T0 + 7 days]];
        for (uint256 i = 0; i < 3; ++i) {
            reqs[k++] = _transferReq(address(rtoken), recipient, 1e18, leaf++, wr[i][0], wr[i][1], bytes32(0));
        }
        // Leaf-reuse attempts: different content, leaves already taken by X[0] and Y[0].
        reqs[k++] = _transferReq(address(token), recipient, 3e18, 0, T0, T0 + 3 days, bytes32(0));
        reqs[k++] = _transferReq(address(token), recipient, 2e18, 9, T0, T0 + 3 days, bytes32(0));
        // Reserve (last): X commitment, open-ended, own leaf — the liveness probe.
        reqs[k++] = _transferReq(address(token), recipient, 1e18, 31, 0, type(uint64).max, bytes32(0));
        require(k == 30 && leaf <= 31, "pool layout");

        (bytes[] memory e, bytes[] memory x) = _signAll(reqs, classes);
        for (uint256 i = 0; i < 30; ++i) {
            Entry storage en = i < 29 ? pool.push() : reserve;
            en.req = reqs[i];
            en.class_ = classes[i];
            en.ecdsa = e[i];
            en.xmss = x[i];
            en.id = keccak256(abi.encodePacked(address(safe), reqs[i].nonce));
            en.commitment = _commit(reqs[i], classes[i]);
        }
    }

    function _commit(PreApprovalEngine.PreApprovalRequest memory r, uint8 c) internal view returns (bytes32) {
        if (c == C_TRANSFER) return keccak256(abi.encode(address(safe), c, r.token, r.recipient, r.amount));
        return keccak256(abi.encode(address(safe), c, r.target, r.value, r.dataHash));
    }

    // ── Model helpers ───────────────────────────────────────────────────────

    function _now() internal view returns (uint64) {
        return uint64(vm.getBlockTimestamp());
    }

    function _dead(Entry storage e) internal view returns (bool) {
        return e.used || e.revoked || _now() > e.req.validTo;
    }

    function _consumable(Entry storage e) internal view returns (bool) {
        return e.submitted && !e.used && !e.revoked && _now() >= e.req.validFrom && _now() <= e.req.validTo;
    }

    function _liveInQueue(bytes32 c) internal view returns (uint256 n) {
        for (uint256 i = 0; i < pool.length; ++i) {
            Entry storage e = pool[i];
            if (e.submitted && e.req.txHash == bytes32(0) && e.commitment == c && !_dead(e)) ++n;
        }
    }

    function _leafTaken(uint32 leaf) internal view returns (bool) {
        for (uint256 i = 0; i < pool.length; ++i) {
            if (pool[i].submitted && pool[i].req.xmssLeafIndex == leaf) return true;
        }
        return false;
    }

    function _check(bool ok, string memory why) internal {
        if (!ok && bytes(failure).length == 0) failure = why;
    }

    // ── Action: relay a signed approval (anyone, any order) ─────────────────

    /// Pool layout: X 0–8 and 22–23 (TRANSFER 1e18), Y 9–11, Z 12–14 (native), pins
    /// 15–21 (21 duplicates 16's safeTxHash), re-entering token 24–26, leaf reuse 27–28.
    function submit(uint256 i, uint8 actor) external {
        _submitIdx(i % pool.length, actor);
    }

    /// Queue pressure: relay an X-commitment approval (the cap is 4, there are eleven).
    function submitX(uint256 i, uint8 actor) external {
        uint256 r = i % 11;
        _submitIdx(r < 9 ? r : 13 + r, actor);
    }

    /// Pin pressure: relay a Tier-1 pinned approval (incl. the duplicate pin).
    function submitPin(uint256 i, uint8 actor) external {
        _submitIdx(15 + i % 7, actor);
    }

    function _submitIdx(uint256 idx, uint8 actor) internal {
        Entry storage e = pool[idx];
        bool expected = !e.submitted && e.req.validTo > _now() && !_leafTaken(e.req.xmssLeafIndex);
        if (expected) {
            if (e.req.txHash != bytes32(0)) {
                uint256 h = pinHolder[e.req.txHash];
                if (h != 0) {
                    Entry storage p = pool[h - 1];
                    expected = !p.used && _dead(p);
                }
            } else {
                expected = _liveInQueue(e.commitment) < MAX_QUEUE;
            }
        }
        address[3] memory relayers = [relayer, stranger, owner1];
        bool ok;
        try this.submitAs(relayers[actor % 3], e.req, e.class_, e.ecdsa, e.xmss) {
            ok = true;
        } catch {}
        _check(ok == expected, "submit outcome differs from model");
        if (ok) {
            ++ghostSubmits;
            e.submitted = true;
            e.order = ++submitCount;
            if (e.req.txHash != bytes32(0)) pinHolder[e.req.txHash] = idx + 1;
            else _check(guard.commitmentOf(e.id) == e.commitment, "commitment mismatch");
        }
    }

    /// External hop so the relay can be try/caught with an arbitrary msg.sender.
    function submitAs(
        address relayer_,
        PreApprovalEngine.PreApprovalRequest calldata req,
        uint8 c,
        bytes calldata ec,
        bytes calldata xm
    ) external {
        require(msg.sender == address(this));
        vm.prank(relayer_);
        _submit(req, c, ec, xm);
    }

    // ── Action: execute a Safe (or module) transaction ──────────────────────

    function exec(uint8 kind, bool viaModule, bool withGas) external {
        (address to, uint256 value, bytes memory data) = _txOf(kind % 8);
        uint256 safeTxGas = withGas ? 500_000 : 0;
        int256 predicted = _predict(to, value, data, viaModule, safeTxGas, safe.nonce(), mPaused);
        bool ok;
        if (viaModule) (ok,) = _tryModuleExec(to, value, data, Enum.Operation.Call);
        else (ok,) = _tryExec(to, value, data, Enum.Operation.Call, safeTxGas);
        ++ghostExecs;
        _settle(ok, predicted);
    }

    /// The pool transaction shapes, plus near misses that no approval covers.
    function _txOf(uint8 kind) internal view returns (address, uint256, bytes memory) {
        if (kind == 0) return (address(token), 0, _transferData(recipient, 1e18));
        if (kind == 1) return (address(token), 0, _transferData(recipient, 2e18));
        if (kind == 2) return (recipient2, 1 ether, "");
        if (kind == 3) return (address(token), 0, _transferData(recipient2, PIN_AMOUNT));
        if (kind == 4) return (address(token), 0, _transferData(recipient, 1e18 + 1));
        if (kind == 5) return (address(token), 0, _transferData(recipient2, 1e18));
        if (kind == 6) return (recipient2, 1 ether + 1, "");
        return (address(token2), 0, _transferData(recipient, 2e18));
    }

    /// Index of the approval the Guard must consume, or -1 if the tx must be rejected.
    function _predict(
        address to,
        uint256 value,
        bytes memory data,
        bool viaModule,
        uint256 safeTxGas,
        uint256 nonce,
        bool paused
    ) internal view returns (int256) {
        if (paused) return -1;
        if (!viaModule) {
            uint256 h = pinHolder[_txHash(to, value, data, Enum.Operation.Call, safeTxGas, nonce)];
            if (h != 0 && _consumable(pool[h - 1])) return int256(h - 1);
        }
        bytes32 c = _commitOfTx(to, value, data);
        int256 best = -1;
        uint256 bestOrder = type(uint256).max;
        for (uint256 i = 0; i < pool.length; ++i) {
            Entry storage e = pool[i];
            if (e.req.txHash == bytes32(0) && e.commitment == c && _consumable(e) && e.order < bestOrder) {
                best = int256(i);
                bestOrder = e.order;
            }
        }
        return best;
    }

    function _commitOfTx(address to, uint256 value, bytes memory data) internal view returns (bytes32) {
        if (data.length == 68 && bytes4(data) == bytes4(0xa9059cbb)) {
            (address r, uint256 amt) = abi.decode(_slice4(data), (address, uint256));
            return keccak256(abi.encode(address(safe), C_TRANSFER, to, r, amt));
        }
        return keccak256(abi.encode(address(safe), C_PAYLOAD, to, value, keccak256(data)));
    }

    function _slice4(bytes memory d) internal pure returns (bytes memory out) {
        out = new bytes(d.length - 4);
        for (uint256 i = 0; i < out.length; ++i) {
            out[i] = d[i + 4];
        }
    }

    /// Compare the Guard's consumption with the prediction and advance the model.
    function _settle(bool ok, int256 predicted) internal {
        _check(ok == (predicted >= 0), ok ? "executed without a model match" : "matching approval not honoured");
        for (uint256 i = 0; i < pool.length; ++i) {
            Entry storage e = pool[i];
            if (!e.submitted) continue;
            bool nowUsed = guard.getPreApproval(e.id).used;
            bool shouldBeUsed = e.used || (ok && int256(i) == predicted);
            _check(nowUsed == shouldBeUsed, "wrong approval consumed (FIFO / tier / exactness)");
            if (nowUsed && !e.used) {
                e.used = true;
                e.usedAt = _now();
            }
        }
        if (ok) ++ghostChecked;
    }

    // ── Action: revoke ──────────────────────────────────────────────────────

    function revoke(uint256 i, uint8 actor) external {
        Entry storage e = pool[i % pool.length];
        uint8 a = actor % 5;
        bool authorized = a <= 2; // ledger, owner, Safe — never stranger/recipient
        bool expected = e.submitted && !e.used && !e.revoked && authorized;
        bool ok;
        if (a == 2) {
            (ok,) = _tryExec(address(guard), 0, abi.encodeCall(PreApprovalEngine.revokePreApproval, (e.id)), Enum.Operation.Call, 0);
        } else {
            address[5] memory who = [ledger, owner2, address(0), stranger, recipient];
            vm.prank(who[a]);
            (ok,) = address(guard).call(abi.encodeCall(PreApprovalEngine.revokePreApproval, (e.id)));
        }
        _check(ok == expected, "revoke outcome differs from model");
        if (ok) e.revoked = true;
    }

    // ── Action: time ────────────────────────────────────────────────────────

    function warp(uint32 dt) external {
        vm.warp(vm.getBlockTimestamp() + (dt % 12 hours));
    }

    // ── Action: pause controls ──────────────────────────────────────────────

    function pause(uint8 actor) external {
        uint8 a = actor % 4;
        bool ok;
        bool expected;
        if (a == 0) {
            (ok,) = _tryExec(address(guard), 0, abi.encodeCall(FermionWalletGuard.pauseSafe, (address(safe))), Enum.Operation.Call, 0);
            expected = true;
        } else {
            address[4] memory who = [address(0), owner3, ledger, stranger];
            vm.prank(who[a]);
            (ok,) = address(guard).call(abi.encodeCall(FermionWalletGuard.pauseSafe, (address(safe))));
            expected = a != 3 && _now() >= mCooldownUntil;
        }
        _check(ok == expected, "pause outcome differs from model (cooldown)");
        if (ok) mPaused = true;
    }

    function requestUnpause() external {
        (bool ok,) = _tryExec(address(guard), 0, abi.encodeCall(FermionWalletGuard.requestUnpauseSafe, ()), Enum.Operation.Call, 0);
        _check(ok == mPaused, "requestUnpause outcome");
        if (ok) mUnpauseAt = _now() + ADMIN_TIMELOCK;
    }

    function unpause() external {
        (bool ok,) = _tryExec(address(guard), 0, abi.encodeCall(FermionWalletGuard.unpauseSafe, ()), Enum.Operation.Call, 0);
        _check(ok == (mUnpauseAt != 0 && _now() >= mUnpauseAt), "unpause timelock");
        if (ok) {
            mPaused = false;
            mUnpauseAt = 0;
            mCooldownUntil = _now() + ADMIN_TIMELOCK;
        }
    }

    // ── Action: a frame of Safe transactions sharing transient storage ──────

    struct Sim {
        bool paused;
        uint64 unpauseAt;
        uint64 emergencyAt;
        uint64 cooldown;
    }

    function _sim() internal view returns (Sim memory) {
        return Sim(mPaused, mUnpauseAt, mEmergencyAt, mCooldownUntil);
    }

    function _commitSim(Sim memory m) internal {
        mPaused = m.paused;
        mUnpauseAt = m.unpauseAt;
        mEmergencyAt = m.emergencyAt;
        mCooldownUntil = m.cooldown;
    }

    /// One random owner safety call (escape hatch) and its predicted outcome, applied
    /// to the simulated model.
    function _escape(uint256 r, Sim memory m) internal view returns (bytes memory d, bool ok) {
        uint256 pick = r % 7;
        if (pick == 0) {
            d = abi.encodeCall(FermionWalletGuard.pauseSafe, (address(safe)));
            ok = true;
            m.paused = true;
        } else if (pick == 1) {
            d = abi.encodeCall(FermionWalletGuard.requestUnpauseSafe, ());
            ok = m.paused;
            if (ok) m.unpauseAt = _now() + ADMIN_TIMELOCK;
        } else if (pick == 2) {
            d = abi.encodeCall(FermionWalletGuard.unpauseSafe, ());
            ok = m.unpauseAt != 0 && _now() >= m.unpauseAt;
            if (ok) {
                m.paused = false;
                m.unpauseAt = 0;
                m.cooldown = _now() + ADMIN_TIMELOCK;
            }
        } else if (pick == 3) {
            d = abi.encodeCall(FermionWalletGuard.requestEmergencyDeGuard, ());
            ok = true;
            m.emergencyAt = _now() + EMERGENCY_TIMELOCK;
        } else if (pick == 4) {
            d = abi.encodeCall(FermionWalletGuard.cancelEmergencyDeGuard, (address(safe)));
            ok = m.emergencyAt != 0;
            m.emergencyAt = 0;
        } else if (pick == 5) {
            d = abi.encodeCall(PreApprovalEngine.revokePreApproval, (keccak256(abi.encode(r, "unknown"))));
        } else {
            d = abi.encodeCall(QuantumKeyRegistry.cancelKeyRevocation, (address(safe)));
        }
    }

    /// Random escape-hatch calls (some failing inside, tolerated via safeTxGas), an
    /// optional approval-consuming transaction, then a probe. The probe must see a
    /// depth of zero: it fails for lack of an approval (or the pause), never as nested.
    function frame(uint256 seed, bool withApproved, uint8 kind) external {
        uint256 nEsc = seed % 5;
        FrameRunner.SafeCall[] memory calls = new FrameRunner.SafeCall[](nEsc + (withApproved ? 1 : 0) + 1);
        bool[] memory expectOk = new bool[](calls.length);
        uint256 nonce = safe.nonce();
        Sim memory m = _sim();
        uint256 j = 0;
        int256 predicted = -1;
        uint256 approvedPos = type(uint256).max;
        for (uint256 i = 0; i < nEsc; ++i) {
            (bytes memory d, bool ok) = _escape(uint256(keccak256(abi.encode(seed, i))), m);
            calls[j] = _signed(address(guard), 0, d, 1_000_000, nonce++);
            expectOk[j++] = ok;
        }
        if (withApproved) {
            (address to, uint256 value, bytes memory data) = _txOf(kind % 4);
            predicted = _predict(to, value, data, false, 0, nonce, m.paused);
            calls[j] = _signed(to, value, data, 0, nonce);
            if (predicted >= 0) ++nonce;
            approvedPos = j;
            expectOk[j++] = predicted >= 0;
        }
        calls[j] = _signed(address(token), 0, _transferData(recipient, 12345), 0, nonce); // probe: never approved

        (bool[] memory okArr, bytes[] memory errs) = runner.run(calls);

        for (uint256 i = 0; i < j; ++i) {
            _check(okArr[i] == expectOk[i], "frame call outcome differs from model");
        }
        if (withApproved) _settle(okArr[approvedPos], predicted);
        _checkProbe(okArr[j], errs[j], m.paused);
        _commitSim(m);
    }

    /// An approved outer transaction whose target re-enters execTransaction with escape
    /// calls and then an unapproved transaction. Nested escape calls pass; the nested
    /// ordinary transaction is rejected as nested (depth held by the outer level, not
    /// reset by the escape levels); and a top-level probe right after, in the same
    /// frame, sees depth zero again.
    function nested(uint256 seed, bool innerProbe) external {
        // Precondition help: relay a re-entering-token approval if none is consumable.
        bool any;
        for (uint256 i = 24; i < 27; ++i) {
            if (_consumable(pool[i])) any = true;
        }
        if (!any) _submitIdx(24 + seed % 3, uint8(seed >> 8));
        uint256 n = safe.nonce();
        Sim memory m = _sim();
        bytes memory outerData = _transferData(recipient, 1e18);
        int256 predicted = _predict(address(rtoken), 0, outerData, false, 0, n, m.paused);

        uint256 nEsc = seed % 3;
        FrameRunner.SafeCall[] memory inner = new FrameRunner.SafeCall[](nEsc + (innerProbe ? 1 : 0));
        bool[] memory expectInner = new bool[](inner.length);
        Sim memory mi = Sim(m.paused, m.unpauseAt, m.emergencyAt, m.cooldown);
        uint256 nonce = n + 1;
        for (uint256 i = 0; i < nEsc; ++i) {
            (bytes memory d, bool ok) = _escape(uint256(keccak256(abi.encode(seed, "inner", i))), mi);
            inner[i] = _signed(address(guard), 0, d, 200_000, nonce++);
            expectInner[i] = ok;
        }
        if (innerProbe) inner[nEsc] = _signed(address(token), 0, _transferData(recipient, 54321), 0, nonce);
        rtoken.arm(inner);

        FrameRunner.SafeCall[] memory calls = new FrameRunner.SafeCall[](2);
        calls[0] = _signed(address(rtoken), 0, outerData, 0, n);
        calls[1] = _signed(address(token), 0, _transferData(recipient, 12345), 0, predicted >= 0 ? nonce : n);
        (bool[] memory okArr, bytes[] memory errs) = runner.run(calls);

        _settle(okArr[0], predicted);
        if (okArr[0]) {
            (bool[] memory iok, bytes[] memory ierr) = rtoken.results();
            _check(iok.length == inner.length, "inner calls not all attempted");
            for (uint256 i = 0; i < nEsc && i < iok.length; ++i) {
                _check(iok[i] == expectInner[i], "nested escape call outcome differs from model");
            }
            if (innerProbe && iok.length == inner.length) {
                _check(!iok[nEsc], "nested unapproved transaction executed");
                _check(
                    _sel(ierr[nEsc])
                        == (mi.paused ? FermionWalletGuard.SafePausedError.selector : FermionWalletGuard.NestedSafeTransaction.selector),
                    "nested transaction not rejected as nested"
                );
            }
            m = mi;
        }
        _checkProbe(okArr[1], errs[1], m.paused);
        _commitSim(m);
    }

    function _checkProbe(bool ok, bytes memory err, bool paused) internal {
        bytes4 probeErr = _sel(err);
        _check(!ok, "unapproved probe executed");
        _check(probeErr != FermionWalletGuard.NestedSafeTransaction.selector, "depth counter leaked across transactions");
        _check(
            probeErr == (paused ? FermionWalletGuard.SafePausedError.selector : PreApprovalEngine.NoMatchingPreApproval.selector),
            "probe rejected for an unexpected reason"
        );
        ++ghostProbes;
    }

    function _signed(address to, uint256 value, bytes memory data, uint256 safeTxGas, uint256 nonce)
        internal
        view
        returns (FrameRunner.SafeCall memory)
    {
        return FrameRunner.SafeCall(
            to, value, data, 0, safeTxGas, _ownerSigs(_txHash(to, value, data, Enum.Operation.Call, safeTxGas, nonce))
        );
    }

    // ── Views for the invariants ────────────────────────────────────────────

    function poolLength() external view returns (uint256) {
        return pool.length;
    }

    function entry(uint256 i)
        external
        view
        returns (bytes32 id, bool submitted, bool used, bool revoked, uint64 usedAt, uint64 validFrom, uint64 validTo, uint32 leaf, bytes32 commitment, uint256 order, bool pinned)
    {
        Entry storage e = pool[i];
        return (e.id, e.submitted, e.used, e.revoked, e.usedAt, e.req.validFrom, e.req.validTo, e.req.xmssLeafIndex, e.commitment, e.order, e.req.txHash != bytes32(0));
    }

    function model() external view returns (bool paused, uint64 unpauseAt, uint64 cooldownUntil, uint64 emergencyAt) {
        return (mPaused, mUnpauseAt, mCooldownUntil, mEmergencyAt);
    }

    function reserveRequest() external view returns (PreApprovalEngine.PreApprovalRequest memory, bytes memory, bytes memory) {
        return (reserve.req, reserve.ecdsa, reserve.xmss);
    }
}

/// Stateful invariants over arbitrary interleavings of relaying, execution (owner and
/// module path, Tier 1 and Tier 2, near misses), revocation, time, pause controls and
/// multi-transaction frames.
contract GuardInvariantTest is PropertyBase {
    GuardHandler internal handler;

    function setUp() public {
        _deployFixture(true);
        handler = new GuardHandler(safe, guard, token, token2, msco, keyId);
        targetContract(address(handler));
        bytes4[] memory sels = new bytes4[](11);
        sels[0] = GuardHandler.submit.selector;
        sels[1] = GuardHandler.exec.selector;
        sels[2] = GuardHandler.revoke.selector;
        sels[3] = GuardHandler.warp.selector;
        sels[4] = GuardHandler.pause.selector;
        sels[5] = GuardHandler.requestUnpause.selector;
        sels[6] = GuardHandler.unpause.selector;
        sels[7] = GuardHandler.frame.selector;
        sels[8] = GuardHandler.nested.selector;
        sels[9] = GuardHandler.submitX.selector;
        sels[10] = GuardHandler.submitPin.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: sels}));
    }

    /// The Guard behaved exactly as the reference model on every action: outcomes of
    /// relaying (cap, pins, leaves, windows), execution (which approval is consumed —
    /// Tier-1 first, then oldest consumable Tier-2 — or rejection), revocation rights,
    /// pause/cooldown/unpause timelocks, and a zero depth after every frame.
    /// forge-config: default.invariant.runs = 64
    /// forge-config: default.invariant.depth = 80
    /// forge-config: default.invariant.fail-on-revert = true
    function invariant_guardMatchesModel() public view {
        assertEq(handler.failure(), "");
    }

    /// Accounting + queue + leaf + window + posture invariants, read from chain state.
    /// forge-config: default.invariant.runs = 64
    /// forge-config: default.invariant.depth = 80
    /// forge-config: default.invariant.fail-on-revert = true
    function invariant_stateInvariants() public view {
        uint256 n = handler.poolLength();
        uint256 usedCount;
        uint256 created;
        for (uint256 i = 0; i < n; ++i) {
            (bytes32 id, bool submitted, bool used, bool revoked, uint64 usedAt, uint64 vf, uint64 vt, uint32 leaf, bytes32 c,, bool pinned) =
                handler.entry(i);
            PreApprovalEngine.PreApproval memory a = guard.getPreApproval(id);
            assertEq(a.id != bytes32(0), submitted, "existence");
            if (!submitted) continue;
            ++created;
            assertEq(a.used, used, "used flag");
            assertEq(a.revoked, revoked, "revoked flag");
            assertFalse(a.used && a.revoked, "approval both used and revoked");
            assertTrue(guard.isLeafUsed(keyId, leaf), "created approval's leaf not consumed");
            if (used) {
                ++usedCount;
                assertTrue(usedAt >= vf && usedAt <= vt, "consumed outside its validity window");
            }
            if (!pinned) assertLe(guard.queueLength(c), MAX_QUEUE, "queue above MAX_COMMITMENT_QUEUE");
            // Each leaf backs at most one approval.
            for (uint256 j = i + 1; j < n; ++j) {
                (, bool s2,,,,,, uint32 leaf2,,,) = handler.entry(j);
                assertFalse(s2 && leaf2 == leaf, "XMSS leaf used twice");
            }
        }
        // Every non-escape execution consumed exactly one approval, and nothing else did.
        assertEq(usedCount, handler.ghostChecked(), "executions != consumed approvals");
        assertEq(guard.getKey(keyId).useCounter, created, "useCounter != approvals created");
        // Queue order is FIFO in relay order.
        _assertQueueOrder();

        (bool paused, uint64 unpauseAt, uint64 cooldownUntil, uint64 emergencyAt) = handler.model();
        assertEq(guard.safePaused(address(safe)), paused, "pause state");
        assertEq(guard.safeUnpauseExecutableAt(address(safe)), unpauseAt, "unpause timelock state");
        assertEq(guard.safePauseCooldownUntil(address(safe)), cooldownUntil, "cooldown state");
        assertEq(guard.emergencyDeGuardExecutableAt(address(safe)), emergencyAt, "emergency state");
        assertEq(uint256(vm.load(address(safe), FALLBACK_SLOT)), 0, "fallback handler appeared");
        assertEq(address(uint160(uint256(vm.load(address(safe), GUARD_SLOT)))), address(guard), "Guard detached");
    }

    function _assertQueueOrder() internal view {
        (,,,,,,,, bytes32 cX,,) = handler.entry(0);
        uint256 len = guard.queueLength(cX);
        uint256 prev;
        for (uint256 q = 0; q < len; ++q) {
            bytes32 qid = guard.queueAt(cX, q);
            uint256 order = type(uint256).max;
            for (uint256 i = 0; i < handler.poolLength(); ++i) {
                (bytes32 id,,,,,,,,, uint256 o,) = handler.entry(i);
                if (id == qid) order = o;
            }
            assertTrue(order != type(uint256).max && order > prev, "queue not in relay order");
            prev = order;
        }
    }

    /// No permanent DoS: whatever the handler did (including third parties relaying
    /// signed approvals in adversarial order), once the Administrator revokes the live
    /// approvals of a commitment, a fresh approval for it can always be created.
    /// forge-config: default.invariant.runs = 64
    /// forge-config: default.invariant.depth = 80
    /// forge-config: default.invariant.fail-on-revert = true
    function invariant_creationAlwaysRecoverable() public {
        uint256 snap = vm.snapshotState();
        (,,,,,,,, bytes32 cX,,) = handler.entry(0);
        for (uint256 i = 0; i < handler.poolLength(); ++i) {
            (bytes32 id, bool submitted, bool used, bool revoked,,,,, bytes32 c,, bool pinned) = handler.entry(i);
            if (submitted && !used && !revoked && !pinned && c == cX) {
                vm.prank(ledger);
                guard.revokePreApproval(id);
            }
        }
        (PreApprovalEngine.PreApprovalRequest memory req, bytes memory e, bytes memory x) = handler.reserveRequest();
        vm.prank(stranger);
        guard.createPreApproval(req, e, x);
        assertLe(guard.queueLength(cX), 1);
        vm.revertToState(snap);
    }
}
