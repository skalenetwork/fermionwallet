// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC20Mock as MockToken} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import {FermionWallet} from "../src/FermionWallet.sol";
import {XMSS} from "xmss-solidity/XMSS.sol";

/// A token whose `transfer` re-enters the wallet with the very calldata that is moving
/// its tokens. The leaf is spent before the token call [FWL-019], so the inner call must
/// find it spent; the error it hit is recorded for the test to inspect.
contract ReenteringToken {
    mapping(address => uint256) public balanceOf;

    address internal wallet;
    bytes internal payload;
    bool internal armed;

    bool public innerSucceeded;
    bytes4 public innerError;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function arm(address wallet_, bytes calldata payload_) external {
        (wallet, payload, armed) = (wallet_, payload_, true);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        if (armed) {
            armed = false;
            (bool ok, bytes memory err) = wallet.call(payload);
            innerSucceeded = ok;
            if (!ok && err.length >= 4) innerError = bytes4(err);
        }
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

/// A token that refuses transfers while paused — the "paused, blocklisted, zero-value
/// refused" row of the spec's failure table [FWL-035].
contract PausableToken is MockToken {
    bool public paused;

    function setPaused(bool p) external {
        paused = p;
    }

    function transfer(address to, uint256 amount) public override returns (bool) {
        require(!paused, "token: paused");
        return super.transfer(to, amount);
    }
}

/// A token that reports failure by returning `false` instead of reverting. Only
/// `SafeERC20` turns that into a revert; a bare `IERC20.transfer` would pass silently
/// and the wallet would burn a leaf for nothing [FWL-020].
contract FalseReturningToken {
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transfer(address, uint256) external pure returns (bool) {
        return false;
    }
}

/// An ERC-1271 contract signer standing in for a `quantumAdmin` that is not an EOA —
/// the case the ERC-1271 branch exists for [FWL-017].
contract Erc1271Signer {
    mapping(bytes32 => bool) public approved;

    function approve(bytes32 hash) external {
        approved[hash] = true;
    }

    function isValidSignature(bytes32 hash, bytes calldata) external view returns (bytes4) {
        return approved[hash] ? this.isValidSignature.selector : bytes4(0);
    }
}

/// FermionWallet — the suite `fermionwallet.md` specifies. XMSS signatures come from the
/// RFC 8391 reference implementation over FFI (`lib/xmss-solidity/py/sign_digest.py`),
/// the same deterministic test key the Guard suites use.
///
/// The default height here is h = 4 — not one of FWL-027's RFC 8391 parameter sets, but
/// the height the shipped Ledger app build actually generates
/// (`ledger-app/src/xmss.rs: HEIGHT = 4`), and the height the pinned library has vectors
/// for. One test signs at h = 10 end to end and records the gas against the spec's cost
/// table.
contract FermionWalletTest is Test {
    /// The device's ECDSA key (`GET_ADMIN_ADDRESS`), in tests only.
    uint256 internal constant DEVICE_PK = 0x1ED6E4;
    uint256 internal constant ATTACKER_PK = 0xBADA55;
    uint32 internal constant H = 4;

    /// Byte-for-byte the type string the device hashes (`ledger-app/src/wallet.rs`).
    string internal constant TRANSFER_TYPE =
        "Transfer(address wallet,address token,address to,uint256 amount,uint32 leafIndex,uint64 validUntil)";
    bytes32 internal constant TRANSFER_TYPEHASH = keccak256(bytes(TRANSFER_TYPE));
    bytes32 internal constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    address internal device = vm.addr(DEVICE_PK);
    address internal recipient = makeAddr("recipient");
    address internal relayer = makeAddr("relayer");
    address internal stranger = makeAddr("stranger");

    FermionWallet internal wallet;
    MockToken internal token;
    bytes32 internal root;
    bytes32 internal seed;

    uint64 internal validUntil;
    /// Held in storage on purpose: `block.chainid` read into a local is rematerialized by
    /// the optimizer after the `vm.chainId` cheatcode, which silently breaks a restore.
    uint256 internal homeChainId;

    function setUp() public {
        homeChainId = block.chainid;
        (root, seed,) = _xmss(H, 0, bytes32(0));
        wallet = new FermionWallet(root, seed, H, device);
        token = new MockToken();
        token.mint(address(wallet), 1_000_000 ether);
        validUntil = uint64(block.timestamp) + 1 hours;
    }

    // ── The happy path, and what the wallet is ──────────────────────────────

    /// Covers: [FWL-004], [FWL-012], [FWL-019], [FWL-020]
    function test_transferMovesTokensAgainstOneHybridSignature() public {
        (bytes memory ecdsa, bytes memory xmss) = _sign(wallet, address(token), recipient, 100 ether, validUntil, 0);

        assertFalse(wallet.isLeafUsed(0));
        vm.expectEmit(true, true, true, true, address(wallet));
        emit FermionWallet.Transferred(address(token), recipient, 100 ether, 0);
        vm.prank(relayer);
        wallet.transfer(address(token), recipient, 100 ether, validUntil, ecdsa, xmss);

        assertEq(token.balanceOf(recipient), 100 ether);
        assertEq(token.balanceOf(address(wallet)), 999_900 ether);
        assertTrue(wallet.isLeafUsed(0));
        // The bitmap records exactly the one leaf the signature used.
        assertFalse(wallet.isLeafUsed(1));
    }

    /// Covers: [FWL-003], [FWL-028]
    function test_receivingNeedsNoSignatureAndCostsAnOrdinaryTransfer() public {
        address holder = makeAddr("holder");
        token.mint(holder, 10 ether);

        // A wallet with no balance yet and a never-seen EOA: apples to apples.
        FermionWallet fresh = new FermionWallet(root, seed, H, device);
        address eoa = makeAddr("plain-eoa");

        vm.startPrank(holder);
        uint256 before = gasleft();
        token.transfer(address(fresh), 1 ether);
        uint256 toWallet = before - gasleft();
        before = gasleft();
        token.transfer(eoa, 1 ether);
        uint256 toEoa = before - gasleft();
        vm.stopPrank();

        assertEq(token.balanceOf(address(fresh)), 1 ether);
        emit log_named_uint("gas: ERC20 transfer into a FermionWallet", toWallet);
        emit log_named_uint("gas: ERC20 transfer into an EOA          ", toEoa);
        // No hook, no callback, no cooperation: receiving is not the wallet's business.
        assertLe(toWallet, toEoa + 100);
    }

    /// Covers: [FWL-002], [FWL-027], [FWL-030]
    function test_constructorBindsTheKeyAndRejectsImpossibleOnes() public {
        assertEq(wallet.xmssRoot(), root);
        assertEq(wallet.xmssSeed(), seed);
        assertEq(wallet.treeHeight(), H);
        assertEq(wallet.quantumAdmin(), device);

        // The RFC 8391 single-tree parameter sets [FWL-027], plus the height the shipped
        // app build generates. The contract binds whatever height it was given (that is
        // what FWL-018 needs); it does not police the parameter set.
        uint256[4] memory heights = [uint256(4), 10, 16, 20];
        for (uint256 i = 0; i < heights.length; ++i) {
            FermionWallet w = new FermionWallet(root, seed, heights[i], device);
            assertEq(w.treeHeight(), heights[i]);
        }

        // Arguments that would deploy a wallet no signature could ever open.
        vm.expectRevert(FermionWallet.InvalidKeyParams.selector);
        new FermionWallet(root, seed, 0, device);
        vm.expectRevert(FermionWallet.InvalidKeyParams.selector);
        new FermionWallet(root, seed, uint256(XMSS.MAX_HEIGHT) + 1, device);
        vm.expectRevert(FermionWallet.InvalidKeyParams.selector);
        new FermionWallet(bytes32(0), seed, H, device);
        vm.expectRevert(FermionWallet.InvalidKeyParams.selector);
        new FermionWallet(root, bytes32(0), H, device);
        vm.expectRevert(FermionWallet.InvalidKeyParams.selector);
        new FermionWallet(root, seed, H, address(0));
    }

    /// Covers: [FWL-031]
    function test_create2AddressPinsTheKey() public {
        bytes32 salt = keccak256("fermionwallet/salt");
        bytes memory initCode =
            abi.encodePacked(type(FermionWallet).creationCode, abi.encode(root, seed, uint256(H), device));

        address predicted = vm.computeCreate2Address(salt, keccak256(initCode), address(this));
        address deployed = address(new FermionWallet{salt: salt}(root, seed, H, device));
        assertEq(deployed, predicted);

        // A different key is a different init code, hence a different address: for a
        // fixed factory and salt, one address can only ever hold this exact wallet.
        address other = vm.computeCreate2Address(
            salt,
            keccak256(abi.encodePacked(type(FermionWallet).creationCode, abi.encode(root, seed, uint256(H), stranger))),
            address(this)
        );
        assertTrue(other != predicted);
    }

    // ── Both halves are required [FWL-022] ──────────────────────────────────

    /// Covers: [FWL-022], [FWL-018]
    function test_ecdsaHalfAloneIsRejected() public {
        (bytes memory ecdsa, bytes memory xmss) = _sign(wallet, address(token), recipient, 5 ether, validUntil, 0);

        // A structurally valid XMSS signature with one WOTS+ word corrupted.
        XMSS.Signature memory sig = abi.decode(xmss, (XMSS.Signature));
        sig.wotsSig[0] = keccak256("not the chain the device produced");
        vm.expectRevert(FermionWallet.InvalidXmssSignature.selector);
        wallet.transfer(address(token), recipient, 5 ether, validUntil, ecdsa, abi.encode(sig));

        // An all-zero XMSS structure of the right shape: the classical half is genuine,
        // the post-quantum half is absent.
        XMSS.Signature memory empty;
        empty.authPath = new bytes32[](H);
        vm.expectRevert(FermionWallet.InvalidXmssSignature.selector);
        wallet.transfer(address(token), recipient, 5 ether, validUntil, ecdsa, abi.encode(empty));

        assertEq(token.balanceOf(recipient), 0);
        assertFalse(wallet.isLeafUsed(0));
    }

    /// Covers: [FWL-022], [FWL-017]
    function test_xmssHalfAloneIsRejected() public {
        uint64 exp = validUntil;
        bytes32 digest = _digest(wallet, address(token), recipient, 5 ether, 0, exp);
        (,, bytes memory xmss) = _xmss(H, 0, digest);

        // Signed by somebody who is not the device.
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ATTACKER_PK, digest);
        vm.expectRevert(FermionWallet.InvalidEcdsaSignature.selector);
        wallet.transfer(address(token), recipient, 5 ether, exp, abi.encodePacked(r, s, v), xmss);

        // No classical half at all.
        vm.expectRevert(FermionWallet.InvalidEcdsaSignature.selector);
        wallet.transfer(address(token), recipient, 5 ether, exp, "", xmss);

        assertEq(token.balanceOf(recipient), 0);
        assertFalse(wallet.isLeafUsed(0));
    }

    /// Covers: [FWL-004], [FWL-022]
    function test_tamperedFieldIsRejected() public {
        (bytes memory ecdsa, bytes memory xmss) = _sign(wallet, address(token), recipient, 100 ether, validUntil, 0);
        MockToken otherToken = new MockToken();
        otherToken.mint(address(wallet), 1 ether);

        // Every signed field is bound: amount, recipient, token, expiry.
        vm.expectRevert(FermionWallet.InvalidEcdsaSignature.selector);
        wallet.transfer(address(token), recipient, 100 ether + 1, validUntil, ecdsa, xmss);
        vm.expectRevert(FermionWallet.InvalidEcdsaSignature.selector);
        wallet.transfer(address(token), stranger, 100 ether, validUntil, ecdsa, xmss);
        vm.expectRevert(FermionWallet.InvalidEcdsaSignature.selector);
        wallet.transfer(address(otherToken), recipient, 100 ether, validUntil, ecdsa, xmss);
        vm.expectRevert(FermionWallet.InvalidEcdsaSignature.selector);
        wallet.transfer(address(token), recipient, 100 ether, validUntil + 1, ecdsa, xmss);

        assertEq(token.balanceOf(address(wallet)), 1_000_000 ether);
        assertFalse(wallet.isLeafUsed(0));

        // The fields as signed still work: nothing above consumed the leaf.
        wallet.transfer(address(token), recipient, 100 ether, validUntil, ecdsa, xmss);
        assertEq(token.balanceOf(recipient), 100 ether);
    }

    /// Covers: [FWL-018]
    function test_xmssSignatureMustHaveThisKeysTreeHeight() public {
        (bytes memory ecdsa, bytes memory xmss) = _sign(wallet, address(token), recipient, 1 ether, validUntil, 0);
        assertEq(xmss.length, 2304 + 32 * uint256(H));

        bytes memory truncated = new bytes(xmss.length - 32);
        for (uint256 i = 0; i < truncated.length; ++i) {
            truncated[i] = xmss[i];
        }
        vm.expectRevert(
            abi.encodeWithSelector(FermionWallet.InvalidXmssSignatureLength.selector, uint256(xmss.length - 32))
        );
        wallet.transfer(address(token), recipient, 1 ether, validUntil, ecdsa, truncated);

        // A signature for a taller tree: rejected on length, so the height bound to the
        // key can never be chosen by whoever supplies the signature.
        XMSS.Signature memory sig = abi.decode(xmss, (XMSS.Signature));
        bytes32[] memory longer = new bytes32[](uint256(H) + 1);
        for (uint256 i = 0; i < H; ++i) {
            longer[i] = sig.authPath[i];
        }
        sig.authPath = longer;
        bytes memory tall = abi.encode(sig);
        vm.expectRevert(abi.encodeWithSelector(FermionWallet.InvalidXmssSignatureLength.selector, tall.length));
        wallet.transfer(address(token), recipient, 1 ether, validUntil, ecdsa, tall);
    }

    // ── One leaf, one digest [FWL-034] ──────────────────────────────────────

    /// The rejected design, run against the implemented one: a device that signs leaf 5
    /// twice while labelling the two transfers leaf 0 and leaf 1. Had the index been a
    /// calldata argument, both would have verified, both would have executed, and the
    /// bitmap would have recorded two untouched leaves. Because the contract rebuilds the
    /// digest with the index the signature actually used, both mislabelled transfers fail
    /// the ECDSA check and leaf 5 buys exactly one transfer.
    ///
    /// Covers: [FWL-034], [FWL-016], [FWL-022]
    function test_oneLeafSignedTwiceUnderTwoLabelsBuysOneTransfer() public {
        uint32 spent = 5;

        // The device signs digest("leafIndex = 0") and digest("leafIndex = 1"), both with
        // WOTS+ leaf 5 — two different digests under one one-time key, the exact abuse
        // the bitmap exists to make visible.
        (bytes memory ecdsa0, bytes memory xmss0) =
            _signLabelled(wallet, address(token), recipient, 10 ether, validUntil, 0, spent);
        (bytes memory ecdsa1, bytes memory xmss1) =
            _signLabelled(wallet, address(token), recipient, 20 ether, validUntil, 1, spent);

        // The digest the contract rebuilds names leaf 5, so neither classical half
        // recovers to the device: the ECDSA check is what stops this.
        vm.expectRevert(FermionWallet.InvalidEcdsaSignature.selector);
        wallet.transfer(address(token), recipient, 10 ether, validUntil, ecdsa0, xmss0);
        vm.expectRevert(FermionWallet.InvalidEcdsaSignature.selector);
        wallet.transfer(address(token), recipient, 20 ether, validUntil, ecdsa1, xmss1);

        assertEq(token.balanceOf(recipient), 0);
        assertFalse(wallet.isLeafUsed(0));
        assertFalse(wallet.isLeafUsed(1));
        assertFalse(wallet.isLeafUsed(spent));

        // Labelled honestly, leaf 5 works — once.
        (bytes memory ecdsa, bytes memory xmss) =
            _sign(wallet, address(token), recipient, 10 ether, validUntil, spent);
        wallet.transfer(address(token), recipient, 10 ether, validUntil, ecdsa, xmss);
        assertTrue(wallet.isLeafUsed(spent));

        (bytes memory ecdsaB, bytes memory xmssB) =
            _sign(wallet, address(token), recipient, 20 ether, validUntil, spent);
        vm.expectRevert(abi.encodeWithSelector(FermionWallet.LeafAlreadyUsed.selector, spent));
        wallet.transfer(address(token), recipient, 20 ether, validUntil, ecdsaB, xmssB);

        assertEq(token.balanceOf(recipient), 10 ether);
    }

    /// Covers: [FWL-034]
    function test_relabellingTheIndexInTheSignatureFails() public {
        (bytes memory ecdsa, bytes memory xmss) = _sign(wallet, address(token), recipient, 7 ether, validUntil, 3);

        // A relayer rewrites the one field the contract reads for bookkeeping.
        XMSS.Signature memory sig = abi.decode(xmss, (XMSS.Signature));
        sig.leafIdx = 6;
        vm.expectRevert(FermionWallet.InvalidEcdsaSignature.selector);
        wallet.transfer(address(token), recipient, 7 ether, validUntil, ecdsa, abi.encode(sig));

        assertFalse(wallet.isLeafUsed(3));
        assertFalse(wallet.isLeafUsed(6));
        assertEq(token.balanceOf(recipient), 0);
    }

    /// A leaf beyond the tree cannot be poisoned either: the digest agrees with the
    /// rewritten index, so the ECDSA half passes — and the XMSS half, which binds the
    /// index into `H_msg` and rejects `leafIdx >= 2**h`, is what refuses it.
    ///
    /// Covers: [FWL-018], [FWL-022], [FWL-016]
    function test_outOfRangeLeafCannotBeMarkedSpent() public {
        uint32 outOfRange = 100; // h = 4 has 16 leaves
        (bytes memory ecdsa, bytes memory xmss) =
            _signLabelled(wallet, address(token), recipient, 1 ether, validUntil, outOfRange, 3);

        XMSS.Signature memory sig = abi.decode(xmss, (XMSS.Signature));
        sig.leafIdx = outOfRange; // now the label and the field agree
        vm.expectRevert(FermionWallet.InvalidXmssSignature.selector);
        wallet.transfer(address(token), recipient, 1 ether, validUntil, ecdsa, abi.encode(sig));

        assertFalse(wallet.isLeafUsed(outOfRange));
        assertFalse(wallet.isLeafUsed(3));
    }

    /// A malleated ECDSA half — same signature, `s` flipped to `n - s` — is not a second
    /// way to satisfy the classical check, and it does not consume the leaf either.
    ///
    /// Covers: [FWL-017], [FWL-016]
    function test_malleatedEcdsaHalfIsRejected() public {
        bytes32 digest = _digest(wallet, address(token), recipient, 1 ether, 0, validUntil);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(DEVICE_PK, digest);
        (,, bytes memory xmss) = _xmss(H, 0, digest);

        uint256 n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        bytes memory malleated = abi.encodePacked(r, bytes32(n - uint256(s)), v == 27 ? uint8(28) : uint8(27));
        vm.expectRevert(FermionWallet.InvalidEcdsaSignature.selector);
        wallet.transfer(address(token), recipient, 1 ether, validUntil, malleated, xmss);
        assertFalse(wallet.isLeafUsed(0));

        // The original still works, so nothing above was a partial consumption.
        wallet.transfer(address(token), recipient, 1 ether, validUntil, abi.encodePacked(r, s, v), xmss);
        assertEq(token.balanceOf(recipient), 1 ether);
    }

    /// The classical half is never raw `ecrecover`: a `quantumAdmin` that is a contract
    /// at construction authorizes through ERC-1271 instead.
    ///
    /// Covers: [FWL-017]
    function test_anErc1271SignerCanBeTheQuantumAdmin() public {
        Erc1271Signer signer = new Erc1271Signer();
        FermionWallet w = new FermionWallet(root, seed, H, address(signer));
        token.mint(address(w), 10 ether);

        bytes32 digest = _digest(w, address(token), recipient, 1 ether, 0, validUntil);
        (,, bytes memory xmss) = _xmss(H, 0, digest);
        bytes memory blessing = bytes("attested out of band");

        vm.expectRevert(FermionWallet.InvalidEcdsaSignature.selector);
        w.transfer(address(token), recipient, 1 ether, validUntil, blessing, xmss);

        signer.approve(digest);
        w.transfer(address(token), recipient, 1 ether, validUntil, blessing, xmss);
        assertEq(token.balanceOf(recipient), 1 ether);
        assertTrue(w.isLeafUsed(0));
    }

    /// The length check is not the only thing binding the tree height: a signature whose
    /// authentication path is short but padded to the expected byte count decodes fine and
    /// is refused by the four-argument `XMSS.verify`.
    ///
    /// Covers: [FWL-018]
    function test_aShortAuthPathPaddedToTheRightLengthIsRejected() public {
        (bytes memory ecdsa, bytes memory xmss) = _sign(wallet, address(token), recipient, 1 ether, validUntil, 0);

        XMSS.Signature memory sig = abi.decode(xmss, (XMSS.Signature));
        bytes32[] memory short_ = new bytes32[](uint256(H) - 1);
        for (uint256 i = 0; i < short_.length; ++i) {
            short_[i] = sig.authPath[i];
        }
        sig.authPath = short_;
        bytes memory padded = abi.encodePacked(abi.encode(sig), bytes32(0)); // back to 2304 + 32*H

        assertEq(padded.length, 2304 + 32 * uint256(H));
        vm.expectRevert(FermionWallet.InvalidXmssSignature.selector);
        wallet.transfer(address(token), recipient, 1 ether, validUntil, ecdsa, padded);
        assertFalse(wallet.isLeafUsed(0));
    }

    /// Naming the wallet itself as the token: there is no fallback to impersonate an
    /// ERC-20, so `safeTransfer` finds no `transfer(address,uint256)` and the whole
    /// transaction reverts rather than burning a leaf on a silent no-op.
    ///
    /// Covers: [FWL-005], [FWL-009], [FWL-020]
    function test_theWalletCannotBeItsOwnToken() public {
        (bytes memory ecdsa, bytes memory xmss) =
            _sign(wallet, address(wallet), recipient, 1 ether, validUntil, 0);
        (bool ok,) = address(wallet).call(
            abi.encodeCall(FermionWallet.transfer, (address(wallet), recipient, 1 ether, validUntil, ecdsa, xmss))
        );
        assertFalse(ok);
        assertFalse(wallet.isLeafUsed(0));
    }

    // ── Leaf reuse, and how cheaply it is refused [FWL-016] ─────────────────

    /// Covers: [FWL-016]
    function test_replayIsRefusedBeforeTheExpensiveVerification() public {
        (bytes memory ecdsa, bytes memory xmss) = _sign(wallet, address(token), recipient, 3 ether, validUntil, 0);
        bytes memory call_ =
            abi.encodeCall(FermionWallet.transfer, (address(token), recipient, 3 ether, validUntil, ecdsa, xmss));

        (bool ok,) = address(wallet).call(call_);
        uint256 accepted = vm.lastCallGas().gasTotalUsed;
        assertTrue(ok);

        (bool replayed, bytes memory err) = address(wallet).call(call_);
        uint256 refused = vm.lastCallGas().gasTotalUsed;
        assertFalse(replayed);
        assertEq(bytes4(err), FermionWallet.LeafAlreadyUsed.selector);

        // For scale, the cheapest refusal this function has: the expiry check, which runs
        // before the signature blob is decoded at all.
        vm.warp(validUntil + 1);
        (bool expired,) = address(wallet).call(call_);
        uint256 refusedOnExpiry = vm.lastCallGas().gasTotalUsed;
        assertFalse(expired);

        emit log_named_uint("gas: accepted transfer (h = 4)  ", accepted);
        emit log_named_uint("gas: refused replay (spent leaf)", refused);
        emit log_named_uint("gas: refused on expiry          ", refusedOnExpiry);

        // The leaf check runs before the ~700k-gas verification, so a replay costs a
        // fraction of an accepted transfer. It is not "almost nothing", though, and what
        // remains is not our checks: a refusal on expiry — which touches nothing at all —
        // costs the same. Carrying the 2.4 KB signature is the floor. On a post-Pectra
        // chain, EIP-7623 prices calldata at 10 gas per token whenever execution gas is
        // small, which is exactly the case for a cheap revert, so the relayer's real bill
        // for a refused replay is ~120k regardless of how early we stop.
        assertApproxEqAbs(refused, refusedOnExpiry, 2_000);
        assertLt(refused, 150_000);
        assertLt(refused * 5, accepted);
    }

    /// The order is what makes the replay cheap: with the leaf already spent, both halves
    /// can be garbage and the wallet still stops at the bitmap.
    ///
    /// Covers: [FWL-016]
    function test_theLeafCheckPrecedesBothSignatureChecks() public {
        (bytes memory ecdsa, bytes memory xmss) = _sign(wallet, address(token), recipient, 3 ether, validUntil, 0);
        wallet.transfer(address(token), recipient, 3 ether, validUntil, ecdsa, xmss);

        XMSS.Signature memory sig = abi.decode(xmss, (XMSS.Signature));
        for (uint256 i = 0; i < 67; ++i) {
            sig.wotsSig[i] = bytes32(0);
        }
        vm.expectRevert(abi.encodeWithSelector(FermionWallet.LeafAlreadyUsed.selector, uint32(0)));
        wallet.transfer(address(token), recipient, 3 ether, validUntil, hex"", abi.encode(sig));
    }

    // ── Expiry, and the absence of a cancel path ────────────────────────────

    /// Covers: [FWL-015]
    function test_transferPastValidUntilReverts() public {
        (bytes memory ecdsa, bytes memory xmss) = _sign(wallet, address(token), recipient, 1 ether, validUntil, 0);

        vm.warp(validUntil + 1);
        vm.expectRevert(abi.encodeWithSelector(FermionWallet.SignatureExpired.selector, validUntil));
        wallet.transfer(address(token), recipient, 1 ether, validUntil, ecdsa, xmss);

        // The boundary is inclusive: `block.timestamp <= validUntil` is still valid.
        vm.warp(validUntil);
        wallet.transfer(address(token), recipient, 1 ether, validUntil, ecdsa, xmss);
        assertEq(token.balanceOf(recipient), 1 ether);
    }

    /// Covers: [FWL-015], [FWL-016]
    function test_expiryIsTheFirstCheck() public {
        (bytes memory ecdsa, bytes memory xmss) = _sign(wallet, address(token), recipient, 1 ether, validUntil, 0);
        wallet.transfer(address(token), recipient, 1 ether, validUntil, ecdsa, xmss);

        // Expired AND the leaf spent AND both halves missing: expiry answers first, and
        // an undersized garbage blob never reaches the length check.
        vm.warp(validUntil + 1);
        vm.expectRevert(abi.encodeWithSelector(FermionWallet.SignatureExpired.selector, validUntil));
        wallet.transfer(address(token), recipient, 1 ether, validUntil, hex"", hex"00");

        // And a blob of the right length whose bytes are garbage: `abi.decode` would
        // panic on it, so this is also the check that the optimizer has not hoisted the
        // decode ahead of the timestamp comparison.
        bytes memory garbage = new bytes(2304 + 32 * uint256(H));
        for (uint256 i = 0; i < garbage.length; ++i) {
            garbage[i] = 0xff;
        }
        vm.expectRevert(abi.encodeWithSelector(FermionWallet.SignatureExpired.selector, validUntil));
        wallet.transfer(address(token), recipient, 1 ether, validUntil, hex"", garbage);
    }

    // ── `msg.sender` carries no authority [FWL-021] ─────────────────────────

    /// Covers: [FWL-021], [FWL-004]
    function test_anyoneMayRelayAValidSignature() public {
        address[3] memory relayers = [stranger, makeAddr("mev-bot"), device];
        for (uint256 i = 0; i < relayers.length; ++i) {
            (bytes memory ecdsa, bytes memory xmss) =
                _sign(wallet, address(token), recipient, 1 ether, validUntil, uint32(i));
            vm.prank(relayers[i]);
            wallet.transfer(address(token), recipient, 1 ether, validUntil, ecdsa, xmss);
        }
        assertEq(token.balanceOf(recipient), 3 ether);
    }

    /// Covers: [FWL-021], [FWL-006], [FWL-005]
    function test_noAddressCanMoveTokensWithoutASignature() public {
        address[4] memory callers = [device, stranger, address(this), address(wallet)];
        for (uint256 i = 0; i < callers.length; ++i) {
            vm.prank(callers[i]);
            vm.expectRevert(
                abi.encodeWithSelector(FermionWallet.InvalidXmssSignatureLength.selector, uint256(0))
            );
            wallet.transfer(address(token), callers[i], 1 ether, validUntil, hex"", hex"");
        }
        assertEq(token.balanceOf(address(wallet)), 1_000_000 ether);
    }

    /// Covers: [FWL-005], [FWL-006], [FWL-007], [FWL-009], [FWL-012]
    function test_thereIsNoOtherWayOutAndNoPrivilegedCaller() public {
        // Everything a wallet of this kind is usually asked for, and the recovery hatches
        // an auditor looks for. None of it exists, and there is no fallback to catch it.
        bytes[] memory attempts = new bytes[](12);
        attempts[0] = abi.encodeWithSignature("approve(address,uint256)", address(token), type(uint256).max);
        attempts[1] = abi.encodeWithSignature("transferFrom(address,address,uint256)", address(wallet), stranger, 1);
        attempts[2] = abi.encodeWithSignature("execute(address,uint256,bytes)", address(token), 0, hex"");
        attempts[3] = abi.encodeWithSignature("multicall(bytes[])", new bytes[](0));
        attempts[4] = abi.encodeWithSignature("sweep(address)", address(token));
        attempts[5] = abi.encodeWithSignature("rescueERC20(address,address,uint256)", address(token), stranger, 1);
        attempts[6] = abi.encodeWithSignature("withdraw(address,uint256)", address(token), 1);
        attempts[7] = abi.encodeWithSignature("owner()");
        attempts[8] = abi.encodeWithSignature("transferOwnership(address)", stranger);
        attempts[9] = abi.encodeWithSignature("upgradeTo(address)", stranger);
        attempts[10] = abi.encodeWithSignature("setKey(bytes32,bytes32)", root, seed);
        attempts[11] = hex"";

        for (uint256 i = 0; i < attempts.length; ++i) {
            vm.prank(stranger);
            (bool ok,) = address(wallet).call(attempts[i]);
            assertFalse(ok);
            vm.prank(device);
            (ok,) = address(wallet).call(attempts[i]);
            assertFalse(ok);
        }

        // And a completed transfer leaves no allowance behind for anyone.
        (bytes memory ecdsa, bytes memory xmss) = _sign(wallet, address(token), recipient, 1 ether, validUntil, 0);
        wallet.transfer(address(token), recipient, 1 ether, validUntil, ecdsa, xmss);
        assertEq(token.allowance(address(wallet), stranger), 0);
        assertEq(token.allowance(address(wallet), device), 0);
        assertEq(token.balanceOf(address(wallet)), 999_999 ether);
    }

    /// Covers: [FWL-008], [FWL-010]
    function test_walletTakesNoEthAndPaysNoRefund() public {
        vm.deal(stranger, 10 ether);

        // Not payable, no `receive`, no payable fallback.
        vm.prank(stranger);
        (bool ok,) = address(wallet).call{value: 1 ether}("");
        assertFalse(ok);
        vm.prank(stranger);
        (ok,) = address(wallet).call{value: 1 ether}(abi.encodeWithSignature("deposit()"));
        assertFalse(ok);
        assertEq(address(wallet).balance, 0);

        // ETH forced in by a self-destructing contract is stuck and ignored: no path
        // moves it, and a transfer does not touch it.
        vm.deal(address(wallet), 1 ether);
        (bytes memory ecdsa, bytes memory xmss) = _sign(wallet, address(token), recipient, 1 ether, validUntil, 0);

        uint256 relayerEthBefore = relayer.balance;
        vm.prank(relayer);
        wallet.transfer(address(token), recipient, 1 ether, validUntil, ecdsa, xmss);

        // The wallet never pays anyone out of its balance — no gas refund, in ETH or in
        // the token it just moved.
        assertEq(address(wallet).balance, 1 ether);
        assertEq(relayer.balance, relayerEthBefore);
        assertEq(token.balanceOf(relayer), 0);
        assertEq(token.balanceOf(address(wallet)), 999_999 ether);
    }

    // ── The domain binds the wallet and the chain [FWL-013] ─────────────────

    /// Covers: [FWL-013], [FWL-023], [FWL-025]
    function test_aSignatureForOneWalletIsUselessOnAnother() public {
        FermionWallet other = new FermionWallet(root, seed, H, device); // same key, second wallet
        token.mint(address(other), 1_000 ether);

        (bytes memory ecdsa, bytes memory xmss) = _sign(wallet, address(token), recipient, 1 ether, validUntil, 0);
        vm.expectRevert(FermionWallet.InvalidEcdsaSignature.selector);
        other.transfer(address(token), recipient, 1 ether, validUntil, ecdsa, xmss);
        assertFalse(other.isLeafUsed(0));

        // The residual risk of FWL-025, demonstrated rather than asserted away: each
        // wallet has its own bitmap, so a device that binds one key to two wallets can
        // spend the SAME leaf in both, and nothing on-chain notices. Only the device's
        // per-slot contract binding [FWL-023] prevents this.
        (bytes memory eA, bytes memory xA) = _sign(wallet, address(token), recipient, 1 ether, validUntil, 7);
        (bytes memory eB, bytes memory xB) = _sign(other, address(token), recipient, 2 ether, validUntil, 7);
        wallet.transfer(address(token), recipient, 1 ether, validUntil, eA, xA);
        other.transfer(address(token), recipient, 2 ether, validUntil, eB, xB);
        assertTrue(wallet.isLeafUsed(7));
        assertTrue(other.isLeafUsed(7));
        assertEq(token.balanceOf(recipient), 3 ether);
    }

    /// Covers: [FWL-013]
    function test_aSignatureForOneChainIsUselessOnAnother() public {
        (bytes memory ecdsa, bytes memory xmss) = _sign(wallet, address(token), recipient, 1 ether, validUntil, 0);

        vm.chainId(homeChainId + 1);
        vm.expectRevert(FermionWallet.InvalidEcdsaSignature.selector);
        wallet.transfer(address(token), recipient, 1 ether, validUntil, ecdsa, xmss);

        vm.chainId(homeChainId);
        wallet.transfer(address(token), recipient, 1 ether, validUntil, ecdsa, xmss);
        assertEq(token.balanceOf(recipient), 1 ether);
    }

    /// The digest is the device's own: the contract's type hash is the string
    /// `ledger-app/src/wallet.rs` hashes, the domain is the one it builds, and `transfer`
    /// takes fields — there is no parameter through which a host could hand it a hash.
    ///
    /// Covers: [FWL-014], [FWL-013]
    function test_theDigestIsTheOneTheDeviceComputes() public view {
        assertEq(wallet.TRANSFER_TYPEHASH(), TRANSFER_TYPEHASH);

        (, string memory name, string memory version, uint256 chainId, address verifying,,) = wallet.eip712Domain();
        assertEq(name, "FermionWallet");
        assertEq(version, "1");
        assertEq(chainId, block.chainid);
        assertEq(verifying, address(wallet));

        // Independently recomputed here from the fields alone (the same path
        // `ledger-app/test/test_wallet.py` takes through `cast`), and the transfers above
        // prove it is the digest both halves must cover.
        bytes32 expected = keccak256(
            abi.encodePacked(
                hex"1901",
                keccak256(
                    abi.encode(
                        DOMAIN_TYPEHASH,
                        keccak256("FermionWallet"),
                        keccak256("1"),
                        block.chainid,
                        address(wallet)
                    )
                ),
                keccak256(
                    abi.encode(
                        TRANSFER_TYPEHASH, address(wallet), address(token), recipient, 1 ether, uint32(2), validUntil
                    )
                )
            )
        );
        assertEq(_digest(wallet, address(token), recipient, 1 ether, 2, validUntil), expected);
    }

    // ── The token call [FWL-019], [FWL-020], [FWL-035], [FWL-036] ───────────

    /// Covers: [FWL-019]
    function test_theLeafIsSpentBeforeTheTokenCall() public {
        ReenteringToken evil = new ReenteringToken();
        evil.mint(address(wallet), 100 ether);

        (bytes memory ecdsa, bytes memory xmss) = _sign(wallet, address(evil), recipient, 10 ether, validUntil, 0);
        evil.arm(
            address(wallet),
            abi.encodeCall(FermionWallet.transfer, (address(evil), recipient, 10 ether, validUntil, ecdsa, xmss))
        );

        wallet.transfer(address(evil), recipient, 10 ether, validUntil, ecdsa, xmss);

        // The re-entrant call carried a perfectly valid signature — and still failed,
        // because the leaf was already spent. That ordering is the reentrancy guard.
        assertFalse(evil.innerSucceeded());
        assertEq(evil.innerError(), FermionWallet.LeafAlreadyUsed.selector);
        assertEq(evil.balanceOf(recipient), 10 ether);
        assertEq(evil.balanceOf(address(wallet)), 90 ether);
    }

    /// Covers: [FWL-020]
    function test_aTokenThatReturnsFalseFailsTheWholeTransfer() public {
        FalseReturningToken liar = new FalseReturningToken();
        liar.mint(address(wallet), 100 ether);

        (bytes memory ecdsa, bytes memory xmss) = _sign(wallet, address(liar), recipient, 10 ether, validUntil, 0);
        vm.expectRevert(abi.encodeWithSelector(SafeERC20.SafeERC20FailedOperation.selector, address(liar)));
        wallet.transfer(address(liar), recipient, 10 ether, validUntil, ecdsa, xmss);

        assertFalse(wallet.isLeafUsed(0));
        assertEq(liar.balanceOf(recipient), 0);
    }

    /// Covers: [FWL-035], [FWL-036]
    function test_aRevertingTokenLeavesTheLeafUnspentAndTheSignatureLive() public {
        PausableToken paused = new PausableToken();
        paused.mint(address(wallet), 100 ether);
        paused.setPaused(true);

        (bytes memory ecdsa, bytes memory xmss) = _sign(wallet, address(paused), recipient, 10 ether, validUntil, 4);

        vm.prank(relayer);
        vm.expectRevert(bytes("token: paused"));
        wallet.transfer(address(paused), recipient, 10 ether, validUntil, ecdsa, xmss);

        // The whole transaction reverted, so the leaf is NOT spent on-chain — while the
        // device committed its counter before signing, so leaf 4 is gone from its side.
        // Nothing is lost; the leaf is simply burned [FWL-035].
        assertFalse(wallet.isLeafUsed(4));

        // …and when the token unpauses, the same signature is still live and relayable by
        // anyone, with no cancel path [FWL-036].
        paused.setPaused(false);
        vm.prank(stranger);
        wallet.transfer(address(paused), recipient, 10 ether, validUntil, ecdsa, xmss);
        assertEq(paused.balanceOf(recipient), 10 ether);
        assertTrue(wallet.isLeafUsed(4));
    }

    /// Covers: [FWL-036], [FWL-015]
    function test_theOnlyControlOverALiveSignatureIsTheWindow() public {
        PausableToken paused = new PausableToken();
        paused.mint(address(wallet), 100 ether);
        paused.setPaused(true);

        (bytes memory ecdsa, bytes memory xmss) = _sign(wallet, address(paused), recipient, 10 ether, validUntil, 0);
        vm.expectRevert(bytes("token: paused"));
        wallet.transfer(address(paused), recipient, 10 ether, validUntil, ecdsa, xmss);

        // No cancel, revoke, pause or nonce bump exists to retire the signature early.
        bytes[] memory hatches = new bytes[](4);
        hatches[0] = abi.encodeWithSignature("cancel(uint32)", uint32(0));
        hatches[1] = abi.encodeWithSignature("invalidateLeaf(uint32)", uint32(0));
        hatches[2] = abi.encodeWithSignature("pause()");
        hatches[3] = abi.encodeWithSignature("bumpNonce()");
        for (uint256 i = 0; i < hatches.length; ++i) {
            vm.prank(device);
            (bool ok,) = address(wallet).call(hatches[i]);
            assertFalse(ok);
        }

        // Only the clock retires it.
        vm.warp(validUntil + 1);
        paused.setPaused(false);
        vm.expectRevert(abi.encodeWithSelector(FermionWallet.SignatureExpired.selector, validUntil));
        wallet.transfer(address(paused), recipient, 10 ether, validUntil, ecdsa, xmss);
        assertEq(paused.balanceOf(recipient), 0);
    }

    // ── Rotation is a transfer [FWL-011] ────────────────────────────────────

    /// Covers: [FWL-011], [FWL-024]
    function test_rotationIsATransferToAWalletWithANewKey() public {
        (bytes32 newRoot, bytes32 newSeed,) = _xmss(5, 0, bytes32(0));
        FermionWallet successor = new FermionWallet(newRoot, newSeed, 5, device);
        assertTrue(newRoot != root);

        uint256 balance = token.balanceOf(address(wallet));
        (bytes memory ecdsa, bytes memory xmss) =
            _sign(wallet, address(token), address(successor), balance, validUntil, 0);
        wallet.transfer(address(token), address(successor), balance, validUntil, ecdsa, xmss);

        assertEq(token.balanceOf(address(wallet)), 0);
        assertEq(token.balanceOf(address(successor)), balance);

        // The old key cannot spend the new wallet: a signature from the h = 4 key is the
        // wrong length for the successor's tree, and its root is not the successor's root.
        bytes32 digest = _digest(successor, address(token), recipient, 1 ether, 1, validUntil);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(DEVICE_PK, digest);
        (,, bytes memory oldXmss) = _xmss(H, 1, digest);
        vm.expectRevert(abi.encodeWithSelector(FermionWallet.InvalidXmssSignatureLength.selector, oldXmss.length));
        successor.transfer(address(token), recipient, 1 ether, validUntil, abi.encodePacked(r, s, v), oldXmss);

        // Nor does the reverse hold: the successor's key is the only one that opens it.
        (bytes memory newEcdsa, bytes memory newXmss) =
            _sign(successor, address(token), recipient, 1 ether, validUntil, 1);
        successor.transfer(address(token), recipient, 1 ether, validUntil, newEcdsa, newXmss);
        assertEq(token.balanceOf(recipient), 1 ether);
    }

    // ── Cost, at a real RFC 8391 height [FWL-027] ───────────────────────────

    /// One end-to-end transfer at h = 10 — an RFC 8391 parameter set and the sensible
    /// default for a personal wallet — measured against the spec's cost table (~712k for
    /// verification, ~0.8M in total).
    ///
    /// Covers: [FWL-018], [FWL-027], [FWL-032]
    function test_transferAtHeight10CostsAboutWhatTheSpecSays() public {
        (bytes32 r10, bytes32 s10,) = _xmss(10, 0, bytes32(0));
        FermionWallet big = new FermionWallet(r10, s10, 10, device);
        token.mint(address(big), 10 ether);

        bytes32 digest = _digest(big, address(token), recipient, 1 ether, 3, validUntil);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(DEVICE_PK, digest);
        (,, bytes memory xmss) = _xmss(10, 3, digest);

        bytes memory call_ = abi.encodeCall(
            FermionWallet.transfer, (address(token), recipient, 1 ether, validUntil, abi.encodePacked(r, s, v), xmss)
        );
        uint256 before = gasleft();
        (bool ok,) = address(big).call(call_);
        uint256 used = before - gasleft();
        assertTrue(ok);

        emit log_named_uint("gas: accepted transfer (h = 10, spec says ~0.8M)", used);
        assertTrue(big.isLeafUsed(3));
        assertEq(token.balanceOf(recipient), 1 ether);
        assertLt(used, 1_000_000);
        assertGt(used, 500_000);
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    /// The EIP-712 `Transfer` digest, recomputed here from the fields rather than through
    /// the contract's own helper.
    function _digest(
        FermionWallet w,
        address token_,
        address to,
        uint256 amount,
        uint32 leafIndex,
        uint64 expiry
    ) internal view returns (bytes32) {
        bytes32 domain = keccak256(
            abi.encode(DOMAIN_TYPEHASH, keccak256("FermionWallet"), keccak256("1"), block.chainid, address(w))
        );
        bytes32 structHash =
            keccak256(abi.encode(TRANSFER_TYPEHASH, address(w), token_, to, amount, leafIndex, expiry));
        return keccak256(abi.encodePacked(hex"1901", domain, structHash));
    }

    /// Both halves of the device's signature, honestly labelled: the digest names `leaf`
    /// and the XMSS signature uses `leaf`.
    function _sign(
        FermionWallet w,
        address token_,
        address to,
        uint256 amount,
        uint64 expiry,
        uint32 leaf
    ) internal returns (bytes memory ecdsa, bytes memory xmss) {
        return _signLabelled(w, token_, to, amount, expiry, leaf, leaf);
    }

    /// Both halves over the digest that names `labelledLeaf`, with the XMSS half produced
    /// from WOTS+ leaf `spentLeaf`. When the two differ this is the device the spec's
    /// "One leaf, one digest" section describes: one one-time key, two digests.
    function _signLabelled(
        FermionWallet w,
        address token_,
        address to,
        uint256 amount,
        uint64 expiry,
        uint32 labelledLeaf,
        uint32 spentLeaf
    ) internal returns (bytes memory ecdsa, bytes memory xmss) {
        bytes32 digest = _digest(w, token_, to, amount, labelledLeaf, expiry);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(DEVICE_PK, digest);
        ecdsa = abi.encodePacked(r, s, v);
        (,, xmss) = _xmss(uint32(w.treeHeight()), spentLeaf, digest);
    }

    /// Sign `digest` at `leaf` with the deterministic height-`h` test key
    /// (lib/xmss-solidity/py/sign_digest.py), the same helper the Guard suites use.
    function _xmss(uint32 h, uint32 leaf, bytes32 digest)
        internal
        returns (bytes32 root_, bytes32 seed_, bytes memory encoded)
    {
        string[] memory cmd = new string[](5);
        cmd[0] = "python3";
        cmd[1] = "lib/xmss-solidity/py/sign_digest.py";
        cmd[2] = vm.toString(h);
        cmd[3] = vm.toString(leaf);
        cmd[4] = vm.toString(digest);
        bytes memory out = vm.ffi(cmd);

        XMSS.Signature memory sig;
        sig.leafIdx = leaf;
        sig.authPath = new bytes32[](h);
        root_ = _word(out, 0);
        seed_ = _word(out, 1);
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
