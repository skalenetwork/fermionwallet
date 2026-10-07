// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC20Mock as MockToken} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import {FermionWallet} from "../src/FermionWallet.sol";
import {XMSS} from "xmss-solidity/XMSS.sol";

// ═══════════════════════════════════════════════════════════════════════════════
//  ADVERSARIAL REVIEW of FermionWallet (e719720, 20099b2) against fermionwallet.md
// ═══════════════════════════════════════════════════════════════════════════════
//
// Every test in this file PASSES against the current `src/FermionWallet.sol`. What
// each one is for is stated in its own comment block, using one of three tags:
//
//   [OPEN FINDING]  — the test documents behaviour that is wrong, or a spec claim
//                     that the contract does not deliver. It passes because it
//                     asserts the *actual* behaviour. Do not read it as a
//                     regression test: if someone fixes the finding, the test
//                     must be rewritten.
//   [TEST GAP]      — the contract is correct, but `FermionWallet.t.sol` does not
//                     check it: a deliberate mutation of the named line survives
//                     that whole 32-test suite. These ARE regression tests; they
//                     are what the existing suite should have contained.
//   [NO FINDING]    — an attack that was tried and does not work. Recorded with
//                     the line that stops it, so nobody has to try it again.
//   [FIXED]         — was an [OPEN FINDING]; the contract has since been fixed and
//                     the test rewritten to assert the fixed behaviour. These ARE
//                     regression tests: if one goes red, the finding is back.
//
// Mutation testing was done in a scratch copy of `contracts/` (src + this one
// test file, `lib` symlinked), never in the repo. Survivors of the existing
// suite, i.e. mutations of FermionWallet.sol that leave all 32 of its tests
// green:
//
//   S1  four-argument `XMSS.verify(...,treeHeight)` -> three-argument `verify`
//       (the height then comes from the signature). FWL-018 untested.
//   S2  drop `treeHeight_ > XMSS.MAX_HEIGHT` from the constructor.
//   S3  drop the zero-root, zero-SEED and zero-admin constructor checks.
//   S4  move `emit Transferred` after the token call (log-order claim untested).
//
// S2 and S3 survive for a Foundry reason worth knowing, demonstrated below in
// `test_GAP_everyConstructorRejectionThatTheSuiteNeverReaches`.
//
// ═══════════════════════════════════════════════════════════════════════════════

/// A `quantumAdmin` that answers ERC-1271 with the magic value for every hash and
/// every signature — the "exotic signer" case. Revocable, as ERC-1271 signers are.
contract BlanketErc1271Signer {
    bool public live = true;

    function setLive(bool v) external {
        live = v;
    }

    function isValidSignature(bytes32, bytes calldata) external view returns (bytes4) {
        return live ? this.isValidSignature.selector : bytes4(0);
    }
}

/// A `quantumAdmin` that blesses exactly one digest and nothing else: used to pin
/// the contract's own EIP-712 digest to a digest computed outside it.
contract OneDigestSigner {
    bytes32 public immutable only;

    constructor(bytes32 only_) {
        only = only_;
    }

    function isValidSignature(bytes32 hash, bytes calldata) external view returns (bytes4) {
        return hash == only ? this.isValidSignature.selector : bytes4(0);
    }
}

/// Code with no `isValidSignature` and no fallback — what an EOA looks like to
/// `SignatureChecker` once anything at all has been deployed (or delegated) there.
contract MuteCode {
    uint256 public x;
}

contract FermionWalletReviewTest is Test {
    uint256 internal constant DEVICE_PK = 0x1ED6E4;
    uint32 internal constant H = 4;

    bytes32 internal constant TRANSFER_TYPEHASH = keccak256(
        "Transfer(address wallet,address token,address to,uint256 amount,uint32 leafIndex,uint64 validUntil)"
    );
    bytes32 internal constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    address internal device = vm.addr(DEVICE_PK);
    address internal recipient = makeAddr("recipient");
    address internal attacker = makeAddr("attacker");

    FermionWallet internal wallet;
    MockToken internal token;
    bytes32 internal root;
    bytes32 internal seed;
    uint64 internal validUntil;

    function setUp() public {
        (root, seed,) = _xmss(H, 0, bytes32(0));
        wallet = new FermionWallet(root, seed, H, device);
        token = new MockToken();
        token.mint(address(wallet), 1_000_000 ether);
        validUntil = uint64(block.timestamp) + 1 hours;
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  TEST GAPS — mutations that survive FermionWallet.t.sol
    // ══════════════════════════════════════════════════════════════════════════

    /// [TEST GAP — survivor S1, FWL-018]
    ///
    /// `FermionWallet.t.sol` has two tests that claim FWL-018 ("the XMSS half is
    /// verified with the height-bound `XMSS.verify`"):
    /// `test_xmssSignatureMustHaveThisKeysTreeHeight` and
    /// `test_aShortAuthPathPaddedToTheRightLengthIsRejected`. Replacing the
    /// four-argument `XMSS.verify(digest, sig, pk, treeHeight)` with the
    /// three-argument form — the one the library's own doc comment warns lets
    /// "the height be chosen by whoever supplies the signature" — leaves all 32
    /// tests green. Neither test can see the difference: the first is stopped by
    /// the byte-length check before `verify` is reached, and the second hands
    /// `verify` a shorter path that fails on the root either way.
    ///
    /// The length check does NOT bind the height, contrary to the comment in
    /// `test_xmssSignatureMustHaveThisKeysTreeHeight`. ABI decoding only bounds
    /// offsets; it does not require the tail to sit where `abi.encode` would put
    /// it. So a blob of *exactly* `2304 + 32*treeHeight` bytes can decode to an
    /// authentication path of any length that fits — here `treeHeight + 1`. The
    /// only thing that rejects it is `sig.authPath.length != treeHeight` inside
    /// the four-argument `verify`.
    ///
    /// The discriminator is gas: the height check is one comparison, whereas the
    /// three-argument form runs the whole ~700k-gas climb before returning false.
    /// Measured here: ~125k under the current source — almost all of it copying
    /// and decoding the 2.4 KB blob, which no contract-side check avoids — against
    /// ~770k under the three-argument mutant.
    function test_GAP_theHeightIsBoundByVerifyNotByTheSignatureLength() public {
        (bytes memory ecdsa, bytes memory xmss) = _sign(wallet, address(token), recipient, 1 ether, validUntil, 0);
        assertEq(xmss.length, 2304 + 32 * uint256(H));

        // Same byte count, but the decoded authentication path is one node longer
        // than this key's tree.
        bytes memory reshaped = _withDeclaredAuthPathLength(xmss, uint256(H) + 1);
        assertEq(reshaped.length, xmss.length, "the length check must still pass");
        assertEq(abi.decode(reshaped, (XMSS.Signature)).authPath.length, uint256(H) + 1);
        assertEq(abi.decode(reshaped, (XMSS.Signature)).leafIdx, 0);

        bytes memory call_ =
            abi.encodeCall(FermionWallet.transfer, (address(token), recipient, 1 ether, validUntil, ecdsa, reshaped));
        uint256 before = gasleft();
        (bool ok, bytes memory err) = address(wallet).call(call_);
        uint256 used = before - gasleft();

        assertFalse(ok);
        assertEq(bytes4(err), FermionWallet.InvalidXmssSignature.selector);
        assertFalse(wallet.isLeafUsed(0));
        emit log_named_uint("gas: wrong-height signature refused (execution only)", used);
        // Rejected on the height comparison, not after a full verification. The
        // three-argument mutant lands around 750k here.
        assertLt(used, 200_000);

        // And the honestly shaped signature still works, so nothing above was a
        // partial consumption.
        wallet.transfer(address(token), recipient, 1 ether, validUntil, ecdsa, xmss);
        assertTrue(wallet.isLeafUsed(0));
    }

    /// [TEST GAP — survivors S2 and S3, FWL-002 / FWL-027]
    ///
    /// `test_constructorBindsTheKeyAndRejectsImpossibleOnes` lists five rejected
    /// constructor arguments. It executes ONE of them.
    ///
    /// `vm.expectRevert` does not swallow a revert raised inside a `CREATE`
    /// frame the way it swallows one from a `CALL`: `new FermionWallet(...)`
    /// bubbles the constructor's revert straight out of the test function.
    /// Foundry then matches the pending expectation against the *test's own*
    /// revert and reports PASS — so every statement after the first
    /// `vm.expectRevert` + reverting `new` pair is dead code. A `-vvvv` trace of
    /// that test ends at `new FermionWallet(root, seed, 0, device)`.
    ///
    /// Consequences, both confirmed by mutation: deleting
    /// `treeHeight_ > XMSS.MAX_HEIGHT` (S2) or deleting the zero-root, zero-SEED
    /// and zero-admin checks (S3) leaves all 32 tests green. A wallet with a
    /// zero root or a zero admin is an inescapable black hole, which is exactly
    /// why the constructor rejects them — and exactly what was untested.
    ///
    /// This test drives each construction through its own CALL frame instead, so
    /// all five run.
    function test_GAP_everyConstructorRejectionThatTheSuiteNeverReaches() public {
        _assertDeployReverts(bytes32(0), seed, H, device, "zero root");
        _assertDeployReverts(root, bytes32(0), H, device, "zero SEED");
        _assertDeployReverts(root, seed, H, address(0), "zero admin");
        _assertDeployReverts(root, seed, 0, device, "height 0");
        _assertDeployReverts(root, seed, uint256(XMSS.MAX_HEIGHT) + 1, device, "height 21");
        _assertDeployReverts(root, seed, type(uint256).max, device, "height 2**256-1");

        // …and the boundary that must NOT revert.
        assertEq(this.deploy(root, seed, uint256(XMSS.MAX_HEIGHT), device).treeHeight(), XMSS.MAX_HEIGHT);
        assertEq(this.deploy(root, seed, 1, device).treeHeight(), 1);
    }

    /// [TEST GAP — FWL-013 / FWL-014]
    ///
    /// `test_theDigestIsTheOneTheDeviceComputes` does not check what its name
    /// says. It asserts `TRANSFER_TYPEHASH` and the four `eip712Domain()` fields,
    /// then compares its own `_digest` helper to an inline recomputation — two
    /// copies of the test's arithmetic, never the contract's. Both of these
    /// mutations of FermionWallet.sol leave that test PASSING:
    ///   * swapping `token` and `to` in the struct-hash `abi.encode`;
    ///   * dropping `_hashTypedDataV4` entirely, so the digest carries no domain
    ///     separator (no chain id, no `verifyingContract`).
    /// (Other tests do catch both, so this is a mislabelled test rather than a
    /// hole in the suite's overall coverage — but the one test named for the
    /// property is the one that cannot see it.)
    ///
    /// Here the digest is computed outside the contract and then made the ONLY
    /// hash the wallet's admin will bless. The transfer succeeding is proof of
    /// byte-for-byte equality with the digest `ledger-app/src/wallet.rs::digest`
    /// builds: same `EIP712Domain` type string, name "FermionWallet", version
    /// "1", `chainId`, `verifyingContract = the wallet`, same `Transfer` type
    /// string, same field order, `leafIndex` padded to 32 bytes at position 5 and
    /// `validUntil` at position 6.
    function test_GAP_theContractsOwnDigestEqualsTheIndependentlyComputedOne() public {
        // Deploy first: the digest depends on the wallet address, which depends on
        // the admin. Two-step, with a placeholder admin that is replaced below.
        address predicted = vm.computeCreateAddress(address(this), vm.getNonce(address(this)) + 1);
        bytes32 expected = keccak256(
            abi.encodePacked(
                hex"1901",
                keccak256(
                    abi.encode(DOMAIN_TYPEHASH, keccak256("FermionWallet"), keccak256("1"), block.chainid, predicted)
                ),
                keccak256(
                    abi.encode(TRANSFER_TYPEHASH, predicted, address(token), recipient, 42 ether, uint32(9), validUntil)
                )
            )
        );
        OneDigestSigner signer = new OneDigestSigner(expected);
        FermionWallet w = new FermionWallet(root, seed, H, address(signer));
        assertEq(address(w), predicted, "address prediction");
        token.mint(address(w), 100 ether);

        (,, bytes memory xmss) = _xmss(H, 9, expected);
        // The admin blesses `expected` and nothing else, so this call can only
        // succeed if the contract rebuilt exactly `expected`.
        w.transfer(address(token), recipient, 42 ether, validUntil, hex"", xmss);
        assertEq(token.balanceOf(recipient), 42 ether);
        assertTrue(w.isLeafUsed(9));
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  OPEN FINDINGS
    // ══════════════════════════════════════════════════════════════════════════

    /// [OPEN FINDING 1 — FWL-022 and FWL-036 are not properties of the contract]
    ///
    /// Severity: low-medium, and a spec defect rather than an exploit — stated
    /// that way on purpose. Capability: whoever chooses the constructor arguments
    /// (the holder's host at deployment time, or a compromised one). It gives an
    /// attacker no path on its own: they would still need the XMSS half, which
    /// means the device. What it destroys is the defence in depth FWL-022
    /// promises, and it reverses FWL-036.
    ///
    /// FWL-022 says "Both signature halves are required over the same digest …
    /// a flaw in our young XMSS code still leaves the battle-tested classical
    /// half." The contract cannot deliver that, because `quantumAdmin` may be any
    /// non-zero address and `SignatureChecker` will route a contract admin
    /// through ERC-1271. An admin that returns the magic value unconditionally
    /// makes step 3 vacuous: `ecdsaSignature = ""` is accepted, and the wallet is
    /// XMSS-only. Nothing in the constructor or in `transfer` can tell this apart
    /// from a Ledger's ECDSA address. Since FWL-017a the deployed state does say
    /// *that* the admin is a contract (`adminIsContract`, FWL-022a), but not what
    /// that contract accepts — a blanket answerer and a careful multisig read back
    /// identically.
    ///
    /// The second half of the finding is the reverse of FWL-036 ("A signed
    /// transfer stays relayable by anyone until `validUntil`, with no cancel
    /// path; short windows are the only control"). ERC-1271 signatures are
    /// revocable by construction — OpenZeppelin's own `SignatureChecker` doc
    /// comment says so — so with a contract admin there IS a cancel path, and
    /// conversely a transfer the holder believes is authorized can be silently
    /// retracted mid-flight. Both directions of FWL-036 are wrong for a contract
    /// admin, and the spec's residual-risk section does not mention it.
    ///
    /// Not fixable by a test; fixable by either requiring `quantumAdmin.code.length
    /// == 0` at construction (which FWL-017's ERC-1271 support forbids) or by
    /// saying plainly in the spec that the classical half is only as strong as the
    /// admin the deployer picked.
    function test_FINDING_aBlanketErc1271AdminMakesTheClassicalHalfVacuous() public {
        BlanketErc1271Signer admin = new BlanketErc1271Signer();
        FermionWallet w = new FermionWallet(root, seed, H, address(admin));
        token.mint(address(w), 100 ether);
        assertEq(w.quantumAdmin(), address(admin));
        assertTrue(w.adminIsContract()); // visibly a contract — but not visibly a blanket one

        bytes32 d0 = _digest(w, address(token), recipient, 1 ether, 0, validUntil);
        (,, bytes memory x0) = _xmss(H, 0, d0);

        // No classical half at all — and FWL-022's "both halves are required" is
        // satisfied by nobody.
        w.transfer(address(token), recipient, 1 ether, validUntil, hex"", x0);
        assertEq(token.balanceOf(recipient), 1 ether);

        // Arbitrary junk works just as well: the classical half carries no
        // information whatsoever.
        bytes32 d1 = _digest(w, address(token), recipient, 2 ether, 1, validUntil);
        (,, bytes memory x1) = _xmss(H, 1, d1);
        vm.prank(attacker);
        w.transfer(address(token), recipient, 2 ether, validUntil, bytes("not a signature"), x1);
        assertEq(token.balanceOf(recipient), 3 ether);

        // FWL-036 reversed: a live, in-window, fully valid transfer can be
        // cancelled by the admin contract, with no leaf consumed.
        bytes32 d2 = _digest(w, address(token), recipient, 4 ether, 2, validUntil);
        (,, bytes memory x2) = _xmss(H, 2, d2);
        admin.setLive(false);
        vm.expectRevert(FermionWallet.InvalidEcdsaSignature.selector);
        w.transfer(address(token), recipient, 4 ether, validUntil, hex"", x2);
        assertFalse(w.isLeafUsed(2));
    }

    /// [FIXED — was OPEN FINDING 2; this is now a regression test, FWL-017a]
    ///
    /// The finding: `SignatureChecker.isValidSignatureNow` branches on
    /// `signer.code.length == 0` *at call time*. `quantumAdmin` is immutable, but
    /// that branch was not. The moment any code existed at the admin address, the
    /// wallet stopped recovering ECDSA and started asking the address for an
    /// ERC-1271 opinion instead — so a delegate with no `isValidSignature` refused
    /// every genuine Ledger signature, and with no owner, pause, recovery or
    /// rotation-that-is-not-a-transfer the balance was unreachable forever.
    /// Capability: the holder of the device's own ECDSA key, signing an EIP-7702
    /// authorization for it — routine, unrelated to this wallet, and with nothing
    /// to warn them off. No third party can trigger it, because code cannot appear
    /// at an address without that address's key. Loss: total and permanent, by
    /// FWL-007. The mirror case was worse than a brick: a delegate that DOES
    /// answer ERC-1271 permissively hands the classical half to whoever that
    /// delegate trusts — Finding 1 below, arrived at after deployment instead of
    /// chosen at it.
    ///
    /// The fix: `adminIsContract` is snapshotted in the constructor and the branch
    /// is taken on the snapshot, so the delegation is irrelevant — the device's
    /// key still signs and `ECDSA.tryRecover` still returns `quantumAdmin`.
    ///
    /// `vm.etch` rather than a 7702 cheatcode: the branch under test is
    /// `code.length`, and plain code trips it identically. Revert the routing in
    /// `transfer` to `quantumAdmin.isValidSignatureNow(...)` and this test goes
    /// red at the first transfer after the etch.
    function test_REGRESSION_codeAppearingAtTheAdminAddressDoesNotBrickTheWallet() public {
        assertFalse(wallet.adminIsContract(), "an EOA admin must be snapshotted as an EOA");

        // A genuine device signature, made and verified before anything changes.
        (bytes memory ecdsa, bytes memory xmss) = _sign(wallet, address(token), recipient, 1 ether, validUntil, 0);
        wallet.transfer(address(token), recipient, 1 ether, validUntil, ecdsa, xmss);
        assertEq(token.balanceOf(recipient), 1 ether);

        // The holder delegates their device address (7702) or otherwise puts code
        // there. Nothing about this wallet was touched.
        vm.etch(device, address(new MuteCode()).code);
        assertEq(wallet.quantumAdmin(), device);
        assertFalse(wallet.adminIsContract(), "the snapshot is immutable, unlike the code");

        // The same device, the same key: still spends, exactly as the holder expects.
        for (uint32 leaf = 1; leaf < 5; ++leaf) {
            (bytes memory e, bytes memory x) = _sign(wallet, address(token), recipient, 1 ether, validUntil, leaf);
            wallet.transfer(address(token), recipient, 1 ether, validUntil, e, x);
            assertTrue(wallet.isLeafUsed(leaf));
        }
        assertEq(token.balanceOf(recipient), 5 ether);

        // And the delegate's opinion is never asked for, so a permissive one cannot
        // authorize anything either: a blanket ERC-1271 answerer sitting at the
        // admin address does not make a junk classical half acceptable.
        vm.etch(device, address(new BlanketErc1271Signer()).code);
        (bytes memory e5, bytes memory x5) = _sign(wallet, address(token), recipient, 1 ether, validUntil, 5);
        vm.expectRevert(FermionWallet.InvalidEcdsaSignature.selector);
        wallet.transfer(address(token), recipient, 1 ether, validUntil, bytes("not a signature"), x5);
        assertFalse(wallet.isLeafUsed(5));
        // …while the device's own signature still works over the same delegate.
        wallet.transfer(address(token), recipient, 1 ether, validUntil, e5, x5);
        assertTrue(wallet.isLeafUsed(5));
    }

    /// [FIXED — the other direction of FWL-017a: a deliberate ERC-1271 admin]
    ///
    /// The snapshot must not break the case `SignatureChecker` exists for. An
    /// admin that was a contract at construction is routed through ERC-1271
    /// forever, including after it is emptied — which is the honest outcome, since
    /// recovery could never return a contract's address anyway.
    function test_REGRESSION_anAdminThatWasAContractStaysOnTheErc1271Path() public {
        BlanketErc1271Signer admin = new BlanketErc1271Signer();
        FermionWallet w = new FermionWallet(root, seed, H, address(admin));
        assertTrue(w.adminIsContract(), "a contract admin must be snapshotted as a contract");
        token.mint(address(w), 10 ether);

        // FWL-017's ERC-1271 support, intact: an empty classical half is accepted
        // because the admin blesses the digest.
        bytes32 d0 = _digest(w, address(token), recipient, 1 ether, 0, validUntil);
        (,, bytes memory x0) = _xmss(H, 0, d0);
        w.transfer(address(token), recipient, 1 ether, validUntil, hex"", x0);
        assertEq(token.balanceOf(recipient), 1 ether);

        // The admin's answer is still what decides, call by call.
        admin.setLive(false);
        bytes32 d1 = _digest(w, address(token), recipient, 1 ether, 1, validUntil);
        (,, bytes memory x1) = _xmss(H, 1, d1);
        vm.expectRevert(FermionWallet.InvalidEcdsaSignature.selector);
        w.transfer(address(token), recipient, 1 ether, validUntil, hex"", x1);
        admin.setLive(true);
        w.transfer(address(token), recipient, 1 ether, validUntil, hex"", x1);
        assertEq(token.balanceOf(recipient), 2 ether);

        // And if that contract is later emptied, the wallet does NOT quietly fall
        // back to secp256k1 recovery against a contract address — which could never
        // succeed — it stays on the branch it was built with and says so.
        vm.etch(address(admin), hex"");
        assertTrue(w.adminIsContract());
        bytes32 d2 = _digest(w, address(token), recipient, 1 ether, 2, validUntil);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(DEVICE_PK, d2);
        (,, bytes memory x2) = _xmss(H, 2, d2);
        vm.expectRevert(FermionWallet.InvalidEcdsaSignature.selector);
        w.transfer(address(token), recipient, 1 ether, validUntil, abi.encodePacked(r, s, v), x2);
        assertFalse(w.isLeafUsed(2));
    }

    /// [OPEN FINDING 3 — a mistyped constructor argument is an undetectable brick]
    ///
    /// Severity: low-medium. Capability: any deployment mistake, or a host that
    /// hands the deployer one wrong argument. Loss: everything later sent to the
    /// address, with nothing to warn anyone until the first transfer is attempted
    /// — which, under FWL-031's CREATE2 flow, is deliberately *after* the tokens
    /// have been sent.
    ///
    /// The constructor rejects only zeros and an out-of-range height. It cannot
    /// check that the height it is given is the height the key was generated with,
    /// or that the root and SEED belong together, or that `quantumAdmin` is the
    /// same device. A wallet built with an h = 4 key and `treeHeight = 10` deploys
    /// cleanly, reads back exactly the values the deployer expected, accepts
    /// deposits for as long as anyone cares to send them, and can never spend:
    /// the honest signature is the wrong byte length, and a signature of the right
    /// length cannot exist for this root.
    ///
    /// FWL-031 makes this sharper rather than safer. The address pins the init
    /// code, so it pins the *mistake* too: "Nobody — including the holder — can
    /// deploy a different wallet there." A one-argument slip is therefore
    /// unrecoverable by design, and the recommended flow sends the tokens first.
    ///
    /// A constructor that demanded one valid signature over a canary digest —
    /// proof that the bound key can actually open the wallet — would refuse all
    /// three substitutions at deployment for the price of one leaf. The contract
    /// has no such self-test, and no other fact about a deployed FermionWallet
    /// distinguishes a working one from a black hole.
    function test_FINDING_aWrongHeightDeploysCleanlyAndCanNeverSpend() public {
        // The h = 4 key, bound at h = 10. Nothing complains.
        FermionWallet brick = new FermionWallet(root, seed, 10, device);
        assertEq(brick.xmssRoot(), root);
        assertEq(brick.xmssSeed(), seed);
        assertEq(brick.quantumAdmin(), device);
        assertEq(brick.treeHeight(), 10);

        // Deposits work exactly as FWL-003 promises.
        token.mint(address(brick), 500 ether);
        assertEq(token.balanceOf(address(brick)), 500 ether);

        // The honest signature from the device that owns this root: wrong length.
        bytes32 d = _digest(brick, address(token), recipient, 1 ether, 0, validUntil);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(DEVICE_PK, d);
        (,, bytes memory honest) = _xmss(H, 0, d);
        vm.expectRevert(abi.encodeWithSelector(FermionWallet.InvalidXmssSignatureLength.selector, honest.length));
        brick.transfer(address(token), recipient, 1 ether, validUntil, abi.encodePacked(r, s, v), honest);

        // A signature of the accepted length, from the only key that could produce
        // one at h = 10: a different root, so the post-quantum half fails.
        (bytes32 r10, bytes32 s10, bytes memory tall) = _xmss(10, 0, d);
        assertTrue(r10 != root || s10 != seed);
        assertEq(tall.length, 2304 + 32 * 10);
        vm.expectRevert(FermionWallet.InvalidXmssSignature.selector);
        brick.transfer(address(token), recipient, 1 ether, validUntil, abi.encodePacked(r, s, v), tall);

        assertEq(token.balanceOf(address(brick)), 500 ether);

        // The same one-argument slip on the admin is equally quiet and equally
        // terminal: the XMSS half is genuine, the classical half can never be.
        FermionWallet wrongAdmin = new FermionWallet(root, seed, H, attacker);
        token.mint(address(wrongAdmin), 500 ether);
        bytes32 d2 = _digest(wrongAdmin, address(token), recipient, 1 ether, 0, validUntil);
        (v, r, s) = vm.sign(DEVICE_PK, d2);
        (,, bytes memory x2) = _xmss(H, 0, d2);
        vm.expectRevert(FermionWallet.InvalidEcdsaSignature.selector);
        wrongAdmin.transfer(address(token), recipient, 1 ether, validUntil, abi.encodePacked(r, s, v), x2);
        assertEq(token.balanceOf(address(wrongAdmin)), 500 ether);
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  NO FINDING — attacks tried, and the line that stops each
    // ══════════════════════════════════════════════════════════════════════════

    /// [NO FINDING] The index the bitmap records is the index the WOTS+ key used.
    ///
    /// This is the property the whole design rests on, so it was attacked from
    /// both ends. `leafIdx` is read once (`uint32 leafIndex = sig.leafIdx;`) and
    /// the same local feeds the digest, `XMSS.verify` (through `sig`) and
    /// `_usedLeaves.set`, so there is no second copy to desynchronize. Inside the
    /// library, `sig.leafIdx` is the OTS address (`wotsPkFromSig(..., idx, ...)`),
    /// the L-tree address (`ltree(wotsPk, idx, ...)`), bit source for the climb
    /// (`climbStep(..., idx, k, ...)`) and part of `H_msg`
    /// (`hMsg(sig.r, pk.root, sig.leafIdx, ...)`) — all at full 32-bit width, so
    /// no two indices share a WOTS+ key and none can be aliased onto another.
    ///
    /// Three concrete attempts, all refused:
    ///   * rewriting `leafIdx` in a genuine signature — `InvalidEcdsaSignature`,
    ///     because the digest is rebuilt from the rewritten value (covered by the
    ///     existing suite; repeated here for a leaf the suite does not use);
    ///   * an index at 2**h and beyond, with the digest labelled to match —
    ///     `XMSS.sol:81`, `if (uint256(sig.leafIdx) >= (1 << h)) return false`;
    ///   * the same leaf offered under a different `leafIdx` *and* a reshaped
    ///     authentication path, to see whether the bitmap could be pointed at an
    ///     untouched bit while a real WOTS+ chain was consumed. The WOTS+ chains
    ///     are keyed by `idx`, so changing it invalidates them.
    function test_NOFINDING_theBitmapAlwaysRecordsTheLeafThatWasConsumed() public {
        // Rewritten index.
        (bytes memory e, bytes memory x) = _sign(wallet, address(token), recipient, 1 ether, validUntil, 11);
        XMSS.Signature memory sig = abi.decode(x, (XMSS.Signature));
        sig.leafIdx = 12;
        vm.expectRevert(FermionWallet.InvalidEcdsaSignature.selector);
        wallet.transfer(address(token), recipient, 1 ether, validUntil, e, abi.encode(sig));

        // Index at exactly 2**h, honestly labelled in the digest.
        uint32 atBound = uint32(1) << H;
        (bytes memory eb, bytes memory xb) =
            _signLabelled(wallet, address(token), recipient, 1 ether, validUntil, atBound, 3);
        XMSS.Signature memory sb = abi.decode(xb, (XMSS.Signature));
        sb.leafIdx = atBound;
        vm.expectRevert(FermionWallet.InvalidXmssSignature.selector);
        wallet.transfer(address(token), recipient, 1 ether, validUntil, eb, abi.encode(sb));

        // uint32 max, likewise.
        (bytes memory em, bytes memory xm) =
            _signLabelled(wallet, address(token), recipient, 1 ether, validUntil, type(uint32).max, 3);
        XMSS.Signature memory sm = abi.decode(xm, (XMSS.Signature));
        sm.leafIdx = type(uint32).max;
        vm.expectRevert(FermionWallet.InvalidXmssSignature.selector);
        wallet.transfer(address(token), recipient, 1 ether, validUntil, em, abi.encode(sm));

        // Nothing was recorded, and leaf 3 — the one whose WOTS+ chains were
        // actually offered above — is still spendable exactly once.
        assertFalse(wallet.isLeafUsed(11));
        assertFalse(wallet.isLeafUsed(12));
        assertFalse(wallet.isLeafUsed(atBound));
        assertFalse(wallet.isLeafUsed(type(uint32).max));
        assertFalse(wallet.isLeafUsed(3));

        (bytes memory e3, bytes memory x3) = _sign(wallet, address(token), recipient, 1 ether, validUntil, 3);
        wallet.transfer(address(token), recipient, 1 ether, validUntil, e3, x3);
        assertTrue(wallet.isLeafUsed(3));
    }

    /// [NO FINDING] A token that is not a contract burns no leaf.
    ///
    /// The worry is a silent success: `safeTransfer` to an address with no code
    /// would return no data, the leaf would be marked spent and the tokens would
    /// not have moved. OpenZeppelin 5.2's `_callOptionalReturn` closes it —
    /// `returnSize == 0 ? address(token).code.length == 0 : returnValue != 1` —
    /// so an EOA, `address(0)` and a never-deployed address all revert with
    /// `SafeERC20FailedOperation` and the whole transaction, bitmap included, is
    /// rolled back. FWL-020's choice of `safeTransfer` over `IERC20.transfer` is
    /// what buys this; the suite's `FalseReturningToken` test covers only the
    /// "returns false" half of it.
    function test_NOFINDING_aTokenWithNoCodeRevertsAndSpendsNoLeaf() public {
        address[3] memory notTokens = [address(0), attacker, address(uint160(0xdead))];
        for (uint256 i = 0; i < notTokens.length; ++i) {
            (bytes memory e, bytes memory x) = _sign(wallet, notTokens[i], recipient, 1 ether, validUntil, uint32(i));
            vm.expectRevert(abi.encodeWithSelector(SafeERC20.SafeERC20FailedOperation.selector, notTokens[i]));
            wallet.transfer(notTokens[i], recipient, 1 ether, validUntil, e, x);
            assertFalse(wallet.isLeafUsed(uint32(i)));
        }
    }

    /// [NO FINDING] Reentrancy from the token buys nothing, with any signature.
    ///
    /// The existing suite re-enters with the *same* signature. The interesting
    /// case is a *different*, fully valid one: does executing two authorized
    /// transfers nested rather than sequentially corrupt anything? It cannot —
    /// `transfer` writes no state after the external call (`_usedLeaves.set`
    /// precedes it), so the inner frame starts from a fully committed outer state
    /// and the outer frame has nothing left to do. Two leaves are consumed for
    /// two signatures, which is the arithmetic the holder authorized.
    function test_NOFINDING_reentryWithASecondValidSignatureConsumesExactlyTwoLeaves() public {
        NestedToken t = new NestedToken();
        t.mint(address(wallet), 100 ether);

        (bytes memory e0, bytes memory x0) = _sign(wallet, address(t), recipient, 10 ether, validUntil, 0);
        (bytes memory e1, bytes memory x1) = _sign(wallet, address(t), recipient, 20 ether, validUntil, 1);
        t.arm(
            address(wallet),
            abi.encodeCall(FermionWallet.transfer, (address(t), recipient, 20 ether, validUntil, e1, x1))
        );

        wallet.transfer(address(t), recipient, 10 ether, validUntil, e0, x0);

        assertTrue(t.innerSucceeded());
        assertTrue(wallet.isLeafUsed(0));
        assertTrue(wallet.isLeafUsed(1));
        assertFalse(wallet.isLeafUsed(2));
        assertEq(t.balanceOf(recipient), 30 ether);
        assertEq(t.balanceOf(address(wallet)), 70 ether);
    }

    /// [NO FINDING] Neither signature half is malleable into a second acceptance.
    ///
    /// ECDSA: `ECDSA.tryRecover` (the EOA branch, FWL-017a), which accepts only a
    /// 65-byte `r‖s‖v` with `s <= n/2` and `v` in {27,28}, so the flipped-`s`
    /// twin, a 64-byte EIP-2098 compact form and a `v` of 0/1 are all refused
    /// (the device already normalizes to low `s` —
    /// `ledger-app/src/main.rs::sign_ecdsa`). XMSS: every byte of the structure
    /// is bound by the Merkle climb, and the one field that is not — nothing — so
    /// there is no slack. The existing suite covers the flipped-`s` twin; the
    /// other two encodings are added here.
    function test_NOFINDING_noAlternativeEncodingOfEitherHalfIsAccepted() public {
        bytes32 d = _digest(wallet, address(token), recipient, 1 ether, 0, validUntil);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(DEVICE_PK, d);
        (,, bytes memory x) = _xmss(H, 0, d);

        // EIP-2098 compact 64-byte form.
        bytes32 vs = bytes32(uint256(s) | (v == 28 ? (uint256(1) << 255) : 0));
        vm.expectRevert(FermionWallet.InvalidEcdsaSignature.selector);
        wallet.transfer(address(token), recipient, 1 ether, validUntil, abi.encodePacked(r, vs), x);

        // v as 0/1 instead of 27/28.
        vm.expectRevert(FermionWallet.InvalidEcdsaSignature.selector);
        wallet.transfer(address(token), recipient, 1 ether, validUntil, abi.encodePacked(r, s, v - 27), x);

        // 66 bytes: the genuine signature with one trailing byte.
        vm.expectRevert(FermionWallet.InvalidEcdsaSignature.selector);
        wallet.transfer(address(token), recipient, 1 ether, validUntil, abi.encodePacked(r, s, v, hex"00"), x);

        assertFalse(wallet.isLeafUsed(0));
        wallet.transfer(address(token), recipient, 1 ether, validUntil, abi.encodePacked(r, s, v), x);
        assertTrue(wallet.isLeafUsed(0));
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Helpers
    // ══════════════════════════════════════════════════════════════════════════

    /// Repoint the encoded signature's `authPath` offset at a length word we
    /// choose, without changing the blob's byte count. Layout of
    /// `abi.encode(XMSS.Signature)`: [0,32) outer offset; struct body starts at
    /// byte 32 with leafIdx, r, 67 inline wotsSig words and the authPath offset at
    /// bytes [2240,2272); then the authPath length at [2272,2304) and its words.
    /// Here the offset is aimed at struct-relative 64 (the `wotsSig[0]` slot),
    /// where `declared` is written; the path's nodes then come out of the rest of
    /// `wotsSig`, which is in bounds, so strict ABI decoding is happy.
    function _withDeclaredAuthPathLength(bytes memory blob, uint256 declared) internal pure returns (bytes memory out) {
        out = new bytes(blob.length);
        for (uint256 i = 0; i < blob.length; ++i) {
            out[i] = blob[i];
        }
        assembly ("memory-safe") {
            let base := add(out, 32)
            mstore(add(base, 2240), 64) // authPath offset, struct-relative
            mstore(add(base, 96), declared) // the length word it now points at
        }
    }

    function deploy(bytes32 r, bytes32 s, uint256 h, address a) public returns (FermionWallet) {
        return new FermionWallet(r, s, h, a);
    }

    /// `vm.expectRevert` cannot be used on `new` (see the S2/S3 note above), so
    /// each construction gets its own CALL frame and its own explicit assertion.
    function _assertDeployReverts(bytes32 r, bytes32 s, uint256 h, address a, string memory what) internal {
        (bool ok, bytes memory err) = address(this).call(abi.encodeCall(this.deploy, (r, s, h, a)));
        assertFalse(ok, what);
        assertEq(bytes4(err), FermionWallet.InvalidKeyParams.selector, what);
    }

    function _digest(FermionWallet w, address token_, address to, uint256 amount, uint32 leaf, uint64 expiry)
        internal
        view
        returns (bytes32)
    {
        bytes32 domain = keccak256(
            abi.encode(DOMAIN_TYPEHASH, keccak256("FermionWallet"), keccak256("1"), block.chainid, address(w))
        );
        bytes32 structHash = keccak256(abi.encode(TRANSFER_TYPEHASH, address(w), token_, to, amount, leaf, expiry));
        return keccak256(abi.encodePacked(hex"1901", domain, structHash));
    }

    function _sign(FermionWallet w, address token_, address to, uint256 amount, uint64 expiry, uint32 leaf)
        internal
        returns (bytes memory ecdsa, bytes memory xmss)
    {
        return _signLabelled(w, token_, to, amount, expiry, leaf, leaf);
    }

    function _signLabelled(
        FermionWallet w,
        address token_,
        address to,
        uint256 amount,
        uint64 expiry,
        uint32 labelledLeaf,
        uint32 spentLeaf
    ) internal returns (bytes memory ecdsa, bytes memory xmss) {
        bytes32 d = _digest(w, token_, to, amount, labelledLeaf, expiry);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(DEVICE_PK, d);
        ecdsa = abi.encodePacked(r, s, v);
        (,, xmss) = _xmss(uint32(w.treeHeight()), spentLeaf, d);
    }

    /// The RFC 8391 reference implementation over FFI — the same deterministic
    /// test key `FermionWallet.t.sol` and the Guard suites use.
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

/// A token whose `transfer` re-enters the wallet once, with a *different* valid
/// signature than the one that is moving its tokens.
contract NestedToken {
    mapping(address => uint256) public balanceOf;

    address internal wallet;
    bytes internal payload;
    bool internal armed;
    bool public innerSucceeded;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function arm(address wallet_, bytes calldata payload_) external {
        (wallet, payload, armed) = (wallet_, payload_, true);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        if (armed) {
            armed = false;
            (bool ok,) = wallet.call(payload);
            innerSucceeded = ok;
        }
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
