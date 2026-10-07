// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {BitMaps} from "@openzeppelin/contracts/utils/structs/BitMaps.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {XMSS} from "xmss-solidity/XMSS.sol";

/// @title FermionWallet — the smallest possible post-quantum ERC-20 wallet
/// @notice An address that holds ERC-20 tokens and releases them only against a hybrid
///         (ECDSA + XMSS) signature from the Fermion Ledger app. One immutable key baked
///         in at construction, one state-changing function, one used-leaf bitmap as the
///         only mutable state. Specified by `fermionwallet.md` [FWL-001]…[FWL-036].
/// @dev    What this contract deliberately does NOT have, because each absence is what
///         keeps it small — and because each, if present, would be a way for tokens to
///         leave without the device's consent:
///
///           * no owner, admin, role, pause or upgrade path [FWL-006];
///           * no recovery: lose the device and its seed backup and the balance is
///             unreachable forever — choose FermionGuard if that is unacceptable [FWL-007];
///           * no `receive`, no `payable`, no way to send ETH: a wallet that could take
///             ETH and never return it would be a trap [FWL-008];
///           * no `approve`, no arbitrary call, no delegatecall, no batching — an
///             allowance would let a spender move tokens with no XMSS signature at all,
///             voiding the whole point [FWL-009];
///           * no gas refund to the relayer: the wallet never pays anyone out of its
///             balance, which is exactly how a refund parameter once made the Guard's
///             escape hatch drainable [FWL-010];
///           * no key rotation: rotation is a transfer to a new wallet, authorized by the
///             current key, which is rotation with no extra code [FWL-011].
///
///         There is no outbound path for tokens other than `transfer` [FWL-005], and
///         `transfer` consults `msg.sender` nowhere [FWL-021].
/// @author FermionWallet — MIT licensed.
contract FermionWallet is EIP712 {
    using BitMaps for BitMaps.BitMap;
    using SafeERC20 for IERC20;
    using SignatureChecker for address;

    // ── The signed message ──────────────────────────────────────────────────

    /// @notice EIP-712 type hash of the only message this wallet accepts.
    /// @dev    The type string is byte-for-byte the one the device builds its digest
    ///         from (`ledger-app/src/wallet.rs`, `TRANSFER_TYPE`), under the domain
    ///         `{ name: "FermionWallet", version: "1", chainId, verifyingContract: this }`
    ///         — so the chain and the wallet address are part of every signature and a
    ///         signature for one wallet is meaningless to any other wallet or chain
    ///         [FWL-013]. The device recomputes this digest from the fields it displays;
    ///         it never signs a hash handed to it by the host, and this interface gives
    ///         it no way to — `transfer` takes fields, never a digest [FWL-014].
    bytes32 public constant TRANSFER_TYPEHASH = keccak256(
        "Transfer(address wallet,address token,address to,uint256 amount,uint32 leafIndex,uint64 validUntil)"
    );

    /// Wire length of `abi.encode(XMSS.Signature)` with an empty authentication path:
    /// the leading offset word, the head (leafIdx, r, wotsSig[67] inline, authPath
    /// offset) and the authPath length word. The full blob is this plus one word per
    /// tree level. Checked before decoding so a malformed argument fails with a clear
    /// error instead of an ABI decode revert, and so step 2 below stays arithmetic.
    uint256 internal constant ENCODED_SIGNATURE_BASE_LENGTH = 2304;

    // ── The key, immutable from deployment [FWL-002] ────────────────────────

    /// @notice XMSS public root of the device key bound to this wallet.
    bytes32 public immutable xmssRoot;
    /// @notice XMSS public SEED of that key.
    bytes32 public immutable xmssSeed;
    /// @notice Tree height the key was generated with; binds the parameter set the way
    ///         RFC 8391's public-key OID does. The RFC 8391 single-tree sets are 10, 16
    ///         and 20 [FWL-027]; the contract accepts any height the pinned library
    ///         supports (1…`XMSS.MAX_HEIGHT`), exactly as `QuantumKeyRegistry` does, and
    ///         the parameter set is a deployment choice rather than an on-chain rule.
    uint256 public immutable treeHeight;
    /// @notice The device's ECDSA address — the classical half of the hybrid.
    address public immutable quantumAdmin;
    /// @notice Whether `quantumAdmin` had code at the moment this wallet was built, and
    ///         therefore which scheme the classical half is checked under for the rest of
    ///         the wallet's life: `false` means secp256k1 recovery, `true` means ERC-1271.
    /// @dev    Snapshotted, not read live, and that is the whole point. OpenZeppelin's
    ///         `SignatureChecker.isValidSignatureNow` branches on
    ///         `signer.code.length == 0` *at call time*, so an address that is an EOA at
    ///         deployment and gains code later — most realistically because its own key
    ///         signed an EIP-7702 authorization, which is routine and has nothing to do
    ///         with this wallet — would silently stop being checked by recovery and start
    ///         being asked for an ERC-1271 opinion instead. A delegate without
    ///         `isValidSignature` refuses every genuine device signature from then on, and
    ///         with no owner, pause, recovery or rotation-that-is-not-a-transfer
    ///         ([FWL-006], [FWL-007], [FWL-011]) the balance would be unreachable forever;
    ///         a permissive delegate is worse, handing the classical half to whoever that
    ///         delegate trusts. Freezing the branch at construction makes the delegation
    ///         irrelevant: the device's key still signs, recovery still returns
    ///         `quantumAdmin`, and a deliberate ERC-1271 admin still works because it was
    ///         already a contract when the wallet was built. [FWL-017a]
    ///
    ///         It is public because it is the one fact that distinguishes, on-chain, a
    ///         wallet whose classical half is a device key from one whose classical half is
    ///         whatever a contract chooses to bless ([FWL-022a]).
    bool public immutable adminIsContract;

    // ── The only mutable state ──────────────────────────────────────────────

    /// One bit per XMSS leaf: the on-chain backstop for the rule that a WOTS+ one-time
    /// key signs exactly one digest. It is spent-leaf accounting and nothing else — no
    /// nonces, no queues, no policy.
    BitMaps.BitMap private _usedLeaves;

    // ── Events and errors ───────────────────────────────────────────────────

    event Transferred(address indexed token, address indexed to, uint256 amount, uint32 leafIndex);

    /// A signed transfer that was never relayed stops being valid [FWL-015].
    error SignatureExpired(uint64 validUntil);
    /// The leaf named by the XMSS signature has already been spent by this wallet.
    error LeafAlreadyUsed(uint32 leafIndex);
    /// `xmssSignature` is not `abi.encode(XMSS.Signature)` for this key's tree height.
    error InvalidXmssSignatureLength(uint256 length);
    /// The classical half does not come from `quantumAdmin` over the rebuilt digest.
    error InvalidEcdsaSignature();
    /// The post-quantum half does not verify against (`xmssRoot`, `xmssSeed`).
    error InvalidXmssSignature();
    /// A constructor argument would have produced a wallet no signature could ever open.
    error InvalidKeyParams();

    /// @param xmssRoot_     the device key's XMSS root (`GET_XMSS_ROOT`)
    /// @param xmssSeed_     that key's public SEED
    /// @param treeHeight_   the height it was generated with (1…`XMSS.MAX_HEIGHT`)
    /// @param quantumAdmin_ the device's ECDSA address (`GET_ADMIN_ADDRESS`)
    /// @dev The key is bound here and can never change: the constructor arguments are
    ///      part of the init code, so under a CREATE2 factory the address itself pins the
    ///      key and nobody — including the holder — can deploy a different wallet there
    ///      [FWL-030], [FWL-031]. Zero values are rejected: `XMSS.verify` refuses a zero
    ///      root or SEED unconditionally, and `address(0)` as the admin would make the
    ///      ECDSA half unsatisfiable, so each would deploy an inescapable black hole.
    constructor(bytes32 xmssRoot_, bytes32 xmssSeed_, uint256 treeHeight_, address quantumAdmin_)
        EIP712("FermionWallet", "1")
    {
        if (
            xmssRoot_ == bytes32(0) || xmssSeed_ == bytes32(0) || quantumAdmin_ == address(0) || treeHeight_ == 0
                || treeHeight_ > XMSS.MAX_HEIGHT
        ) revert InvalidKeyParams();

        xmssRoot = xmssRoot_;
        xmssSeed = xmssSeed_;
        treeHeight = treeHeight_;
        quantumAdmin = quantumAdmin_;
        // The branch, taken once, here. See `adminIsContract` for why it is not read live.
        adminIsContract = quantumAdmin_.code.length != 0;
    }

    /// @notice Whether this wallet has already spent XMSS leaf `leafIndex`.
    /// @dev The bitmap only ever sees leaves spent by THIS wallet. Binding one key to two
    ///      FermionWallets — or to a wallet and a Safe running FermionGuard — gives two
    ///      bitmaps that each start empty, and one leaf can then be spent twice. That is
    ///      refused on the device (one key slot, one verifying contract, one chain
    ///      [FWL-023]) and nowhere else: a rolled-back or cloned device defeats it with
    ///      no on-chain second opinion [FWL-025]. Deployments that cannot accept that
    ///      should use a shared leaf registry [FWL-026] or FermionGuard.
    function isLeafUsed(uint32 leafIndex) external view returns (bool) {
        return _usedLeaves.get(leafIndex);
    }

    /// @notice Move `amount` of `token` to `to`, against one hybrid signature from the
    ///         device. Relayable by anyone; the signature is the only authorization
    ///         [FWL-004], [FWL-021].
    /// @param token          the ERC-20 to move
    /// @param to             the recipient
    /// @param amount         the amount to send (what `safeTransfer` sends, not
    ///                       necessarily what a fee-taking or rebasing token delivers)
    /// @param validUntil     last block timestamp at which this signature may be relayed
    /// @param ecdsaSignature the device's classical half over the EIP-712 digest
    /// @param xmssSignature  `abi.encode(XMSS.Signature)` — its embedded `leafIdx` is the
    ///                       leaf that gets spent, and the index the digest is rebuilt
    ///                       with [FWL-034]
    /// @dev **Both halves are required** over the same digest [FWL-022]: breaking this
    ///      wallet means forging ECDSA *and* XMSS. A quantum adversary who breaks ECDSA
    ///      still faces the hash-based half; a flaw in our young XMSS code still leaves
    ///      the battle-tested classical one. The device produces both in one confirmation.
    ///
    ///      Note what is not an argument: **there is no `leafIndex` parameter.** The index
    ///      is read out of the XMSS signature and used both for the bitmap and for
    ///      rebuilding the digest, so the two can never disagree. Had it been a separate
    ///      calldata field, a compromised or rolled-back device could sign leaf 5 twice
    ///      while labelling the transfers leaf 0 and leaf 1: both would verify, both would
    ///      execute, and the bitmap — the one thing that exists to stop leaf reuse — would
    ///      record two untouched leaves. Taking the index from the signature closes that
    ///      off structurally: a signature whose struct field named a different leaf than
    ///      it actually used fails the ECDSA check below [FWL-034].
    function transfer(
        address token,
        address to,
        uint256 amount,
        uint64 validUntil,
        bytes calldata ecdsaSignature,
        bytes calldata xmssSignature
    ) external {
        // 1. Expiry. Cheapest check first, and the holder's only control over a
        //    signature they cannot cancel: it stays relayable by anyone until this
        //    moment, with no cancel path, so short windows are the whole defence
        //    [FWL-015], [FWL-036].
        if (block.timestamp > validUntil) revert SignatureExpired(validUntil);

        // 2. The spent leaf, and whether it is already spent. Decoding the signature
        //    structure and reading a uint32 field involves no cryptography, so this
        //    check comes BEFORE the ~700k-gas verification below and a replay costs the
        //    relayer almost nothing [FWL-016].
        if (xmssSignature.length != ENCODED_SIGNATURE_BASE_LENGTH + 32 * treeHeight) {
            revert InvalidXmssSignatureLength(xmssSignature.length);
        }
        XMSS.Signature memory sig = abi.decode(xmssSignature, (XMSS.Signature));
        uint32 leafIndex = sig.leafIdx;
        if (_usedLeaves.get(leafIndex)) revert LeafAlreadyUsed(leafIndex);

        // The digest is rebuilt from the calldata fields and the leaf index the XMSS
        // signature actually used — never from a hash supplied by the caller [FWL-014],
        // [FWL-034]. `_hashTypedDataV4` binds chain id and this address [FWL-013].
        bytes32 digest = _hashTypedDataV4(
            keccak256(abi.encode(TRANSFER_TYPEHASH, address(this), token, to, amount, leafIndex, validUntil))
        );

        // 3. The classical half, under the scheme fixed at construction. An ERC-1271
        //    contract signer works [FWL-017]; never raw `ecrecover`, and never a branch
        //    that a later EIP-7702 delegation of `quantumAdmin` could move [FWL-017a].
        //    `tryRecover` rather than `recover`, so a malformed, short or absent
        //    classical half reverts with this contract's own error rather than one of
        //    OpenZeppelin's.
        bool classicalHalfOk;
        if (adminIsContract) {
            classicalHalfOk = quantumAdmin.isValidERC1271SignatureNow(digest, ecdsaSignature);
        } else {
            (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(digest, ecdsaSignature);
            classicalHalfOk = err == ECDSA.RecoverError.NoError && recovered == quantumAdmin;
        }
        if (!classicalHalfOk) revert InvalidEcdsaSignature();

        // 4. The post-quantum half, with the four-argument `XMSS.verify` — the form that
        //    binds the registered tree height to the key instead of letting whoever
        //    supplies the signature choose it [FWL-018]. The library is the pinned
        //    `xmss-solidity` submodule, unchanged; this wallet adds no cryptography of its
        //    own [FWL-032].
        if (!XMSS.verify(digest, sig, XMSS.PublicKey({root: xmssRoot, seed: xmssSeed}), treeHeight)) {
            revert InvalidXmssSignature();
        }

        // 5. Spend the leaf BEFORE the token call [FWL-019]. A token that re-enters this
        //    function with the same signature finds the leaf already spent, which is why
        //    no reentrancy guard is needed.
        _usedLeaves.set(leafIndex);

        // 6. The transfer itself, through SafeERC20: a token that returns false without
        //    reverting must fail the whole transaction, not pass silently [FWL-020].
        //    If the token call reverts (paused, blocklisted, zero-value refused) the whole
        //    transaction reverts and the leaf is NOT spent on-chain — but the device
        //    committed its counter before signing, so that leaf is burned there. Nothing
        //    is lost; the same signature stays relayable by anyone until `validUntil`
        //    [FWL-035], [FWL-036].
        //    The event is emitted before the call, not after: a revert discards logs, so
        //    it is published exactly when the transfer succeeds either way, and a
        //    re-entrant token cannot interleave logs ahead of this one.
        emit Transferred(token, to, amount, leafIndex);

        IERC20(token).safeTransfer(to, amount);
    }
}
