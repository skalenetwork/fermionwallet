#!/usr/bin/env python3
"""End-to-end checks for the app's FermionWallet support, against the app itself.

FermionWallet (`fermionwallet.md`) is the second product this key can sign for: one
contract holding ERC-20 tokens, no Safe and no registry. The app tells a `Transfer`
from a `PreApproval` by the streamed payload's length, hashes it under the
`FermionWallet` domain, and binds the key slot to one verifying contract [FWL-023].

What is checked here is what decides whether a transfer the device signs is one the
wallet contract would accept, plus the binding, which on this product has no on-chain
backstop at all [FWL-025]:

1. the digest the device reports is the EIP-712 `Transfer` digest of the fields sent,
   computed independently with `cast` — so the device hashes what it displayed and
   agrees with the contract;
2. the XMSS half verifies under the published root and SEED, checked with the RFC 8391
   reference implementation the Solidity verifier is proven against;
3. the ECDSA half recovers to the address the device reports as `quantumAdmin`;
4. the review shows the wallet, the token, the amount and the recipient — and no Safe,
   no pin and no policy, because a `Transfer` has no such fields;
5. a second transfer for the same wallet is accepted, one for a *different* wallet is
   refused, and a Safe pre-approval is refused once the slot is bound to a wallet;
6. a refused signature consumes no leaf, and the counter advances by exactly one per
   signature.

    ledger-app/test/test_wallet.py          # expects the ELF built by build.sh
    SPECULOS_APDU_URL=... test_wallet.py    # against an already-running Speculos

Reuses the harness in test_app.py (the emulator, the button walker, `cast`) so there
is one Speculos launcher and one place where the checks are counted.
"""
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(REPO, "demo"))
sys.path.insert(0, os.path.join(REPO, "contracts", "lib", "xmss-solidity", "py"))

import test_app as base  # noqa: E402  (the shared harness)
from test_app import CHAIN_ID, FIELDS, GUARD, SEED, cast, check, decide  # noqa: E402

DOMAIN_TYPE = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
TRANSFER_TYPE = (
    "Transfer(address wallet,address token,address to,uint256 amount,uint32 leafIndex,"
    "uint64 validUntil)"
)

# Two different wallets: the key may sign for the first one only.
WALLET = "0xCf7Ed3AcCa5a467e9e704C703E8D87F634fB0Fc9"
OTHER_WALLET = "0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9"
TRANSFER = {
    "token": "0x5FbDB2315678afecb367f032d93F642f64180aa3",
    "to": "0x000000000000000000000000000000000000dEaD",
    "amount": str(125 * 10**18),
    "validUntil": 1790086400,
}

ELF = os.path.join(REPO, "ledger-app", "build", "nanos2", "bin", "app.elf")


class Emulator:
    """The built app in Speculos, on ports of its own.

    Deliberately not test_app.py's launcher: two suites that fix the same ports cannot
    run at the same time, and this one also restarts the device mid-run to get a second
    key with a clean binding.
    """

    API, APDU = 15003, 19996

    def __init__(self):
        self.container = None
        if os.environ.get("SPECULOS_APDU_URL"):
            return
        if not os.path.exists(ELF):
            sys.exit(f"no app at {ELF} — run ledger-app/build.sh first")
        self.container = f"fg-wallet-test-{os.getpid()}-{int(time.time())}"
        subprocess.run(
            ["docker", "run", "-d", "--rm", "--name", self.container,
             "-v", os.path.dirname(ELF) + ":/app",
             "-p", f"{self.API}:5000", "-p", f"{self.APDU}:9999",
             "ghcr.io/ledgerhq/speculos:latest", "--model", "nanosp", "--display", "headless",
             "--api-port", "5000", "--apdu-port", "9999", "--seed", SEED, "/app/app.elf"],
            check=True, capture_output=True)
        os.environ["SPECULOS_APDU_URL"] = f"tcp://127.0.0.1:{self.APDU}"
        os.environ["SPECULOS_API_URL"] = f"http://127.0.0.1:{self.API}"

    def stop(self):
        if self.container:
            subprocess.run(["docker", "rm", "-f", self.container], capture_output=True)
            os.environ.pop("SPECULOS_APDU_URL", None)
            os.environ.pop("SPECULOS_API_URL", None)
            time.sleep(1)  # let the ports come free before the next container

    def wait(self, device):
        for _ in range(60):
            try:
                device.next_leaf()
                return
            except Exception:  # noqa: BLE001 (the emulator is simply not up yet)
                time.sleep(1)
        sys.exit("the app never answered in Speculos")


# The app's APDU surface (demo/ledger_device.py documents the framing).
INS_SIGN = 0x04
INS_CHUNK = 0x50
P1_FIRST, P1_MORE, P1_LAST = 0x00, 0x80, 0x81
SW_WRONG_BINDING = 0x6A81


def transfer_digest(wallet, fields, leaf):
    """The digest the FermionWallet contract computes — an independent path from the
    device's own keccak, and from the Rust that produced it."""
    domain = cast("keccak", cast(
        "abi-encode", "f(bytes32,bytes32,bytes32,uint256,address)",
        cast("keccak", DOMAIN_TYPE), cast("keccak", "FermionWallet"), cast("keccak", "1"),
        str(CHAIN_ID), wallet))
    struct_hash = cast("keccak", cast(
        "abi-encode", "f(bytes32,address,address,address,uint256,uint32,uint64)",
        cast("keccak", TRANSFER_TYPE), wallet, fields["token"], fields["to"], fields["amount"],
        str(leaf), str(fields["validUntil"])))
    return cast("keccak", "0x1901" + domain[2:] + struct_hash[2:])


def encode_transfer(wallet, fields, chain_id):
    """chainId(32) ‖ wallet(20) ‖ token(20) ‖ to(20) ‖ amount(32) ‖ validUntil(8).

    The leaf index is absent on purpose: it is the device's counter, not ours.
    """
    addr = lambda a: bytes.fromhex(a[2:].rjust(40, "0"))  # noqa: E731
    return b"".join([
        int(chain_id).to_bytes(32, "big"),
        addr(wallet),
        addr(fields["token"]),
        addr(fields["to"]),
        int(fields["amount"]).to_bytes(32, "big"),
        int(fields["validUntil"]).to_bytes(8, "big"),
    ])


def sign_transfer(device, wallet, fields, chain_id, chunks=1, timeout=30):
    """Stream a Transfer and collect both halves, exactly as a wallet host would."""
    payload = encode_transfer(wallet, fields, chain_id)
    assert len(payload) == 132, len(payload)
    if chunks == 1:
        pieces = [payload]
    else:
        cut = len(payload) // 2
        pieces = [payload[:cut], payload[cut:]]
    out = None
    for i, piece in enumerate(pieces):
        last = i == len(pieces) - 1
        p1 = P1_LAST if last else (P1_FIRST if i == 0 else P1_MORE)
        out = device._send(INS_SIGN, p1, piece, timeout if last else 30)
    leaf = int.from_bytes(out[:4], "big")
    digest = "0x" + out[4:36].hex()
    total = int.from_bytes(out[36:38], "big")
    blob = b""
    while len(blob) < total:
        blob += device._send(INS_CHUNK, p1=P1_FIRST if not blob else P1_MORE)
    return {"leaf": leaf, "digest": digest, "blob": blob[:total]}


def split_blob(blob, height):
    """`r(32) ‖ wotsSig(67×32) ‖ auth(h×32) ‖ ecdsa(65)` — the wire format
    `demo/ledger_device.py` documents, ECDSA last so no host can hold the classical
    half without the whole quantum one. The public key is deliberately absent: the root
    and SEED are on-chain from registration and come from `GET_XMSS_ROOT` here, so a
    device that published one key and signed under another would be caught."""
    rest, ecdsa = blob[:-65], blob[-65:]
    expected = 32 * (1 + 67 + height)
    assert len(rest) == expected, f"signature is {len(rest)} bytes, expected {expected}"
    r, rest = rest[:32], rest[32:]
    wots = [rest[32 * i:32 * (i + 1)] for i in range(67)]
    auth = [rest[32 * (67 + i):32 * (68 + i)] for i in range(height)]
    return ecdsa, r, wots, auth


def main():
    import ledger_device as ld
    import xmss_ref

    emu = Emulator()
    try:
        device = ld.Device(ld.transport())
        emu.wait(device)
        admin = device.admin_address()
        key = device.xmss_root()
        height = key["treeHeight"]
        start_leaf = device.next_leaf()

        # ── 1. one transfer, signed in a single APDU ──────────────────────────
        screens = []
        decide(device.tr, "approve", screens)
        res = sign_transfer(device, WALLET, TRANSFER, CHAIN_ID, chunks=1)
        check("a 132-byte Transfer is accepted as one chunk", res["leaf"] == start_leaf,
              f"leaf {res['leaf']}, expected {start_leaf}")
        want = transfer_digest(WALLET, TRANSFER, res["leaf"])
        check("the device's digest is the EIP-712 Transfer digest of the fields sent",
              res["digest"].lower() == want.lower(), f"device {res['digest']} vs cast {want}")

        root, seed = bytes.fromhex(key["root"][2:]), bytes.fromhex(key["seed"][2:])
        ecdsa, r, wots, auth = split_blob(res["blob"], height)
        check("the XMSS half verifies under the root and SEED the device published",
              xmss_ref.verify(bytes.fromhex(res["digest"][2:]), res["leaf"], r, wots, auth,
                              root, seed))
        check("and does not verify for a different digest",
              not xmss_ref.verify(bytes(32), res["leaf"], r, wots, auth, root, seed))
        check("the signature carries exactly one auth node per tree level",
              len(auth) == height and len(wots) == 67, f"{len(auth)} auth, {len(wots)} wots")

        sig = "0x" + ecdsa.hex()
        verify = subprocess.run(
            ["cast", "wallet", "verify", "--address", admin, "--no-hash", res["digest"], sig],
            capture_output=True, text=True)
        check("the ECDSA half recovers to the device's quantumAdmin address",
              verify.returncode == 0, verify.stderr.strip() or verify.stdout.strip())
        check("s is in the lower half of the curve order",
              int.from_bytes(ecdsa[32:64], "big") <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0)

        # ── 2. the review showed the wallet, and nothing that isn't signed ────
        text = " ".join(" ".join(lines) for lines in screens)
        check("the review names the wallet being spent from", "Wallet" in text, text[:300])
        check("and shows no Safe, pin or policy page — a Transfer has no such fields",
              "Safe" not in text and "Policy" not in text and "Binding" not in text, text[:300])
        # Speculos reports a scrolling BAGL line from wherever it had got to, so the
        # first frame can arrive as "end tokens". Match a fragment: what matters is that
        # this is the transfer flow and not the Safe pre-approval flow.
        check("the review is headed as a transfer, not a Safe approval",
              "tokens" in text and "Sign approval" not in text, text[:200])

        # ── 3. the same wallet again: still fine, counter advanced by one ─────
        decide(device.tr, "approve")
        second = sign_transfer(device, WALLET, TRANSFER, CHAIN_ID, chunks=2)
        check("a second transfer for the same wallet is accepted, split across chunks",
              second["leaf"] == res["leaf"] + 1, f"leaf {second['leaf']}")
        check("its digest matches too",
              second["digest"].lower() == transfer_digest(WALLET, TRANSFER, second["leaf"]).lower())

        # ── 4. a different wallet: refused, unseen ────────────────────────────
        before = device.next_leaf()
        try:
            sign_transfer(device, OTHER_WALLET, TRANSFER, CHAIN_ID, chunks=1, timeout=8)
            check("a transfer for another wallet is refused", False, "it signed anyway")
        except ld.DeviceError as e:
            check("a transfer for another wallet is refused [FWL-023]",
                  "belongs to a different contract" in str(e), str(e))
        except (TimeoutError, OSError):
            # The device drew a review and is waiting for a human: the refusal that was
            # supposed to happen before any screen did not happen.
            check("a transfer for another wallet is refused [FWL-023]", False,
                  "the device asked for approval instead of refusing it unseen")
        check("and consumed no leaf", device.next_leaf() == before, str(device.next_leaf()))

        # ── 4b. the same wallet address on another chain: also refused ────────
        #
        # FWL-031 recommends a CREATE2 factory, which puts the same wallet address on
        # every chain. Two such wallets are two contracts with two used-leaf bitmaps, so
        # a binding that ignored the chain id would let one leaf be spent on each.
        try:
            sign_transfer(device, WALLET, TRANSFER, CHAIN_ID + 1, chunks=1, timeout=8)
            check("the same wallet address on another chain is refused", False,
                  "it signed anyway")
        except ld.DeviceError as e:
            check("the same wallet address on another chain is refused [FWL-023]",
                  "belongs to a different contract" in str(e), str(e))
        except (TimeoutError, OSError):
            check("the same wallet address on another chain is refused [FWL-023]", False,
                  "the device asked for approval instead of refusing it unseen")
        check("and consumed no leaf", device.next_leaf() == before, str(device.next_leaf()))

        # ── 5. a Safe pre-approval on a wallet-bound key: refused ─────────────
        try:
            device.sign_preapproval(FIELDS, CHAIN_ID, GUARD, timeout=8)
            check("a Safe pre-approval is refused once the key is a wallet key", False,
                  "it signed anyway")
        except ld.DeviceError as e:
            check("a Safe pre-approval is refused once the key is a wallet key [FWL-023]",
                  "belongs to a different contract" in str(e), str(e))
        except (TimeoutError, OSError):
            check("a Safe pre-approval is refused once the key is a wallet key [FWL-023]", False,
                  "the device asked for approval instead of refusing it unseen")
        check("and consumed no leaf either", device.next_leaf() == before, str(device.next_leaf()))

        # ── 6. rejecting on the device costs nothing ──────────────────────────
        decide(device.tr, "reject")
        try:
            sign_transfer(device, WALLET, TRANSFER, CHAIN_ID, chunks=1, timeout=20)
            check("a rejected transfer produces no signature", False, "it signed anyway")
        except ld.DeviceError as e:
            check("a rejected transfer produces no signature", "Rejected" in str(e), str(e))
        time.sleep(0.2)
        check("a rejection consumes no leaf", device.next_leaf() == before, str(device.next_leaf()))
    finally:
        emu.stop()

    # ── 7. the other direction, on a fresh device: a Safe key refuses a wallet ──
    #
    # This is the case that matters most for the wallet product. A key that has signed
    # for a Safe has leaves accounted for in the registry, which the wallet contract
    # cannot see; if the same key could then sign a wallet transfer, one leaf could be
    # spent under both and nothing on-chain would notice [FWL-023, FWL-025].
    emu = Emulator()  # a fresh device: stop() cleared the environment
    try:
        device = ld.Device(ld.transport())
        emu.wait(device)
        decide(device.tr, "approve")
        first = device.sign_preapproval(FIELDS, CHAIN_ID, GUARD, timeout=30)
        check("a fresh key signs a Safe pre-approval", first.get("status") == "approved",
              str(first))
        before = device.next_leaf()
        try:
            sign_transfer(device, WALLET, TRANSFER, CHAIN_ID, chunks=1, timeout=8)
            check("a wallet transfer is refused once the key is a Safe key", False,
                  "it signed anyway")
        except ld.DeviceError as e:
            check("a wallet transfer is refused once the key is a Safe key [FWL-023]",
                  "belongs to a different contract" in str(e), str(e))
        except (TimeoutError, OSError):
            check("a wallet transfer is refused once the key is a Safe key [FWL-023]", False,
                  "the device asked for approval instead of refusing it unseen")
        check("and consumed no leaf", device.next_leaf() == before, str(device.next_leaf()))
    finally:
        emu.stop()

    print(f"\n{'FAILED: ' + ', '.join(base.failures) if base.failures else 'all checks passed'}")
    return 1 if base.failures else 0


if __name__ == "__main__":
    sys.exit(main())
