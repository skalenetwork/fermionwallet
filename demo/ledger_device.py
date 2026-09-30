#!/usr/bin/env python3
"""Talk to a real FermionGuard Ledger — over USB to a physical device, or over TCP
to the same app running in Speculos (Ledger's emulator).

This replaces the HTTP call to the Python simulator (`ledger_sim.py`) with the real
APDU exchange described in ledger-xmss-app.md. Stdlib, plus Foundry's `cast` for the
host-side digest check; USB additionally needs `hid`, Speculos needs nothing.

Wire protocol (the concrete framing the spec's command table leaves open)
------------------------------------------------------------------------
CLA is 0xE0. Every command carries the key slot in P2. The instruction numbers are
the Ethereum app's: a command with an Ethereum analogue keeps that app's own number,
and the FermionGuard-specific ones start at 0x40, above its highest assignment, so no
number means two different things in two apps (ledger-xmss-app.md). Commands:

  INS 0x02  GET_ADMIN_ADDRESS    -> address(20)   [GET ETH PUBLIC ADDRESS]
  INS 0x04  SIGN_PREAPPROVAL     streams the payload, P1 = 0x00 first chunk,
                                 0x80 more follow, 0x81 last chunk. The device
                                 shows every field, and the response to the LAST
                                 chunk arrives only once the human decides:
                                   0x9000 -> leaf(4) ‖ digest(32) ‖ totalLen(2)
                                   0x6985 -> rejected on the device
  INS 0x06  GET_APP_CONFIG       -> what the ceremony preflight checks
  INS 0x44  GET_XMSS_ROOT        -> root(32) ‖ seed(32) ‖ treeHeight(1) ‖ parameterSet(32)
  INS 0x46  GET_LEAF_INDEX       -> nextLeaf(4, big-endian)
  INS 0x50  GET_SIGNATURE_CHUNK  P1 = 0x00 first chunk, 0x80 each next one ->
                                 up to 255 bytes of
                                 r(32) ‖ wotsSig(67*32) ‖ auth(h*32) ‖ ecdsa(65)

The ECDSA half is LAST: a host that reads only the first chunk has neither half
whole, so the classical signature cannot leave the device ahead of the quantum one.

The signed payload is streamed as the fields themselves, never a host-supplied
hash: the device recomputes the EIP-712 digest from what it displayed.

  chainId(32) ‖ verifyingContract(20) ‖ safe(20) ‖ approvalClass(1) ‖ token(20)
  ‖ recipient(20) ‖ amount(32) ‖ target(20) ‖ value(32) ‖ dataHash(32)
  ‖ validFrom(8) ‖ validTo(8) ‖ nonce(32) ‖ quantumKeyId(32) ‖ policyHash(32)
  ‖ txHash(32)

The host checks the digest the device reports against its own computation and
refuses the signatures if they differ.
"""
import json
import os
import socket
import struct
import subprocess
import sys
import urllib.request

CLA = 0xE0
INS_GET_ADMIN_ADDRESS = 0x02
INS_SIGN_PREAPPROVAL = 0x04
INS_GET_APP_CONFIG = 0x06
INS_GET_XMSS_ROOT = 0x44
INS_GET_LEAF_INDEX = 0x46
INS_GET_SIGNATURE_CHUNK = 0x50

P1_FIRST, P1_MORE, P1_LAST = 0x00, 0x80, 0x81
SW_OK = 0x9000
SW_DENIED = 0x6985  # the human pressed Reject, or the decision screen timed out
SW_BUSY = 0x6986  # another signing session is in flight
SW_EXHAUSTED = 0x6A84  # no one-time leaves left on this key
SW_WRONG_BINDING = 0x6A81  # this key slot belongs to another contract (fermionwallet.md, FWL-023)
SW_BAD_INS = 0x6E01  # the app's dispatcher does not know this instruction number

CHUNK = 200  # payload bytes per APDU; well inside the 255-byte limit


class DeviceError(ValueError):
    """A device-reported failure, in words a demo viewer can act on."""


def _sw_message(sw):
    return {
        SW_DENIED: "Rejected on the Ledger. Nothing was signed and no leaf was used.",
        SW_BUSY: "The Ledger is already showing a signing request — finish it on the device first.",
        SW_EXHAUSTED: "The key has no one-time signatures left. Rotate it on the device.",
        SW_WRONG_BINDING: (
            "This Ledger key already belongs to a different contract, and one key signs for "
            "exactly one. Use another key slot, or the contract it is bound to."
        ),
        SW_BAD_INS: (
            "The Ledger app does not know that command number — this host and the app on the "
            "device disagree about the APDU numbering. Load an app built from this "
            "ledger-app/ (the numbers are the Ethereum app's: 0x02, 0x04, 0x06, then 0x40 up)."
        ),
    }.get(sw, f"The Ledger refused the command (status 0x{sw:04x}).")


# ── transports ───────────────────────────────────────────────────────────────


class SpeculosTransport:
    """The app running in Ledger's emulator: APDUs over TCP, screens over REST.

    Speculos frames a response as a 4-byte big-endian length, that many bytes of
    data, then the 2-byte status word.
    """

    kind = "speculos"

    def __init__(self, apdu_url=None, api_url=None):
        apdu = apdu_url or os.environ.get("SPECULOS_APDU_URL", "tcp://127.0.0.1:9999")
        host, _, port = apdu.removeprefix("tcp://").partition(":")
        self.addr = (host, int(port or 9999))
        self.api = (api_url or os.environ.get("SPECULOS_API_URL", "http://127.0.0.1:5000")).rstrip("/")

    def exchange(self, apdu, timeout):
        with socket.create_connection(self.addr, timeout=10) as s:
            s.settimeout(timeout)
            s.sendall(struct.pack(">I", len(apdu)) + apdu)
            (length,) = struct.unpack(">I", _read_exactly(s, 4))
            data = _read_exactly(s, length)
            (sw,) = struct.unpack(">H", _read_exactly(s, 2))
        return data, sw

    # The demo shows the device's own screen: Speculos reports the text on it.
    def screen(self):
        events = self._api("/events?currentscreenonly=true")
        return [e["text"] for e in events.get("events", []) if e.get("text")]

    def press(self, button):
        # Nano buttons: left/right walk the flow, both confirms.
        self._api("/button/" + button, {"action": "press-and-release"})

    def _api(self, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            self.api + path, data=data, headers={"Content-Type": "application/json"},
            method="POST" if data is not None else "GET",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read()
        return json.loads(raw) if raw.strip() else {}


class HidTransport:
    """A physical Ledger over USB HID (Ledger's 64-byte framing, channel 0x0101)."""

    kind = "usb"
    VENDOR_ID = 0x2C97
    PACKET = 64
    CHANNEL = 0x0101
    TAG = 0x05

    def __init__(self):
        try:
            import hid  # noqa: PLC0415  (optional dependency: only USB needs it)
        except ImportError as e:
            raise DeviceError(
                "USB support needs the 'hid' package (pip install hidapi). "
                "Use LEDGER_TRANSPORT=speculos to run the same app in the emulator."
            ) from e
        devices = [d for d in hid.enumerate(self.VENDOR_ID, 0) if d.get("interface_number") == 0 or d.get("usage_page") == 0xFFA0]
        if not devices:
            raise DeviceError("No Ledger found on USB. Unlock it and open the FermionGuard app.")
        self.dev = hid.device()
        self.dev.open_path(devices[0]["path"])
        self.dev.set_nonblocking(0)

    def exchange(self, apdu, timeout):
        payload = struct.pack(">H", len(apdu)) + apdu
        for seq, offset in enumerate(range(0, len(payload), self.PACKET - 5)):
            frame = struct.pack(">HBH", self.CHANNEL, self.TAG, seq)[:5] if seq else struct.pack(">HBH", self.CHANNEL, self.TAG, 0)
            frame += payload[offset:offset + self.PACKET - 5]
            self.dev.write(list(frame.ljust(self.PACKET, b"\0")))
        # The device answers only once the human has acted, so read with the full timeout.
        data, expected = b"", None
        while expected is None or len(data) < expected:
            chunk = bytes(self.dev.read(self.PACKET, timeout_ms=int(timeout * 1000)))
            if not chunk:
                raise DeviceError("The Ledger stopped responding.")
            body = chunk[5:]
            if expected is None:
                expected = struct.unpack(">H", body[:2])[0]
                body = body[2:]
            data += body
        data = data[:expected]
        return data[:-2], struct.unpack(">H", data[-2:])[0]

    def screen(self):
        return None  # a physical device shows its own screens

    def press(self, button):
        raise DeviceError("Press the buttons on the Ledger itself.")


def _read_exactly(sock, n):
    buf = b""
    while len(buf) < n:
        part = sock.recv(n - len(buf))
        if not part:
            raise DeviceError("The Ledger connection closed mid-response.")
        buf += part
    return buf


def transport(kind=None):
    kind = (kind or os.environ.get("LEDGER_TRANSPORT", "speculos")).lower()
    if kind in ("speculos", "emulator"):
        return SpeculosTransport()
    if kind in ("usb", "hid", "ledger"):
        return HidTransport()
    raise DeviceError(f"unknown LEDGER_TRANSPORT {kind!r} (expected speculos or usb)")


# ── the FermionGuard command set ─────────────────────────────────────────────


def _addr(value):
    return bytes.fromhex(value[2:].rjust(40, "0"))


def _b32(value):
    return bytes.fromhex(value[2:].rjust(64, "0"))


PRE_APPROVAL_TYPE = (
    "PreApproval(address safe,uint8 approvalClass,address token,address recipient,uint256 amount,"
    "address target,uint256 value,bytes32 dataHash,uint64 validFrom,uint64 validTo,bytes32 nonce,"
    "bytes32 quantumKeyId,uint32 xmssLeafIndex,bytes32 policyHash,bytes32 txHash)"
)
DOMAIN_TYPE = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"


def _cast(*args):
    out = subprocess.run(["cast", *args], capture_output=True, text=True, timeout=30)
    if out.returncode != 0:
        raise RuntimeError(out.stderr.strip() or "cast failed")
    return out.stdout.strip()


def _keccak(hex_or_text):
    return _cast("keccak", hex_or_text)


def expected_digest(fields, leaf, chain_id, verifying_contract):
    """What the digest must be, computed here from the fields we sent.

    Deliberately an independent computation, not a copy of the device's: its whole
    value is that it was arrived at separately. Keccak and ABI encoding come from
    Foundry's `cast`, which the demo already requires.
    """
    domain = _keccak(_cast(
        "abi-encode", "f(bytes32,bytes32,bytes32,uint256,address)",
        _keccak(DOMAIN_TYPE), _keccak("FermionGuard"), _keccak("1"), str(chain_id), verifying_contract,
    ))
    struct = _keccak(_cast(
        "abi-encode",
        "f(bytes32,address,uint8,address,address,uint256,address,uint256,bytes32,uint64,uint64,"
        "bytes32,bytes32,uint32,bytes32,bytes32)",
        _keccak(PRE_APPROVAL_TYPE), fields["safe"], str(fields["approvalClass"]), fields["token"],
        fields["recipient"], str(fields["amount"]), fields["target"], str(fields["value"]),
        fields["dataHash"], str(fields["validFrom"]), str(fields["validTo"]), fields["nonce"],
        fields["quantumKeyId"], str(leaf), fields["policyHash"], fields["txHash"],
    ))
    return _keccak("0x1901" + domain[2:] + struct[2:])


def _check_blob_order(xmss_half, ecdsa_half, digest, admin, leaf):
    """Check the split before either half is relayed, and refuse it if it is wrong.

    Two checks on the piece taken off the end. The recovery id is nearly free and
    catches most of it; recovering that piece to the device's own Administrator
    address settles it, because it is the very check the Guard would fail.

    This exists because the swap is otherwise invisible. The two halves keep their
    own lengths when they change places, so a device that still puts the ECDSA half
    first hands back a blob of exactly the right size with exactly the right-sized
    pieces — `require(blob.length == ...)` passes, and the mismatch surfaces only
    on-chain, as `InvalidEcdsaSignature()`. That reads like a wrong `quantumAdmin`
    key and sends the reader into the key ceremony, long after the device has spent a
    one-time leaf. One check here turns that into a sentence naming the real cause.
    """
    wrong_order = (
        "The Ledger's signature blob is not in the order this host expects "
        "(XMSS first, ECDSA last — r | wotsSig | authPath | ecdsa). "
        f"Leaf {leaf} was already spent; the signatures are discarded rather than "
        "relayed, because on-chain this would revert as InvalidEcdsaSignature and read "
        "like a wrong quantumAdmin key. Check the app's GET_SIGNATURE_CHUNK layout "
        "against demo/ledger_device.py."
    )
    if len(xmss_half) % 32 != 0 or not xmss_half:
        raise DeviceError(
            f"{wrong_order} (the XMSS half is {len(xmss_half)} bytes, not a whole number "
            "of 32-byte words.)"
        )
    if ecdsa_half[64] not in (0, 1, 27, 28):
        raise DeviceError(f"{wrong_order} (recovery id 0x{ecdsa_half[64]:02x} is not a v byte.)")
    out = subprocess.run(
        ["cast", "wallet", "verify", "--address", admin, "--no-hash", digest,
         "0x" + ecdsa_half.hex()],
        capture_output=True, text=True, timeout=30,
    )
    if out.returncode != 0:
        raise DeviceError(
            f"{wrong_order} (its last 65 bytes do not recover to the device's own "
            f"quantumAdmin {admin}.)"
        )


def encode_payload(fields, chain_id, verifying_contract):
    """The signed fields, in the order the device parses and displays them."""
    return b"".join([
        int(chain_id).to_bytes(32, "big"),
        _addr(verifying_contract),
        _addr(fields["safe"]),
        bytes([int(fields["approvalClass"])]),
        _addr(fields["token"]),
        _addr(fields["recipient"]),
        int(fields["amount"]).to_bytes(32, "big"),
        _addr(fields["target"]),
        int(fields["value"]).to_bytes(32, "big"),
        _b32(fields["dataHash"]),
        int(fields["validFrom"]).to_bytes(8, "big"),
        int(fields["validTo"]).to_bytes(8, "big"),
        _b32(fields["nonce"]),
        _b32(fields["quantumKeyId"]),
        _b32(fields["policyHash"]),
        _b32(fields["txHash"]),
    ])


class Device:
    """The FermionGuard app on a Ledger, over whichever transport is configured."""

    def __init__(self, tr=None, slot=1):
        self.tr = tr or transport()
        self.slot = slot

    def _send(self, ins, p1=0, data=b"", timeout=30):
        apdu = bytes([CLA, ins, p1, self.slot, len(data)]) + data
        payload, sw = self.tr.exchange(apdu, timeout)
        if sw != SW_OK:
            raise DeviceError(_sw_message(sw))
        return payload

    def admin_address(self):
        return "0x" + self._send(INS_GET_ADMIN_ADDRESS).hex()

    def xmss_root(self):
        out = self._send(INS_GET_XMSS_ROOT)
        return {"root": "0x" + out[:32].hex(), "seed": "0x" + out[32:64].hex(),
                "treeHeight": out[64], "parameterSet": "0x" + out[65:97].hex()}

    def next_leaf(self):
        return int.from_bytes(self._send(INS_GET_LEAF_INDEX), "big")

    def sign_preapproval(self, fields, chain_id, verifying_contract, timeout=3600):
        """Stream the fields, wait for the human, then collect both signature halves.

        Returns the same shape the simulator returned, so the rest of the demo is
        unchanged: status, leaf, digest, ecdsaSignature, xmssSignature.
        """
        payload = encode_payload(fields, chain_id, verifying_contract)
        chunks = [payload[i:i + CHUNK] for i in range(0, len(payload), CHUNK)] or [b""]
        # Read the Administrator address before streaming anything, so the APDU
        # sequence after the signature is exactly the readout and nothing else.
        admin = self.admin_address()
        try:
            for i, chunk in enumerate(chunks):
                first, last = i == 0, i == len(chunks) - 1
                p1 = P1_LAST if last else (P1_FIRST if first else P1_MORE)
                # Only the last exchange waits for the human.
                out = self._send(INS_SIGN_PREAPPROVAL, p1, chunk, timeout if last else 30)
        except DeviceError as e:
            if "Rejected on the Ledger" in str(e):
                return {"status": "rejected"}
            raise
        leaf = int.from_bytes(out[:4], "big")
        digest = "0x" + out[4:36].hex()
        total = int.from_bytes(out[36:38], "big")

        # The device says what it hashed; check it against our own computation before
        # touching the signatures. A device that displayed one thing and signed another
        # would otherwise only be caught on-chain, after the leaf was already spent.
        want = expected_digest(fields, leaf, chain_id, verifying_contract)
        if want.lower() != digest.lower():
            raise DeviceError(
                f"The Ledger signed a different transaction than it was asked to: it reports "
                f"digest {digest}, the fields sent hash to {want}. Signatures discarded."
            )

        blob = b""
        while len(blob) < total:
            blob += self._send(INS_GET_SIGNATURE_CHUNK, p1=P1_FIRST if not blob else P1_MORE)
        blob = blob[:total]
        # XMSS first, ECDSA last (see the module docstring).
        xmss_half, ecdsa_half = blob[:-65], blob[-65:]
        _check_blob_order(xmss_half, ecdsa_half, digest, admin, leaf)
        return {
            "status": "approved",
            "leaf": leaf,
            "digest": digest,
            "ecdsaSignature": "0x" + ecdsa_half.hex(),
            "xmssSignature": "0x" + xmss_half.hex(),
        }


def _main():
    """`python3 ledger_device.py key` prints the device's public key as shell
    assignments, so the demo's setup can register the key the device actually holds
    instead of a key it invented:

        eval "$(python3 demo/ledger_device.py key)"   # DEVICE_XMSS_ROOT, ...
    """
    if len(sys.argv) != 2 or sys.argv[1] != "key":
        sys.exit("usage: ledger_device.py key")
    d = Device()
    k = d.xmss_root()
    print(f"DEVICE_XMSS_ROOT={k['root']}")
    print(f"DEVICE_XMSS_SEED={k['seed']}")
    print(f"DEVICE_XMSS_HEIGHT={k['treeHeight']}")
    print(f"DEVICE_PARAMETER_SET={k['parameterSet']}")
    print(f"DEVICE_ADMIN_ADDRESS={d.admin_address()}")


if __name__ == "__main__":
    _main()
