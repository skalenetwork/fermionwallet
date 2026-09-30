#!/usr/bin/env python3
"""Talk to a real FermionGuard Ledger — over USB to a physical device, or over TCP
to the same app running in Speculos (Ledger's emulator).

This replaces the HTTP call to the Python simulator (`ledger_sim.py`) with the real
APDU exchange described in ledger-xmss-app.md. Stdlib only, except that USB needs
`hid`; Speculos needs nothing.

Wire protocol (the concrete framing the spec's command table leaves open)
------------------------------------------------------------------------
CLA is 0xE0. Every command carries the key slot in P2. Commands:

  INS 0x02  GET_XMSS_ROOT        -> root(32) ‖ seed(32) ‖ treeHeight(1) ‖ parameterSet(32)
  INS 0x04  GET_LEAF_INDEX       -> nextLeaf(4, big-endian)
  INS 0x0E  GET_ADMIN_ADDRESS    -> address(20)
  INS 0x06  SIGN_PREAPPROVAL     streams the payload, P1 = 0x00 first chunk,
                                 0x80 more follow, 0x81 last chunk. The device
                                 shows every field, and the response to the LAST
                                 chunk arrives only once the human decides:
                                   0x9000 -> leaf(4) ‖ digest(32) ‖ totalLen(2)
                                   0x6985 -> rejected on the device
  INS 0x18  GET_SIGNATURE_CHUNK  P1 = chunk index -> up to 255 bytes of
                                 ecdsa(65) ‖ r(32) ‖ wotsSig(67*32) ‖ auth(h*32)

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
import urllib.request

CLA = 0xE0
INS_GET_XMSS_ROOT = 0x02
INS_GET_LEAF_INDEX = 0x04
INS_SIGN_PREAPPROVAL = 0x06
INS_GET_ADMIN_ADDRESS = 0x0E
INS_GET_SIGNATURE_CHUNK = 0x18

P1_FIRST, P1_MORE, P1_LAST = 0x00, 0x80, 0x81
SW_OK = 0x9000
SW_DENIED = 0x6985  # the human pressed Reject, or the decision screen timed out
SW_BUSY = 0x6986  # another signing session is in flight
SW_EXHAUSTED = 0x6A84  # no one-time leaves left on this key

CHUNK = 200  # payload bytes per APDU; well inside the 255-byte limit


class DeviceError(ValueError):
    """A device-reported failure, in words a demo viewer can act on."""


def _sw_message(sw):
    return {
        SW_DENIED: "Rejected on the Ledger. Nothing was signed and no leaf was used.",
        SW_BUSY: "The Ledger is already showing a signing request — finish it on the device first.",
        SW_EXHAUSTED: "The key has no one-time signatures left. Rotate it on the device.",
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

        blob = b""
        while len(blob) < total:
            blob += self._send(INS_GET_SIGNATURE_CHUNK, p1=len(blob) // 255)
        blob = blob[:total]
        return {
            "status": "approved",
            "leaf": leaf,
            "digest": digest,
            "ecdsaSignature": "0x" + blob[:65].hex(),
            "xmssSignature": "0x" + blob[65:].hex(),
        }
