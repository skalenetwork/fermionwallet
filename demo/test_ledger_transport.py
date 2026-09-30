#!/usr/bin/env python3
"""Checks for the real-Ledger transport (demo/ledger_device.py).

The payload encoding is checked offline. The wire framing is checked against a
real Ledger app running in Speculos — any app will do, since the framing is the
device's, not ours: start one and point SPECULOS_APDU_URL / SPECULOS_API_URL at it.

    python3 demo/test_ledger_transport.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ledger_device as ld  # noqa: E402

FIELDS = {
    "safe": "0x8E3fd7B315486ce7Ea44A6E5129046148f807D49", "approvalClass": 0,
    "token": "0x5FbDB2315678afecb367f032d93F642f64180aa3",
    "recipient": "0x000000000000000000000000000000000000dEaD",
    "amount": str(250 * 10**18), "target": "0x" + "00" * 20, "value": "0",
    "dataHash": "0x" + "00" * 32, "validFrom": 1790000000, "validTo": 1790086400,
    "nonce": "0x" + "11" * 32, "quantumKeyId": "0x" + "22" * 32,
    "policyHash": "0x" + "33" * 32, "txHash": "0x" + "44" * 32,
}
GUARD = "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0"

failures = []


def check(name, condition, detail=""):
    print(f"{'ok  ' if condition else 'FAIL'}  {name}{'' if condition else ': ' + detail}")
    if not condition:
        failures.append(name)


# ── the payload the device parses and displays ───────────────────────────────

payload = ld.encode_payload(FIELDS, 31337, GUARD)
check("payload length is fixed", len(payload) == 32 + 20 + 20 + 1 + 20 + 20 + 32 + 20 + 32 + 32 + 8 + 8 + 32 + 32 + 32 + 32,
      f"got {len(payload)}")
check("chain id leads the payload", int.from_bytes(payload[:32], "big") == 31337)
check("verifying contract follows", payload[32:52].hex() == GUARD[2:].lower())
check("safe follows the contract", payload[52:72].hex() == FIELDS["safe"][2:].lower())
check("amount is a 32-byte big-endian word", int.from_bytes(payload[113:145], "big") == int(FIELDS["amount"]))
check("txHash ends the payload", payload[-32:].hex() == "44" * 32)
check("payload splits into APDU-sized chunks",
      all(len(payload[i:i + ld.CHUNK]) <= 255 for i in range(0, len(payload), ld.CHUNK)))

# ── status words map to something a demo viewer can act on ───────────────────

check("a rejection reads as a rejection", "Rejected on the Ledger" in ld._sw_message(ld.SW_DENIED))
check("a busy device says so", "already showing" in ld._sw_message(ld.SW_BUSY))
check("an exhausted key says so", "no one-time signatures left" in ld._sw_message(ld.SW_EXHAUSTED))

# ── the wire, against a real Ledger app in Speculos ───────────────────────────

if os.environ.get("SPECULOS_APDU_URL"):
    tr = ld.SpeculosTransport()
    # Every BOLOS app answers 0xB0 0x01 (get app name and version); the point here is
    # the framing: 4-byte length, data, then the status word.
    data, sw = tr.exchange(bytes.fromhex("b001000000"), timeout=10)
    check("APDU exchange with a real app returns 0x9000", sw == ld.SW_OK, f"sw=0x{sw:04x}")
    check("the app answers with a name", len(data) > 2, f"data={data.hex()}")
    lines = tr.screen()
    check("the device's own screen is readable", isinstance(lines, list) and len(lines) > 0, f"lines={lines}")
    before = lines
    tr.press("right")
    check("a button press changes the screen", tr.screen() != before, "screen did not move")
else:
    print("skip  wire checks (set SPECULOS_APDU_URL to run them against a real app)")

print(f"\n{'FAILED: ' + ', '.join(failures) if failures else 'all checks passed'}")
sys.exit(1 if failures else 0)
