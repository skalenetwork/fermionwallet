#!/usr/bin/env python3
"""The PAYLOAD and ADMIN approval classes: the half of the zero-field rule that
`test_app.py` cannot reach.

`main.rs::unused_fields_are_zero` has two arms. For a `TRANSFER` (class 0) it
requires `target`, `value` and `dataHash` to be zero, because
`PreApprovalEngine::_commitment` and `_fieldsMatch` hash
`(safe, class, token, recipient, amount)` and never look at the other three.
For `PAYLOAD` (class 1) and `ADMIN` (class 2) the split is the other way round:
the engine hashes `(safe, class, target, value, dataHash)`, the review draws that
triple, and `token`, `recipient` and `amount` are the three the device must
refuse unless they are zero.

`test_app.py` sends `approvalClass: 0` and nothing else does — no suite in the
tree, and no host either, since `demo/ledger_sim.py` refuses a class other than
`TRANSFER` outright. So the class-1/2 arm of the rule, the `payload` field set of
the review, and the two other review headings had no check of any kind: deleting

    f.token() == &[0u8; 20] && f.recipient() == &[0u8; 20] && f.amount() == &[0u8; 32]

and returning `true` in its place leaves `test_app.py` at 45/45, `test_wallet.py`
at 23/23 and `test_fmt_utc.py` at 35/35. This file is what turns that red.

It checks both directions, because a zero-field rule can fail either way:

* a class-1 or class-2 approval carrying a non-zero `token`, `recipient` or
  `amount` is refused with `0x6A80` **before any screen** and costs no leaf —
  those are signed fields the review does not draw and the Guard does not read;
* a class-1 or class-2 approval with that triple zeroed is *signed*, draws
  `Target`, `Value` and `Data hash` rather than `Token`, `Amount` and
  `Recipient`, and reports the digest the contracts compute. The rule must refuse
  nothing a legitimate host sends.

    ledger-app/test/test_payload_class.py       # expects the ELF built
    PAYLOAD_TEST_PORTS=15401,19801 ...          # if those two are taken
    SPECULOS_APDU_URL=... test_payload_class.py # against a running Speculos

`cast` (Foundry) provides the independent digest.
"""
import os
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
ELF = os.path.join(REPO, "ledger-app", "build", "nanos2", "bin", "app.elf")
SEED = "test test test test test test test test test test test junk"
# This suite's own ports and container name, so it can run beside the others.
API_PORT, APDU_PORT = (
    int(p) for p in os.environ.get("PAYLOAD_TEST_PORTS", "15005,19994").split(",")
)
# The APDU port is in the name, so the stale sweep below can only reach a container
# holding the ports *this* run wants.
PREFIX = f"fg-payload-test-{APDU_PORT}"
KEY_SLOT = 1

sys.path.insert(0, os.path.join(REPO, "demo"))

PRE_APPROVAL_TYPE = (
    "PreApproval(address safe,uint8 approvalClass,address token,address recipient,uint256 amount,"
    "address target,uint256 value,bytes32 dataHash,uint64 validFrom,uint64 validTo,bytes32 nonce,"
    "bytes32 quantumKeyId,uint32 xmssLeafIndex,bytes32 policyHash,bytes32 txHash)"
)
DOMAIN_TYPE = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
CHAIN_ID = 31337
GUARD = "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0"
ZERO_ADDR = "0x" + "00" * 20
ZERO32 = "0x" + "00" * 32

# A well-formed PAYLOAD approval: the transfer triple zeroed, the payload triple
# carrying the call the Guard will match against.
PAYLOAD_FIELDS = {
    "safe": "0x8E3fd7B315486ce7Ea44A6E5129046148f807D49", "approvalClass": 1,
    "token": ZERO_ADDR, "recipient": ZERO_ADDR, "amount": "0",
    "target": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
    "value": str(3 * 10**18), "dataHash": "0x" + "ab" * 32,
    "validFrom": 1790000000, "validTo": 1790086400,
    "nonce": "0x" + "55" * 32, "quantumKeyId": "0x" + "22" * 32,
    "policyHash": "0x" + "33" * 32, "txHash": "0x" + "66" * 32,
}

failures = []


def check(name, ok, detail=""):
    print(f"{'ok  ' if ok else 'FAIL'}  {name}{'' if ok else ': ' + detail}")
    if not ok:
        failures.append(name)


def cast(*args):
    exe = os.path.expanduser("~/.foundry/bin/cast")
    exe = exe if os.path.exists(exe) else "cast"
    out = subprocess.run([exe, *args], capture_output=True, text=True, timeout=60)
    if out.returncode != 0:
        raise RuntimeError(" ".join(args) + ": " + (out.stderr.strip() or "cast failed"))
    return out.stdout.strip()


def eip712_digest(fields, leaf):
    """The digest the contracts compute, built with cast: an independent path from
    the device's own keccak."""
    domain = cast("keccak", cast(
        "abi-encode", "f(bytes32,bytes32,bytes32,uint256,address)",
        cast("keccak", DOMAIN_TYPE), cast("keccak", "FermionGuard"), cast("keccak", "1"),
        str(CHAIN_ID), GUARD))
    struct_hash = cast("keccak", cast(
        "abi-encode",
        "f(bytes32,address,uint8,address,address,uint256,address,uint256,bytes32,uint64,uint64,"
        "bytes32,bytes32,uint32,bytes32,bytes32)",
        cast("keccak", PRE_APPROVAL_TYPE), fields["safe"], str(fields["approvalClass"]),
        fields["token"], fields["recipient"], fields["amount"], fields["target"], fields["value"],
        fields["dataHash"], str(fields["validFrom"]), str(fields["validTo"]), fields["nonce"],
        fields["quantumKeyId"], str(leaf), fields["policyHash"], fields["txHash"]))
    return cast("keccak", "0x1901" + domain[2:] + struct_hash[2:])


class Speculos:
    """Run the built app, unless the caller pointed us at a running one."""

    def __init__(self):
        self.container = None
        if os.environ.get("SPECULOS_APDU_URL"):
            return
        if not os.path.exists(ELF):
            sys.exit(f"no app at {ELF} — run ledger-app/build.sh first")
        self.container = f"{PREFIX}-{os.getpid()}"
        stale = subprocess.run(["docker", "ps", "-aq", "--filter", f"name={PREFIX}-"],
                               capture_output=True, text=True).stdout.split()
        if stale:
            subprocess.run(["docker", "rm", "-f", *stale], capture_output=True)
        subprocess.run(
            ["docker", "run", "-d", "--name", self.container,
             "-v", os.path.dirname(ELF) + ":/app",
             "-p", f"{API_PORT}:5000", "-p", f"{APDU_PORT}:9999",
             "ghcr.io/ledgerhq/speculos:latest", "--model", "nanosp", "--display", "headless",
             "--api-port", "5000", "--apdu-port", "9999", "--seed", SEED, "/app/app.elf"],
            check=True, capture_output=True)
        os.environ["SPECULOS_APDU_URL"] = f"tcp://127.0.0.1:{APDU_PORT}"
        os.environ["SPECULOS_API_URL"] = f"http://127.0.0.1:{API_PORT}"

    def stop(self):
        if self.container:
            subprocess.run(["docker", "rm", "-f", self.container], capture_output=True)

    def wait(self, device):
        for _ in range(60):
            try:
                device.next_leaf()
                return
            except Exception:
                time.sleep(1)
        sys.exit("the app never answered in Speculos")


HOME_PAGES = ("is ready", "Leaves used", "Version", "Quit", "Key is for")


def send(transport, ins, p1=0, data=b"", timeout=30):
    """One APDU, status word included — the checks below assert on the number."""
    import ledger_device as ld
    return transport.exchange(
        bytes([ld.CLA, ins, p1, KEY_SLOT, len(data)]) + data, timeout)


def stream_raw(transport, payload, timeout=30):
    import ledger_device as ld
    pieces = [payload[i:i + ld.CHUNK] for i in range(0, len(payload), ld.CHUNK)]
    out, sw = b"", ld.SW_OK
    for i, piece in enumerate(pieces):
        last = i == len(pieces) - 1
        p1 = ld.P1_LAST if last else (ld.P1_FIRST if i == 0 else ld.P1_MORE)
        out, sw = send(transport, ld.INS_SIGN_PREAPPROVAL, p1, piece, timeout if last else 30)
        if sw != ld.SW_OK:
            break
    return out, sw


def decide(transport, decision, seen=None, stop=None):
    """Walk the review and press Approve or Reject, like a human would.

    `stop` is for the checks that expect *no* review: a payload refused before any
    screen draws nothing to find, and without a way to call the walker off it waits
    out its whole deadline and outlives the emulator (the hang `4343abb` fixed in
    `test_app.py`).
    """
    stop = stop or threading.Event()

    def home(text):
        return not text or any(p in text for p in HOME_PAGES)

    def run():
        deadline = time.time() + 120
        while time.time() < deadline and not stop.is_set() \
                and home(" ".join(transport.screen())):
            time.sleep(0.1)
        while time.time() < deadline and not stop.is_set():
            lines = transport.screen()
            text = " ".join(lines)
            if home(text):
                return
            if seen is not None:
                seen.append(lines)
            if decision == "approve" and "Approve" in text:
                transport.press("both")
                return
            if decision == "reject" and "Reject" in text:
                transport.press("both")
                return
            transport.press("right")
            time.sleep(0.05)

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t


def refused_unseen(transport, device, fields, name):
    """Stream `fields`, expect `0x6A80` with no screen drawn and no leaf spent."""
    import ledger_device as ld
    leaf = device.next_leaf()
    stop = threading.Event()
    # A walker stands by to reject, so a build that draws a review here fails this
    # check instead of hanging on it.
    presser = decide(transport, "reject", stop=stop)
    _, sw = stream_raw(transport, ld.encode_payload(fields, CHAIN_ID, GUARD), timeout=60)
    stop.set()
    presser.join(timeout=10)
    check(name, sw == ld.SW_BAD_FIELDS, f"0x{sw:04x}")
    check(f"and {name.split(' is ')[0]} costs no leaf", device.next_leaf() == leaf,
          str(device.next_leaf()))


def main():
    import ledger_device as ld

    emu = Speculos()
    try:
        transport = ld.SpeculosTransport()
        device = ld.Device(transport)
        emu.wait(device)

        # ── 1. the three fields a PAYLOAD/ADMIN approval signs and the Guard never
        # reads. `_commitment` hashes (safe, class, target, value, dataHash) for
        # these two classes and never looks at token, recipient or amount.
        for klass, label in ((1, "a class-1"), (2, "a class-2")):
            for field, value in (
                ("token", "0x5FbDB2315678afecb367f032d93F642f64180aa3"),
                ("recipient", "0x000000000000000000000000000000000000dEaD"),
                ("amount", str(250 * 10**18)),
            ):
                refused_unseen(
                    transport, device,
                    dict(PAYLOAD_FIELDS, approvalClass=klass, **{field: value}),
                    f"{label} approval with a non-zero {field} is refused before any screen")

        # ── 2. and the rule refuses nothing legitimate: the same class, triple
        # zeroed, is signed — with the payload triple on the screen, not the
        # transfer triple.
        leaf_before = device.next_leaf()
        screens = []
        presser = decide(transport, "approve", screens)
        res = device.sign_preapproval(PAYLOAD_FIELDS, CHAIN_ID, GUARD, timeout=120)
        presser.join(timeout=10)
        check("a well-formed class-1 approval is signed, not refused",
              res.get("status") == "approved", str(res))
        if res.get("status") != "approved":
            return 1
        check("it consumed exactly one leaf", device.next_leaf() == leaf_before + 1,
              str(device.next_leaf()))
        want = eip712_digest(PAYLOAD_FIELDS, res["leaf"])
        check("over the fields that were sent — the digest agrees with cast",
              res["digest"] == want, f"device {res['digest']} host {want}")

        seen = " | ".join(" ".join(s) for s in screens)
        flat = seen.lower().replace(" ", "")
        for field in ("Target", "Value", "Data hash", "Valid from", "Valid to", "Safe",
                      "Guard", "Network", "Policy", "Binding"):
            check(f"the class-1 review shows {field}", field in seen, seen[:400])
        # The transfer triple is not this class's, so it must not be drawn — a page
        # for a field the Guard ignores is a promise the Guard does not keep.
        for field in ("Token", "Amount", "Recipient"):
            check(f"and draws no {field} page — not this class's field",
                  field not in seen, seen[:400])
        # Speculos reports a scrolling BAGL line from wherever it had got to, so the
        # first frame of "Sign payload" can arrive as "ign payload". Match a fragment:
        # what matters is that this is the payload flow, not the transfer flow.
        check("the review is headed as a payload, not a Safe transfer",
              "payload" in flat and "signapproval" not in flat, seen[:200])
        check("the Target page carries the address the digest covers",
              PAYLOAD_FIELDS["target"][2:10].lower() in flat, seen[:400])

        # ── 3. an ADMIN approval says so, in those words: class 2 is the one that
        # changes the Safe's governance, and the heading is the only place the class
        # appears on the screen.
        admin_fields = dict(PAYLOAD_FIELDS, approvalClass=2, nonce="0x" + "77" * 32)
        screens = []
        presser = decide(transport, "approve", screens)
        res = device.sign_preapproval(admin_fields, CHAIN_ID, GUARD, timeout=120)
        presser.join(timeout=10)
        check("a well-formed class-2 approval is signed too",
              res.get("status") == "approved", str(res))
        if res.get("status") == "approved":
            check("and its digest agrees with cast",
                  res["digest"] == eip712_digest(admin_fields, res["leaf"]), res["digest"])
            seen = " | ".join(" ".join(s) for s in screens)
            # Speculos' screen text reports the BAGL capital I as a lowercase l, so
            # "ADMIN ACTION" arrives as "ADMlN ACTlON". Normalise that one glyph
            # rather than match a fragment: this heading is the only place the class
            # appears on the screen, so it is worth checking whole.
            flat = seen.replace("l", "I").replace(" ", "")
            check("an ADMIN approval is headed as one, not as a payload",
                  "ADMINACTION" in flat and "payIoad" not in flat, seen[:200])

        # ── 4. a class the device has no review for is refused outright, before any
        # screen: `approval_class() > 2` has no field set and no heading.
        refused_unseen(transport, device, dict(PAYLOAD_FIELDS, approvalClass=3),
                       "a class the review cannot draw is refused before any screen")
    finally:
        emu.stop()

    print(f"\n{'FAILED: ' + ', '.join(failures) if failures else 'all checks passed'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
