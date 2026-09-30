#!/usr/bin/env python3
"""End-to-end checks for the FermionGuard Ledger app, against the app itself.

Runs the app in Speculos, drives it over the demo's own transport
(`demo/ledger_device.py`), and checks the three things that decide whether an
approval the device signs is one the Guard will accept:

1. the digest the device reports is the EIP-712 digest of the fields the host sent
   (so the device is hashing what it displayed, and agrees with the contracts);
2. the XMSS half verifies under the root and SEED the device published, checked by
   the RFC 8391 reference implementation the Solidity verifier is proven against;
3. the ECDSA half recovers to the address the device reports as `quantumAdmin`,
   with a low `s` — OpenZeppelin's `ECDSA` rejects a high one.

Plus the parts that are easy to get wrong in firmware: the leaf counter advances by
exactly one and is committed before the signature is released, a rejection consumes
nothing, and an exhausted key refuses to sign.

    ledger-app/test/test_app.py            # builds nothing; expects the ELF built
    SPECULOS_APDU_URL=... test_app.py      # against an already-running Speculos

`cast` (Foundry) provides keccak and ABI encoding; the XMSS reference comes from
contracts/lib/xmss-solidity.
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
# Ports and name are this suite's own: test_wallet.py uses its own, so both
# suites can run at the same time.
PREFIX = "fg-app-test"
API_PORT, APDU_PORT = 15001, 19998

sys.path.insert(0, os.path.join(REPO, "demo"))
sys.path.insert(0, os.path.join(REPO, "contracts", "lib", "xmss-solidity", "py"))

PRE_APPROVAL_TYPE = (
    "PreApproval(address safe,uint8 approvalClass,address token,address recipient,uint256 amount,"
    "address target,uint256 value,bytes32 dataHash,uint64 validFrom,uint64 validTo,bytes32 nonce,"
    "bytes32 quantumKeyId,uint32 xmssLeafIndex,bytes32 policyHash,bytes32 txHash)"
)
DOMAIN_TYPE = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
CHAIN_ID = 31337
GUARD = "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0"
FIELDS = {
    "safe": "0x8E3fd7B315486ce7Ea44A6E5129046148f807D49", "approvalClass": 0,
    "token": "0x5FbDB2315678afecb367f032d93F642f64180aa3",
    "recipient": "0x000000000000000000000000000000000000dEaD",
    "amount": str(250 * 10**18), "target": "0x" + "00" * 20, "value": "0",
    "dataHash": "0x" + "00" * 32, "validFrom": 1790000000, "validTo": 1790086400,
    "nonce": "0x" + "11" * 32, "quantumKeyId": "0x" + "22" * 32,
    "policyHash": "0x" + "33" * 32, "txHash": "0x" + "44" * 32,
}

failures = []
KEEP = bool(os.environ.get('KEEP_SPECULOS'))


def check(name, ok, detail=""):
    print(f"{'ok  ' if ok else 'FAIL'}  {name}{'' if ok else ': ' + detail}")
    if not ok:
        failures.append(name)


def cast(*args):
    out = subprocess.run(["cast", *args], capture_output=True, text=True, timeout=60)
    if out.returncode != 0:
        raise RuntimeError(" ".join(args) + ": " + (out.stderr.strip() or "cast failed"))
    return out.stdout.strip()


def eip712_digest(fields, leaf):
    """The digest the contracts compute, built with cast — an independent path from
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


# ── the emulator ─────────────────────────────────────────────────────────────


class Speculos:
    """Run the built app, unless the caller pointed us at a running one."""

    def __init__(self):
        self.container = None
        if os.environ.get("SPECULOS_APDU_URL"):
            return
        if not os.path.exists(ELF):
            sys.exit(f"no app at {ELF} — run ledger-app/build.sh first")
        # A unique name so this suite can run beside another one, but stale
        # containers from interrupted runs are cleared first: they would hold the
        # ports and the next run would die on a bare "exit status 125".
        self.container = f"{PREFIX}-{os.getpid()}"
        stale = subprocess.run(["docker", "ps", "-aq", "--filter", f"name={PREFIX}-"],
                               capture_output=True, text=True).stdout.split()
        if stale:
            subprocess.run(["docker", "rm", "-f", *stale], capture_output=True)
        subprocess.run(
            ["docker", "run", "-d", "--name", self.container,
             "-v", os.path.dirname(ELF) + ":/app", "-p", f"{API_PORT}:5000", "-p", f"{APDU_PORT}:9999",
             "ghcr.io/ledgerhq/speculos:latest", "--model", "nanosp", "--display", "headless",
             "--api-port", "5000", "--apdu-port", "9999", "--seed", SEED, "/app/app.elf"],
            check=True, capture_output=True)
        os.environ["SPECULOS_APDU_URL"] = f"tcp://127.0.0.1:{APDU_PORT}"
        os.environ["SPECULOS_API_URL"] = f"http://127.0.0.1:{API_PORT}"

    def stop(self, keep_logs=False):
        if self.container and not keep_logs:
            subprocess.run(["docker", "rm", "-f", self.container], capture_output=True)

    def wait(self, device):
        for _ in range(60):
            try:
                device.next_leaf()
                return
            except Exception:
                time.sleep(1)
        sys.exit("the app never answered in Speculos")


HOME_PAGES = ("is ready", "Leaves used", "Version", "Quit")


def decide(transport, decision, seen=None):
    """Walk the review to the end and press Approve or Reject, like a human would.

    Runs in a thread because the device answers the last chunk only once the human
    has decided — which is the behaviour being checked. It waits for the review to
    appear and stops the moment it is gone: pressing both buttons on the home
    screen's Quit page would close the app, which looks exactly like a firmware
    crash in the next exchange.
    """
    def home(text):
        return not text or any(p in text for p in HOME_PAGES)

    def run():
        deadline = time.time() + 120
        while time.time() < deadline and home(" ".join(transport.screen())):
            time.sleep(0.1)
        while time.time() < deadline:
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


def main():
    import ledger_device as ld
    import xmss_ref

    emu = Speculos()
    try:
        transport = ld.SpeculosTransport()
        device = ld.Device(transport)
        emu.wait(device)

        admin = device.admin_address()
        key = device.xmss_root()
        check("the device publishes a non-zero root and SEED",
              int(key["root"], 16) != 0 and int(key["seed"], 16) != 0, str(key))
        check("the tree height is the one the registry will record", key["treeHeight"] == 4,
              str(key["treeHeight"]))
        check("parameterSet is keccak256(\"XMSS-SHA2_4_256-DEMO\")",
              key["parameterSet"] == cast("keccak", "XMSS-SHA2_4_256-DEMO"), key["parameterSet"])

        leaf_before = device.next_leaf()
        screens = []
        presser = decide(transport, "approve", screens)
        res = device.sign_preapproval(FIELDS, CHAIN_ID, GUARD, timeout=120)
        presser.join(timeout=10)
        check("the device approved and returned both halves", res.get("status") == "approved",
              str(res))
        if res.get("status") != "approved":
            return
        check("the leaf the device signed with is its own counter value",
              res["leaf"] == leaf_before, f"{res['leaf']} vs {leaf_before}")
        check("the counter advanced by exactly one", device.next_leaf() == leaf_before + 1,
              str(device.next_leaf()))

        # 1. the digest: the device's own keccak vs the contracts' encoding.
        want = eip712_digest(FIELDS, res["leaf"])
        check("the device's digest is the EIP-712 digest of the fields sent",
              res["digest"] == want, f"device {res['digest']} host {want}")

        # 2. the XMSS half, checked by the reference the Solidity verifier is proven against.
        blob = bytes.fromhex(res["xmssSignature"][2:])
        check("the signature blob has the layout Demo.s.sol parses",
              len(blob) == 32 * (1 + 67 + 4), f"{len(blob)} bytes")
        root = bytes.fromhex(key["root"][2:])
        seed = bytes.fromhex(key["seed"][2:])
        r = blob[0:32]
        wots = [blob[32 + 32 * i:64 + 32 * i] for i in range(67)]
        auth = [blob[32 + 32 * 67 + 32 * i:64 + 32 * 67 + 32 * i] for i in range(4)]
        digest = bytes.fromhex(res["digest"][2:])
        check("the XMSS half verifies under the published key (RFC 8391 reference)",
              xmss_ref.verify(digest, res["leaf"], r, wots, auth, root, seed))
        check("and does not verify against a different digest",
              not xmss_ref.verify(bytes(32), res["leaf"], r, wots, auth, root, seed))

        # 3. the ECDSA half.
        sig = res["ecdsaSignature"]
        s = int(sig[2 + 64:2 + 128], 16)
        check("s is in the lower half of the curve order",
              s <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0, hex(s))
        check("v is 27 or 28", int(sig[2 + 128:], 16) in (27, 28), sig[2 + 128:])
        verified = subprocess.run(
            ["cast", "wallet", "verify", "--address", admin, "--no-hash", res["digest"], sig],
            capture_output=True, text=True)
        check("the ECDSA half recovers to the device's quantumAdmin address",
              verified.returncode == 0, verified.stderr.strip() or verified.stdout.strip())

        # The screens the human actually saw.
        seen = " | ".join(" ".join(s) for s in screens)
        for field in ("Leaf", "Token", "Amount", "Recipient", "Valid from", "Valid to", "Safe",
                      "Network", "Policy", "Binding"):
            check(f"the review shows {field}", field in seen, seen[:400])
        check("the recipient is shown in full, not truncated",
              "dEaD" in seen or "dead" in seen.lower(), seen[:400])

        # A rejection must cost nothing.
        leaf = device.next_leaf()
        presser = decide(transport, "reject")
        res = device.sign_preapproval(FIELDS, CHAIN_ID, GUARD, timeout=120)
        presser.join(timeout=10)
        check("a rejection reports itself as one", res.get("status") == "rejected", str(res))
        check("a rejection consumes no leaf", device.next_leaf() == leaf, str(device.next_leaf()))

        # Exhaustion: spend the rest of the tiny key, then it must refuse.
        #
        # Every signature on the way is checked, both halves, not just the first
        # one: `xmss::sign` walks a different authentication path at every leaf, so
        # an off-by-one in the path or in an ADRS word would produce a signature the
        # Guard refuses at some indices and not others — and the leaf is spent either
        # way. The ECDSA half matters per signature too, because the low-`s`
        # normalisation only runs for the roughly half of nonces above the halfway
        # point.
        bad_ecdsa, bad_xmss = [], []
        for _ in range(device.next_leaf(), 16):
            presser = decide(transport, "approve")
            got = device.sign_preapproval(FIELDS, CHAIN_ID, GUARD, timeout=120)
            presser.join(timeout=10)
            if got.get("status") != "approved":
                check("every remaining leaf signs", False, str(got))
                break
            ok = subprocess.run(
                ["cast", "wallet", "verify", "--address", admin, "--no-hash", got["digest"],
                 got["ecdsaSignature"]], capture_output=True)
            if ok.returncode != 0:
                bad_ecdsa.append(got["leaf"])
            blob = bytes.fromhex(got["xmssSignature"][2:])
            sig_r = blob[0:32]
            sig_wots = [blob[32 + 32 * i:64 + 32 * i] for i in range(67)]
            sig_auth = [blob[32 + 32 * 67 + 32 * i:64 + 32 * 67 + 32 * i] for i in range(4)]
            if not xmss_ref.verify(bytes.fromhex(got["digest"][2:]), got["leaf"], sig_r,
                                   sig_wots, sig_auth, root, seed):
                bad_xmss.append(got["leaf"])
        check("every signature's ECDSA half recovers to quantumAdmin", not bad_ecdsa,
              f"failed at leaves {bad_ecdsa} — suspect the high-s normalisation")
        check("every leaf's XMSS half verifies, not just the first",
              not bad_xmss, f"failed at leaves {bad_xmss} — suspect the auth path or ADRS")
        check("the counter reaches the end of the tree", device.next_leaf() == 16,
              str(device.next_leaf()))
        try:
            device.sign_preapproval(FIELDS, CHAIN_ID, GUARD, timeout=30)
            check("an exhausted key refuses to sign", False, "it signed anyway")
        except ld.DeviceError as e:
            check("an exhausted key refuses to sign", "no one-time signatures left" in str(e),
                  str(e))
    finally:
        emu.stop(keep_logs=bool(failures) or KEEP)

    print(f"\n{'FAILED: ' + ', '.join(failures) if failures else 'all checks passed'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
