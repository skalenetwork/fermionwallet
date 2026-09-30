#!/usr/bin/env python3
"""Simulated FermionGuard Ledger device for the demo.

The FermionGuard XMSS Ledger app is specified (ledger-xmss-app.md) but not yet
built, so Ledger's Speculos emulator has no binary to run. This process stands in
for the device and follows the spec's behaviour for the commands the demo uses:

- the device holds the key: an XMSS key slot with its own monotonic leaf counter,
  and the `quantumAdmin` ECDSA key (demo test keys — never use them for real funds);
- SIGN_PREAPPROVAL: the host sends the payload fields, never a hash; the device
  picks the leaf from its own counter, renders every field on its screen, and signs
  only after the user has paged through every screen and pressed Approve;
- counter-before-signature: the counter is committed to disk *before* the two
  signatures are computed and released together over the same EIP-712 digest;
- rejecting, or 60 s idle on the decision screen (ledger-xmss-app.md: "60 s idle on
  the decision screen" = reject), signs nothing and consumes no leaf; the field
  screens have no idle timeout, only a 10-minute cap on the whole session;
- malformed payload fields abort before the first screen; an empty validity window
  is refused ("Clock window invalid").

Host interface (the "transport"):  POST /apdu     {"ins": ..., ...}
Device screen and buttons:         GET  /screen,  POST /button {"button": ...}
Stdlib only; keccak, ABI encoding and ECDSA come from Foundry's `cast`.
"""
import json
import os
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CONTRACTS = os.environ.get("CONTRACTS_DIR", "/app/contracts")
PORT = int(os.environ.get("LEDGER_SIM_PORT", "9999"))
STATE_DIR = os.path.join(CONTRACTS, "demo-state")
DEVICE_STATE = os.path.join(STATE_DIR, "ledger-device.json")
DEPLOYMENT = os.path.join(STATE_DIR, "deployment.json")
# The demo's quantumAdmin key (same as LEDGER_PK in Demo.s.sol) — a public test key.
ADMIN_PK = os.environ.get(
    "LEDGER_ADMIN_PK", "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a"
)
HEIGHT = 4  # demo XMSS key: 16 one-time leaves
SLOT = 1
IDLE_TIMEOUT_S = 60  # this long idle on the decision screen = reject
SESSION_CAP_S = 600  # an abandoned session on a field screen rejects after this long

sys.path.insert(0, os.path.join(CONTRACTS, "lib", "xmss-solidity", "py"))
import sign_digest  # noqa: E402  (deterministic demo XMSS key, RFC 8391 reference code)
import xmss_ref  # noqa: E402

PRE_APPROVAL_TYPE = (
    "PreApproval(address safe,uint8 approvalClass,address token,address recipient,uint256 amount,"
    "address target,uint256 value,bytes32 dataHash,uint64 validFrom,uint64 validTo,bytes32 nonce,"
    "bytes32 quantumKeyId,uint32 xmssLeafIndex,bytes32 policyHash,bytes32 txHash)"
)
DOMAIN_TYPE = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
ZERO32 = "0x" + "00" * 32


def cast(*args):
    out = subprocess.run(["cast", *args], capture_output=True, text=True, timeout=30)
    if out.returncode != 0:
        raise RuntimeError(out.stderr.strip() or "cast failed")
    return out.stdout.strip()


def keccak(hex_or_text):
    return cast("keccak", hex_or_text)


# ── Device key material and persistent state ────────────────────────────────

_seed, _sk_seed, _sk_prf, _levels = sign_digest.keypair(HEIGHT)
ROOT = "0x" + _levels[HEIGHT][0].hex()
PUB_SEED = "0x" + _seed.hex()
ADMIN_ADDRESS = cast("wallet", "address", "--private-key", ADMIN_PK)


def load_state():
    try:
        with open(DEVICE_STATE) as f:
            return json.load(f)
    except FileNotFoundError:
        return {"slots": {str(SLOT): {"next": 0}}}


def commit_state(state):
    """Durable write: temp file, fsync, atomic rename (the SE NVRAM commit)."""
    os.makedirs(STATE_DIR, exist_ok=True)
    tmp = DEVICE_STATE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, DEVICE_STATE)


def known_tokens():
    """Stands in for Ledger's signed Crypto Asset List: token metadata the device
    trusts. Never taken from the host request."""
    try:
        with open(DEPLOYMENT) as f:
            d = json.load(f)
        return {d["token"].lower(): ("dUSD", "Demo USD", 18)}
    except (FileNotFoundError, KeyError):
        return {}


# ── Screen rendering (spec Flow 2) ──────────────────────────────────────────

def chunk_addr(addr):
    h = addr.lower().replace("0x", "")
    groups = [h[i:i + 4] for i in range(0, len(h), 4)]
    return ["0x" + " ".join(groups[0:5]), "   " + " ".join(groups[5:10])]


def utc(ts):
    return datetime.fromtimestamp(int(ts), timezone.utc).strftime("%d %b %Y %H:%M UTC")


def key_label():
    return f"Key {SLOT} · 0x{ROOT[2:6]}…{ROOT[-4:]}"


def fmt_amount(raw, decimals):
    """Exact decimals-adjusted amount: never rounds, so 0.001 is not shown as 0.00."""
    whole, frac = divmod(int(raw), 10 ** decimals)
    digits = f"{frac:0{decimals}d}".rstrip("0") if decimals else ""
    return f"{whole:,}.{digits.ljust(2, '0')}"


def render(p, leaf, chain_id):
    total = 1 << HEIGHT
    token = known_tokens().get(p["token"].lower())
    if token:
        token_lines = [f"{token[0]} ({token[1]})", *chunk_addr(p["token"])]
        amount_lines = [f"{fmt_amount(p['amount'], token[2])} {token[0]}", f"raw: {int(p['amount'])}"]
    else:
        token_lines = ["Unknown token", *chunk_addr(p["token"])]
        amount_lines = [f"raw: {int(p['amount'])}", "(unknown decimals)"]
    binding = (
        [f"Pinned to Safe tx 0x{p['txHash'][2:10]}…{p['txHash'][-8:]}"]
        if int(p["txHash"], 16)
        else ["NOT PINNED —", "any matching transfer"]
    )
    policy = p["policyHash"]
    return [
        {"title": "Sign approval", "lines": [key_label(), f"Leaf #{leaf} of {total}", "Transfer class"]},
        {"title": "Token", "lines": token_lines},
        {"title": "Amount", "lines": amount_lines},
        {"title": "Recipient", "lines": chunk_addr(p["recipient"])},
        {"title": "Validity", "lines": [f"From {utc(p['validFrom'])}", f"To   {utc(p['validTo'])}"]},
        {"title": "Context", "lines": ["Safe", *chunk_addr(p["safe"]), f"Chain {chain_id}", *binding]},
        {"title": "Policy", "lines": ["policyHash", f"0x{policy[2:10]}…{policy[-8:]}"]},
        {"title": "Approve transfer?", "lines": ["Approve signs with both keys", "Reject is always free"],
         "decision": True},
    ]


def eip712_digest(p, leaf, chain_id, verifying_contract):
    """The device hashes the fields it displays — it never signs a host-supplied hash."""
    domain = keccak(cast(
        "abi-encode", "f(bytes32,bytes32,bytes32,uint256,address)",
        keccak(DOMAIN_TYPE), keccak("FermionGuard"), keccak("1"), str(chain_id), verifying_contract,
    ))
    struct = keccak(cast(
        "abi-encode",
        "f(bytes32,address,uint8,address,address,uint256,address,uint256,bytes32,uint64,uint64,"
        "bytes32,bytes32,uint32,bytes32,bytes32)",
        keccak(PRE_APPROVAL_TYPE), p["safe"], str(p["approvalClass"]), p["token"], p["recipient"],
        str(p["amount"]), p["target"], str(p["value"]), p["dataHash"], str(p["validFrom"]),
        str(p["validTo"]), p["nonce"], p["quantumKeyId"], str(leaf), p["policyHash"], p["txHash"],
    ))
    return keccak("0x1901" + domain[2:] + struct[2:])


# ── Session (one signing flow at a time) ────────────────────────────────────

LOCK = threading.Lock()
session = None  # dict while a signing flow is on screen


ADDRESS_FIELDS = ("safe", "token", "recipient", "target")
BYTES32_FIELDS = ("dataHash", "nonce", "quantumKeyId", "policyHash", "txHash")
UINT_FIELDS = {"approvalClass": 8, "amount": 256, "value": 256, "validFrom": 64, "validTo": 64}


def _is_hex(v, nbytes):
    if not isinstance(v, str) or len(v) != 2 + 2 * nbytes or not v.startswith("0x"):
        return False
    try:
        int(v[2:], 16)
        return True
    except ValueError:
        return False


def _uint(v, bits):
    # JSON numbers or decimal strings; bools, floats and negatives are out of range.
    if isinstance(v, bool) or not isinstance(v, (int, str)):
        raise ValueError
    n = int(v, 10) if isinstance(v, str) else v
    if not 0 <= n < 1 << bits:
        raise ValueError
    return n


def check_payload(p, domain):
    """Unknown, missing or malformed fields abort before screen 1 (ledger-xmss-app.md)."""
    bad = ValueError("Payload rejected — field out of range")
    if not isinstance(p, dict) or not isinstance(domain, dict):
        raise bad
    if set(p) != set(ADDRESS_FIELDS) | set(BYTES32_FIELDS) | set(UINT_FIELDS):
        raise bad
    try:
        nums = {k: _uint(p[k], bits) for k, bits in UINT_FIELDS.items()}
        chain_id = _uint(domain.get("chainId"), 256)
    except (ValueError, TypeError):
        raise bad from None
    if not all(_is_hex(p[k], 20) for k in ADDRESS_FIELDS) or not all(_is_hex(p[k], 32) for k in BYTES32_FIELDS):
        raise bad
    if not _is_hex(domain.get("verifyingContract"), 20):
        raise bad
    if nums["approvalClass"] != 0:
        raise ValueError("Payload rejected — the demo device signs transfer approvals only")
    if nums["validTo"] <= nums["validFrom"]:
        raise ValueError("Clock window invalid")
    return chain_id, domain["verifyingContract"]


def sign_preapproval(req):
    global session
    if req.get("slot") != SLOT:
        raise ValueError("Key mismatch — no such key slot")
    prefix = req.get("rootPrefix")
    if not isinstance(prefix, str) or len(prefix) < 18 or not ROOT.lower().startswith(prefix.lower()):
        raise ValueError("Key mismatch — check host")
    p = req.get("payload")
    chain_id, verifying = check_payload(p, req.get("domain"))

    with LOCK:
        if session is not None:
            raise ValueError("Session already active")
        state = load_state()
        leaf = state["slots"][str(SLOT)]["next"]
        if leaf >= 1 << HEIGHT:
            raise ValueError("Key exhausted — rotate")
        digest = eip712_digest(p, leaf, chain_id, verifying)  # fails before any screen if malformed
        done = threading.Event()
        screens = render(p, leaf, chain_id)
        now = time.monotonic()
        session = {"screens": screens, "index": 0, "seen": 0, "decision": None, "done": done,
                   "leaf": leaf, "started": now,
                   "lastPress": now if len(screens) == 1 else None}  # set while on the decision screen

    # Idle timeout on the decision screen only (restarted by every press there), so a
    # careful reviewer paging through the fields is never cut off; an abandoned session
    # still rejects itself after SESSION_CAP_S.
    while True:
        with LOCK:
            deadline = session["started"] + SESSION_CAP_S
            if session["lastPress"] is not None:
                deadline = min(deadline, session["lastPress"] + IDLE_TIMEOUT_S)
            remaining = deadline - time.monotonic()
            if done.is_set() or remaining <= 0:
                # Decided or timed out, atomically with closing the session: a press
                # arriving after this sees no session and cannot approve.
                decision = session["decision"] if done.is_set() else "timeout"
                session = None
                break
        done.wait(min(remaining, 1.0))  # re-evaluate: a press may start/stop the idle clock
    if decision != "approve":
        return {"status": "rejected" if decision == "reject" else "timeout", "leafConsumed": False}

    # Counter-before-signature: commit leaf+1 durably, THEN compute and release both halves.
    with LOCK:
        state = load_state()
        if state["slots"][str(SLOT)]["next"] != leaf:
            raise RuntimeError("counter moved during the session")
        state["slots"][str(SLOT)]["next"] = leaf + 1
        commit_state(state)

    ecdsa = cast("wallet", "sign", "--no-hash", "--private-key", ADMIN_PK, digest)
    r, sig_ots, auth = xmss_ref.sign(bytes.fromhex(digest[2:]), leaf, _levels, _sk_seed, _sk_prf, _seed)
    # Exactly what the real app returns from GET_SIGNATURE_CHUNK: r | wotsSig | authPath.
    # No root/SEED prefix — they are on-chain already, and a simulator that sent more than
    # the device does would let a format mismatch hide until someone plugged in hardware.
    blob = r + b"".join(sig_ots) + b"".join(auth)
    return {"status": "approved", "leaf": leaf, "digest": digest,
            "ecdsaSignature": ecdsa, "xmssSignature": "0x" + blob.hex()}


def screen_view():
    with LOCK:
        if session is None:
            nxt = load_state()["slots"][str(SLOT)]["next"]
            return {"active": False, "key": key_label(), "admin": ADMIN_ADDRESS,
                    "nextLeaf": nxt, "totalLeaves": 1 << HEIGHT}
        s = session
        cur = s["screens"][s["index"]]
        return {"active": True, "index": s["index"], "total": len(s["screens"]), "screen": cur,
                "canApprove": bool(cur.get("decision")) and s["seen"] == len(s["screens"]) - 1}


def press(button):
    with LOCK:
        s = session
        if s is None:
            raise ValueError("No signing session on the device")
        last = len(s["screens"]) - 1
        if s["done"].is_set():
            raise ValueError("No signing session on the device")
        if button not in ("next", "prev", "reject", "approve"):
            raise ValueError("unknown button")
        if button == "next":
            s["index"] = min(s["index"] + 1, last)
            s["seen"] = max(s["seen"], s["index"])
        elif button == "prev":
            s["index"] = max(s["index"] - 1, 0)
        elif button == "reject":
            s["decision"] = "reject"
            s["done"].set()
        elif button == "approve":
            # No signature without traversing every field screen (spec acceptance criterion).
            if s["index"] != last or s["seen"] != last:
                raise ValueError("Review every screen before approving")
            s["decision"] = "approve"
            s["done"].set()
        else:
            raise ValueError("unknown button")
        # The 60 s idle clock runs only while the decision screen is shown; any press
        # that lands on it (re)starts the clock, leaving it stops the clock.
        s["lastPress"] = time.monotonic() if s["index"] == last else None


def apdu(req):
    if not isinstance(req, dict):
        raise ValueError("Payload rejected — field out of range")
    ins = req.get("ins")
    if ins == "GET_ADMIN_ADDRESS":
        return {"address": ADMIN_ADDRESS}
    if ins == "GET_XMSS_ROOT":
        return {"slot": SLOT, "root": ROOT, "seed": PUB_SEED, "treeHeight": HEIGHT}
    if ins == "GET_LEAF_INDEX":
        return {"slot": SLOT, "next": load_state()["slots"][str(SLOT)]["next"]}
    if ins == "SIGN_PREAPPROVAL":
        return sign_preapproval(req)
    raise ValueError(f"unsupported command {ins!r}")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _json(self, obj, status=200):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        return json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")

    def do_GET(self):
        if self.path == "/screen":
            self._json(screen_view())
        else:
            self.send_error(404)

    def do_POST(self):
        try:
            if self.path == "/apdu":
                self._json(apdu(self._body()))
            elif self.path == "/button":
                body = self._body()
                press(body.get("button") if isinstance(body, dict) else None)
                self._json({"ok": True})
            else:
                self.send_error(404)
        except ValueError as e:
            self._json({"error": str(e)}, 400)
        except Exception as e:  # noqa: BLE001
            self._json({"error": str(e)}, 500)


if __name__ == "__main__":
    print(f"[ledger-sim] FermionGuard Ledger (simulated) on 127.0.0.1:{PORT} — "
          f"{key_label()}, admin {ADMIN_ADDRESS}", flush=True)
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
