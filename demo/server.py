#!/usr/bin/env python3
"""FermionWallet demo server.

Serves the demo dashboard (static files from ./ui) and a small JSON API that
drives the on-chain demo flows by shelling out to `forge script` against the
anvil testnet running in the same container. Read-only chain state is fetched
directly over JSON-RPC. Stdlib only.
"""
import json
import os
import re
import subprocess
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
UI_DIR = os.path.join(HERE, "ui")
CONTRACTS = os.environ.get("CONTRACTS_DIR", "/app/contracts")
RPC = os.environ.get("RPC_URL", "http://127.0.0.1:8545")
FORGE = os.environ.get("FORGE_BIN", "forge")
PORT = int(os.environ.get("PORT", "8080"))
STATE_FILE = os.path.join(CONTRACTS, "demo-state", "deployment.json")

TREE_LEAVES = 16  # demo key h = 4

SEL_BALANCE_OF = "0x70a08231"
SEL_NONCE = "0xaffed0e0"
SEL_THRESHOLD = "0xe75235b8"
SEL_IS_LEAF_USED = "0xc7ac11b8"
SEL_SAFE_TO_KEY = "0xe056ccae"
GUARD_SLOT = "0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8"

ERR_NO_MATCHING = "0x95828945"  # NoMatchingPreApproval(address,bytes32,bytes32)


def deployment():
    with open(STATE_FILE) as f:
        return json.load(f)


def rpc(method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(RPC, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        out = json.load(resp)
    if "error" in out:
        raise RuntimeError(out["error"])
    return out["result"]


def eth_call(to, data):
    return rpc("eth_call", [{"to": to, "data": data}, "latest"])


def pad_addr(addr):
    return addr.lower().replace("0x", "").rjust(64, "0")


def as_int(hexstr):
    return int(hexstr, 16) if hexstr and hexstr != "0x" else 0


def chain_state():
    d = deployment()
    safe, guard, token, vendor = d["safe"], d["guard"], d["token"], d["vendor"]
    key_id = d["keyId"].replace("0x", "")

    leaves = []
    for i in range(TREE_LEAVES):
        data = SEL_IS_LEAF_USED + key_id + format(i, "064x")
        leaves.append(as_int(eth_call(guard, data)) == 1)

    guard_word = rpc("eth_getStorageAt", [safe, GUARD_SLOT, "latest"])
    active_guard = "0x" + guard_word[-40:]

    return {
        "chainId": as_int(rpc("eth_chainId", [])),
        "blockNumber": as_int(rpc("eth_blockNumber", [])),
        "safe": safe,
        "guard": guard,
        "guardActive": active_guard.lower() == guard.lower(),
        "token": token,
        "vendor": vendor,
        "quantumAdmin": d["quantumAdmin"],
        "keyId": d["keyId"],
        "xmssRoot": d["xmssRoot"],
        "safeNonce": as_int(eth_call(safe, SEL_NONCE)),
        "threshold": as_int(eth_call(safe, SEL_THRESHOLD)),
        "safeBalance": str(as_int(eth_call(token, SEL_BALANCE_OF + pad_addr(safe))) // 10**18),
        "vendorBalance": str(as_int(eth_call(token, SEL_BALANCE_OF + pad_addr(vendor))) // 10**18),
        "leavesUsed": sum(leaves),
        "leavesTotal": TREE_LEAVES,
        "leaves": leaves,
    }


def forge_script(sig, args, broadcast):
    cmd = [FORGE, "script", "script/Demo.s.sol:Demo", "-s", sig, *args,
           "--rpc-url", RPC, "--skip-simulation" if False else "-vv"]
    if broadcast:
        cmd.append("--broadcast")
    proc = subprocess.run(cmd, cwd=CONTRACTS, capture_output=True, text=True, timeout=300)
    out = proc.stdout + proc.stderr
    return proc.returncode, out


def parse_amount(payload):
    amount = int(payload.get("amount", 0))
    if not (0 < amount <= 1_000_000):
        raise ValueError("amount must be between 1 and 1,000,000 dUSD")
    return amount


def run_flow(flow, payload):
    amount = parse_amount(payload)
    if flow == "blocked":
        code, out = forge_script("blocked(uint256)", [str(amount)], broadcast=False)
        if "RESULT BLOCKED" in out:
            revert = re.search(r"0x[0-9a-f]{8,}", out.split("REVERT_DATA", 1)[-1])
            data = revert.group(0) if revert else ""
            reason = ("NoMatchingPreApproval — the Guard found no quantum pre-approval "
                      "for this transfer") if data.startswith(ERR_NO_MATCHING) else "Guard revert"
            return {"ok": True, "outcome": "blocked", "reason": reason, "revertData": data[:74]}
        return {"ok": False, "error": "unexpected outcome", "log": tail(out)}
    if flow == "approve":
        code, out = forge_script("approve(uint256)", [str(amount)], broadcast=True)
        m = re.search(r"RESULT APPROVED leaf=(\d+)", out)
        if code == 0 and m:
            idm = re.search(r"APPROVAL_ID\s*\n\s*(0x[0-9a-f]{64})", out)
            return {"ok": True, "outcome": "approved", "leaf": int(m.group(1)),
                    "approvalId": idm.group(1) if idm else None}
        return {"ok": False, "error": friendly_error(out), "log": tail(out)}
    if flow == "execute":
        code, out = forge_script("execute(uint256)", [str(amount)], broadcast=True)
        m = re.search(r"RESULT EXECUTED vendorBalance=(\d+)", out)
        if code == 0 and m:
            return {"ok": True, "outcome": "executed", "vendorBalance": m.group(1)}
        return {"ok": False, "error": friendly_error(out), "log": tail(out)}
    raise ValueError("unknown flow")


def friendly_error(out):
    if "demo key exhausted" in out:
        return "All 16 XMSS demo leaves are consumed — restart the container to reset."
    if ERR_NO_MATCHING in out:
        return ("Blocked by the Guard: no matching quantum pre-approval. "
                "Create a pre-approval for this exact amount first.")
    return "Flow failed — see log."


def tail(out, n=25):
    return "\n".join(out.strip().splitlines()[-n:])


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

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/api/state":
            try:
                self._json(chain_state())
            except Exception as e:  # noqa: BLE001
                self._json({"error": str(e)}, 500)
            return
        if path in ("/", "/index.html"):
            path = "/index.html"
        fs_path = os.path.normpath(os.path.join(UI_DIR, path.lstrip("/")))
        if fs_path.startswith(UI_DIR) and os.path.isfile(fs_path):
            ctype = {"html": "text/html", "svg": "image/svg+xml",
                     "css": "text/css", "js": "text/javascript"}.get(
                fs_path.rsplit(".", 1)[-1], "application/octet-stream")
            with open(fs_path, "rb") as f:
                body = f.read()
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_error(404)

    def do_POST(self):
        m = re.fullmatch(r"/api/(blocked|approve|execute)", self.path.split("?")[0])
        if not m:
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(length) or b"{}")
            self._json(run_flow(m.group(1), payload))
        except ValueError as e:
            self._json({"ok": False, "error": str(e)}, 400)
        except Exception as e:  # noqa: BLE001
            self._json({"ok": False, "error": str(e)}, 500)


if __name__ == "__main__":
    print(f"FermionWallet demo UI on http://0.0.0.0:{PORT}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
