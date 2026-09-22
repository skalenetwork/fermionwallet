"""FermionWallet Safe App backend (the add-on service's approval API).

Per-Safe, product-shaped endpoints used by the Safe App (demo/ui/safe-app):

  GET  /api/v1/safes/<safe>/status     Guard and quantum-key status
  GET  /api/v1/safes/<safe>/queue      pending Safe transactions + their quantum status
  GET  /api/v1/safes/<safe>/approvals  pre-approvals recorded by the Guard
  POST /api/v1/safes/<safe>/approvals  {"safeTxHash", "validForSeconds"}: have the
                                       Ledger sign a pre-approval pinned to that exact
                                       queued Safe transaction, then relay it

Everything is read from the chain and the Safe Transaction Service; nothing is taken
from the browser except which queued transaction to approve and for how long. The
transaction's fields are loaded from the Transaction Service and its safeTxHash is
recomputed on-chain before anything is sent to the Ledger (two independent sources).
Stdlib only.
"""
import json
import os
import re
import secrets
import subprocess
import urllib.error
import urllib.request

TXS = os.environ.get("TXS_URL", "http://nginx:8000/txs").rstrip("/")
ZERO_ADDR = "0x" + "00" * 20
ZERO32 = "0x" + "00" * 32
ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
HASH_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")

MIN_VALIDITY = 15 * 60  # PreApprovalEngine.MIN_WINDOW
MAX_VALIDITY = 7 * 24 * 3600

SEL_SAFE_TO_KEY = "0xe056ccae"
SEL_GET_KEY = "0x12aaac70"
SEL_APPROVAL_BY_TX = "0xaf879722"
SEL_GET_PRE_APPROVAL = "0xafd36a71"
SEL_GET_TX_HASH = "0xd8d11f78"
SEL_SYMBOL = "0x95d89b41"
SEL_DECIMALS = "0x313ce567"
SEL_TRANSFER = "0xa9059cbb"
TOPIC_CREATED = "0x9e2110e875f92d6f08f314952b1b81b9a05679b3703fab77c11266ccef3ec705"
KEY_STATUS = {0: "none", 1: "active", 2: "rotated", 3: "revoked"}

_token_cache = {}


class ApiError(ValueError):
    pass


def _words(hexdata):
    h = hexdata[2:] if hexdata.startswith("0x") else hexdata
    return [h[i:i + 64] for i in range(0, len(h), 64)]


def _addr(word):
    return "0x" + word[-40:]


def _pad(v):
    if isinstance(v, int):
        return format(v, "064x")
    return v.lower().replace("0x", "").rjust(64, "0")


def check_address(a, what="address"):
    if not isinstance(a, str) or not ADDR_RE.match(a):
        raise ApiError(f"invalid {what}")
    return a


def txs_get(path):
    try:
        with urllib.request.urlopen(TXS + path, timeout=10) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise ApiError(f"Safe Transaction Service error {e.code}") from None
    except OSError as e:
        raise ApiError(f"Safe Transaction Service unreachable ({e})") from None


def token_info(host, token):
    t = token.lower()
    if t not in _token_cache:
        try:
            raw = host.eth_call(token, SEL_SYMBOL)
            symbol = host.abi_string(raw) if len(raw) > 130 else bytes.fromhex(raw[2:66]).rstrip(b"\0").decode()
        except Exception:  # noqa: BLE001
            symbol = None
        try:
            decimals = host.as_int(host.eth_call(token, SEL_DECIMALS))
        except Exception:  # noqa: BLE001
            decimals = None
        _token_cache[t] = {"address": token, "symbol": symbol, "decimals": decimals}
    return _token_cache[t]


def fmt_units(raw, decimals):
    if decimals is None:
        return str(raw)
    whole, frac = divmod(int(raw), 10 ** decimals)
    s = f"{whole:,}"
    f = f"{frac:0{decimals}d}".rstrip("0") if decimals else ""
    return s + ("." + f if f else "")


# ── status ────────────────────────────────────────────────────────────────────

def safe_status(host, safe):
    check_address(safe, "Safe address")
    d = host.deployment()
    guard = d["guard"]
    guard_word = host.rpc("eth_getStorageAt", [safe, host.GUARD_SLOT, "latest"])
    active_guard = _addr(guard_word[2:].rjust(64, "0"))
    code = host.rpc("eth_getCode", [safe, "latest"])
    out = {
        "safe": safe,
        "chainId": host.as_int(host.rpc("eth_chainId", [])),
        "isContract": code not in ("0x", "0x0"),
        "guard": guard,
        "activeGuard": None if int(active_guard, 16) == 0 else active_guard,
        "protected": active_guard.lower() == guard.lower(),
        "key": None,
    }
    if not out["isContract"]:
        return out
    out["nonce"] = host.as_int(host.eth_call(safe, host.SEL_NONCE))
    out["threshold"] = host.as_int(host.eth_call(safe, host.SEL_THRESHOLD))
    kid = host.eth_call(guard, SEL_SAFE_TO_KEY + _pad(safe))
    if int(kid, 16) == 0:
        return out
    w = _words(host.eth_call(guard, SEL_GET_KEY + _pad(kid)))
    height = int(w[5], 16)
    total = 2 ** height
    used = int(w[10], 16)
    out["key"] = {
        "id": kid,
        "admin": _addr(w[2]),
        "root": "0x" + w[3],
        "treeHeight": height,
        "status": KEY_STATUS.get(int(w[7], 16), "unknown"),
        "createdAt": int(w[8], 16),
        "leavesUsed": used,
        "leavesTotal": total,
        "leavesLeft": total - used,
    }
    return out


# ── approvals ────────────────────────────────────────────────────────────────

def _approval(host, guard, aid, now):
    w = _words(host.eth_call(guard, SEL_GET_PRE_APPROVAL + _pad(aid)))
    if int(w[0], 16) == 0:
        return None
    valid_from, valid_to = int(w[9], 16), int(w[10], 16)
    used, revoked = int(w[17], 16) == 1, int(w[18], 16) == 1
    if used:
        status = "used"
    elif revoked:
        status = "revoked"
    elif now > valid_to:
        status = "expired"
    elif now < valid_from:
        status = "scheduled"
    else:
        status = "active"
    klass = int(w[2], 16)
    a = {
        "id": "0x" + w[0],
        "class": ["transfer", "payload", "admin"][klass] if klass < 3 else str(klass),
        "validFrom": valid_from,
        "validTo": valid_to,
        "leaf": int(w[13], 16),
        "safeTxHash": None if int(w[15], 16) == 0 else "0x" + w[15],
        "status": status,
    }
    if klass == 0:
        tok = token_info(host, _addr(w[3]))
        a.update(token=tok, recipient=_addr(w[4]), amount=str(int(w[5], 16)),
                 amountFormatted=fmt_units(int(w[5], 16), tok["decimals"]))
    else:
        a.update(target=_addr(w[6]), value=str(int(w[7], 16)), dataHash="0x" + w[8])
    return a


def _now(host):
    return host.as_int(host.rpc("eth_getBlockByNumber", ["latest", False])["timestamp"])


def approvals(host, safe):
    check_address(safe, "Safe address")
    guard = host.deployment()["guard"]
    logs = host.rpc("eth_getLogs", [{"address": guard, "fromBlock": "0x0", "toBlock": "latest",
                                     "topics": [TOPIC_CREATED, None, "0x" + _pad(safe)]}])
    now = _now(host)
    out = []
    for log in logs:
        a = _approval(host, guard, log["topics"][1], now)
        if a:
            a["createdBlock"] = host.as_int(log["blockNumber"])
            a["createdTx"] = log["transactionHash"]
            if a["safeTxHash"]:
                tx = txs_get(f"/api/v1/multisig-transactions/{a['safeTxHash']}/")
                if tx:
                    a["safeNonce"] = tx["nonce"]
            out.append(a)
    out.sort(key=lambda a: a["createdBlock"], reverse=True)
    return {"approvals": out, "now": now}


# ── queue ────────────────────────────────────────────────────────────────────

def _onchain_tx_hash(host, safe, tx):
    data = tx.get("data") or "0x"
    body = data[2:]
    n = len(body) // 2
    enc = (
        _pad(tx["to"]) + _pad(int(tx["value"])) + _pad(10 * 32) + _pad(int(tx["operation"]))
        + _pad(int(tx["safeTxGas"])) + _pad(int(tx["baseGas"])) + _pad(int(tx["gasPrice"]))
        + _pad(tx.get("gasToken") or ZERO_ADDR) + _pad(tx.get("refundReceiver") or ZERO_ADDR)
        + _pad(int(tx["nonce"])) + _pad(n) + body + "0" * ((-len(body)) % 64)
    )
    return host.eth_call(safe, SEL_GET_TX_HASH + enc)


def decode(host, tx):
    data = (tx.get("data") or "0x").lower()
    if int(tx["operation"]) != 0:
        return {"kind": "delegatecall", "summary": "Delegate call to " + tx["to"]}
    if data.startswith(SEL_TRANSFER) and len(data) == 2 + 8 + 128 and int(tx["value"]) == 0:
        tok = token_info(host, tx["to"])
        recipient = _addr(data[10:74])
        amount = int(data[74:138], 16)
        return {"kind": "transfer", "token": tok, "recipient": recipient, "amount": str(amount),
                "amountFormatted": fmt_units(amount, tok["decimals"]),
                "summary": f"Send {fmt_units(amount, tok['decimals'])} {tok['symbol'] or 'tokens'}"}
    if data in ("0x", "") and int(tx["value"]) > 0:
        return {"kind": "native", "summary": f"Send {fmt_units(int(tx['value']), 18)} ETH to {tx['to']}"}
    method = (tx.get("dataDecoded") or {}).get("method")
    return {"kind": "call", "summary": f"Contract interaction{': ' + method if method else ''} ({tx['to']})"}


def queue(host, safe):
    check_address(safe, "Safe address")
    guard = host.deployment()["guard"]
    nonce = host.as_int(host.eth_call(safe, host.SEL_NONCE))
    page = txs_get(f"/api/v1/safes/{safe}/multisig-transactions/?executed=false&nonce__gte={nonce}"
                   "&ordering=nonce&limit=50") or {"results": []}
    now = _now(host)
    rows = []
    for tx in page["results"]:
        h = tx["safeTxHash"]
        row = {
            "safeTxHash": h,
            "nonce": tx["nonce"],
            "to": tx["to"],
            "value": tx["value"],
            "confirmations": len(tx.get("confirmations") or []),
            "confirmationsRequired": tx.get("confirmationsRequired"),
            "submitted": tx.get("submissionDate"),
            "gasPrice": tx.get("gasPrice") or "0",
            **decode(host, tx),
        }
        row["verified"] = _onchain_tx_hash(host, safe, tx).lower() == h.lower()
        aid = host.eth_call(guard, SEL_APPROVAL_BY_TX + _pad(safe) + _pad(h))
        row["approval"] = _approval(host, guard, aid, now) if int(aid, 16) else None
        rows.append(row)

    first_pending_nonce = nonce
    for row in rows:
        a = row["approval"]
        if not row["verified"]:
            row["status"] = "mismatch"
        elif a and a["status"] in ("active", "scheduled"):
            row["status"] = "approved" if row["nonce"] == first_pending_nonce else "waiting"
        elif row["kind"] != "transfer":
            row["status"] = "unsupported"
            row["reason"] = "Only ERC-20 transfers can be approved from this app."
        elif int(row["gasPrice"]) != 0:
            row["status"] = "unsupported"
            row["reason"] = "Transactions with a gas refund are always blocked by the Guard."
        else:
            row["status"] = "needs_approval"
    return {"nonce": nonce, "transactions": rows, "now": now}


# ── create (Ledger signs, relayer submits) ───────────────────────────────────

def create_approval(host, safe, payload):
    check_address(safe, "Safe address")
    if not isinstance(payload, dict):
        raise ApiError("request body must be a JSON object")
    h = payload.get("safeTxHash")
    if not isinstance(h, str) or not HASH_RE.match(h):
        raise ApiError("safeTxHash must be a 32-byte hex string")
    valid_for = payload.get("validForSeconds")
    if isinstance(valid_for, bool) or not isinstance(valid_for, int) or not (MIN_VALIDITY <= valid_for <= MAX_VALIDITY):
        raise ApiError("validForSeconds must be a whole number between 900 (15 min) and 604800 (7 days)")

    st = safe_status(host, safe)
    if not st["protected"]:
        raise ApiError("This Safe is not protected by the FermionWallet Guard.")
    key = st["key"]
    if not key or key["status"] != "active":
        raise ApiError("This Safe has no active quantum key.")
    if key["leavesLeft"] <= 0:
        raise ApiError("The quantum key has no one-time leaves left. Rotate the key first.")

    tx = txs_get(f"/api/v1/multisig-transactions/{h}/")
    if not tx or tx.get("safe", "").lower() != safe.lower():
        raise ApiError("That transaction is not in this Safe's queue.")
    if tx.get("isExecuted"):
        raise ApiError("That transaction has already been executed.")
    if int(tx["nonce"]) < st["nonce"]:
        raise ApiError("That transaction's nonce has already been used.")
    # Two sources: the Transaction Service's fields must hash, on-chain, to its safeTxHash.
    if _onchain_tx_hash(host, safe, tx).lower() != h.lower():
        raise ApiError("The Transaction Service and the chain disagree about this transaction. Do not sign.")
    dec = decode(host, tx)
    if dec["kind"] != "transfer":
        raise ApiError("Only ERC-20 transfers can be approved from this app.")
    if int(tx["gasPrice"]) != 0:
        raise ApiError("Transactions with a gas refund are always blocked by the Guard.")
    guard = st["guard"]
    existing = host.eth_call(guard, SEL_APPROVAL_BY_TX + _pad(safe) + _pad(h))
    if int(existing, 16):
        a = _approval(host, guard, existing, _now(host))
        if a and a["status"] in ("active", "scheduled"):
            raise ApiError("This transaction already has an active pre-approval.")
    bal = host.as_int(host.eth_call(tx["to"], host.SEL_BALANCE_OF + _pad(safe)))
    if bal < int(dec["amount"]):
        raise ApiError(f"The Safe holds only {fmt_units(bal, dec['token']['decimals'])} "
                       f"{dec['token']['symbol'] or ''} — this transfer could never execute, so the "
                       "Ledger was not asked to spend a one-time leaf on it.")

    now = _now(host)
    fields = {
        "safe": safe, "approvalClass": 0, "token": tx["to"], "recipient": dec["recipient"],
        "amount": dec["amount"], "target": ZERO_ADDR, "value": "0", "dataHash": ZERO32,
        "validFrom": now, "validTo": now + valid_for, "nonce": "0x" + secrets.token_hex(32),
        "quantumKeyId": key["id"], "policyHash": host.DEMO_POLICY_HASH, "txHash": h,
    }
    res = host.sign_on_device(fields, key["root"], guard)
    if res.get("status") != "approved":
        return {"ok": True, "outcome": "rejected", "reason": res.get("status", "rejected")}

    req = "(" + ",".join([
        fields["safe"], fields["token"], fields["recipient"], fields["amount"], ZERO_ADDR, "0", ZERO32,
        str(fields["validFrom"]), str(fields["validTo"]), fields["nonce"], fields["quantumKeyId"],
        str(res["leaf"]), fields["policyHash"], fields["txHash"],
    ]) + ")"
    enc = subprocess.run(
        ["cast", "abi-encode", "f((address,address,address,uint256,address,uint256,bytes32,uint64,uint64,"
         "bytes32,bytes32,uint32,bytes32,bytes32))", req],
        capture_output=True, text=True, check=True).stdout.strip()
    with host.FLOW_LOCK:
        code, out = host.forge_script("relayPreApproval(bytes,bytes,bytes)",
                                      [enc, res["ecdsaSignature"], res["xmssSignature"]], broadcast=True)
    m = re.search(r"APPROVAL_ID\s*\n\s*(0x[0-9a-f]{64})", out)
    if code == 0 and m:
        return {"ok": True, "outcome": "approved", "approvalId": m.group(1), "leaf": res["leaf"],
                "digest": res["digest"], "validTo": fields["validTo"]}
    return host.failure(out, f"The Ledger signed with leaf #{res['leaf']} (now spent — the device commits its "
                             "counter before signing), but the Guard refused the approval: ")
