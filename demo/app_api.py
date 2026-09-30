"""FermionGuard Safe App backend (the add-on service's approval API).

Per-Safe, product-shaped endpoints used by the Safe App (demo/ui/safe-app):

  GET  /api/v1/safes/<safe>/status     Guard and quantum-key status
  GET  /api/v1/safes/<safe>/queue      pending Safe transactions + their quantum status
  GET  /api/v1/safes/<safe>/approvals  pre-approvals recorded by the Guard
  POST /api/v1/safes/<safe>/approvals  {"safeTxHash", "validForSeconds",
                                       "overrideNonce"?}: have the Ledger sign a
                                       pre-approval pinned to that exact queued Safe
                                       transaction, then relay it

Everything is read from the chain and the Safe Transaction Service; nothing is taken
from the browser except which queued transaction to approve and for how long. The
transaction's fields are loaded from the Transaction Service and its safeTxHash is
recomputed on-chain before anything is sent to the Ledger (two independent sources).

Two rules of the specification are enforced here rather than in the browser, because a
rule enforced only in the browser is not a rule:

  * nonce order (fermionguard-add-on-service.md, "Nonce-order discipline"): the
    Administrator may approve the lowest unapproved nonce freely; approving any other
    row requires the caller to name that row's nonce in `overrideNonce`, which is what
    the app's full-screen override modal makes the operator type.
  * simulate before spending a leaf (Stage D): the relay is dry-run against the chain
    before the Ledger is asked for a signature, and again — with the signature, and with
    byte-identical arguments — before the broadcast. The device commits its one-time
    counter before releasing a signature, so a relay that was never going to land costs
    a leaf permanently.

The Ledger can hold a decision for up to an hour, so POST does not wait for it: it
returns a pending job and the job's progress rides on every `queue` response, which
means a closed tab loses nothing.
Stdlib only.
"""
import json
import os
import re
import secrets
import subprocess
import threading
import time
import urllib.error
import urllib.request

TXS = os.environ.get("TXS_URL", "http://nginx:8000/txs").rstrip("/")
ZERO_ADDR = "0x" + "00" * 20
ZERO32 = "0x" + "00" * 32
ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
HASH_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")

MIN_VALIDITY = 15 * 60  # PreApprovalEngine.MIN_WINDOW
MAX_VALIDITY = 7 * 24 * 3600

# How long one queued Safe transaction ahead of yours is assumed to take to clear:
# gather the remaining owner signatures, then execute. The specification asks for
# "estimated time for all earlier queued nonces to clear + policy margin" rather than a
# flat minimum; this add-on service keeps no execution history to learn a real
# distribution from, so the estimate is these two constants and is labelled an estimate
# everywhere it is shown. A service with history should replace PER_NONCE_SECONDS with
# the Safe's own median.
PER_NONCE_SECONDS = 30 * 60
POLICY_MARGIN_SECONDS = 60 * 60

RELAY_SIG = "relayPreApproval(bytes,bytes,bytes)"
# 65 zero bytes: a syntactically well-formed ECDSA half that can never recover to the
# registered Quantum Administrator. It is what makes the pre-signature dry run possible.
PROBE_ECDSA = "0x" + "00" * 65

SEL_SAFE_TO_KEY = "0xe056ccae"
SEL_SAFE_PAUSED = "0xfa309153"
SEL_GET_KEY = "0x12aaac70"
SEL_APPROVAL_BY_TX = "0xaf879722"
SEL_GET_PRE_APPROVAL = "0xafd36a71"
SEL_GET_TX_HASH = "0xd8d11f78"
SEL_SYMBOL = "0x95d89b41"
SEL_DECIMALS = "0x313ce567"
SEL_TRANSFER = "0xa9059cbb"
TOPIC_CREATED = "0x9e2110e875f92d6f08f314952b1b81b9a05679b3703fab77c11266ccef3ec705"
KEY_STATUS = {0: "none", 1: "active", 2: "rotated", 3: "revoked"}

# FermionGuard._isDeniedSelector: allowance grants, refused for every Safe, for ever —
# they can never be added to a permit-list, so no approval could ever make them execute.
DENIED_SELECTORS = {
    "0x095ea7b3": "approve",
    "0x23b872dd": "transferFrom",
    "0x39509351": "increaseAllowance",
    "0xd505accf": "permit",
}
# FermionGuard._isEmergencyEscapeCall, branch (a): a zero-value call from the Safe to the
# Guard, which the Guard may never block — no quantum approval, no pause, no enrollment.
GUARD_ESCAPE_CALLS = {
    "0x4745760e": "Revoke a quantum pre-approval",
    "0xedb69aa6": "Pause this Safe",
    "0x95156b37": "Request unpausing this Safe",
    "0xa2580fbd": "Unpause this Safe",
    "0x13acd71f": "Start the 14-day emergency Guard removal",
    "0x7d26d7c8": "Cancel the emergency Guard removal",
    "0xe17a4885": "Cancel a pending key revocation",
}

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
    # Any single owner can pause the Safe, and while it is paused the Guard reverts
    # everything except the owners' escape calls — including transactions that already
    # hold a valid pre-approval. A UI that does not read this says "Ready to execute"
    # about a transaction that cannot execute.
    out["paused"] = host.as_int(host.eth_call(guard, SEL_SAFE_PAUSED + _pad(safe))) == 1
    out["nonce"] = host.as_int(host.eth_call(safe, host.SEL_NONCE))
    out["threshold"] = host.as_int(host.eth_call(safe, host.SEL_THRESHOLD))
    # getOwners() returns (offset, length, addresses...): word 1 is the count.
    out["ownerCount"] = host.as_int(host.eth_call(safe, host.SEL_GET_OWNERS)[2 + 64:2 + 128])
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


# A Safe executes strictly in nonce order, so a transaction that can never execute holds
# every later one behind it — and Safe{Wallet}'s own "on-chain rejection" is an ordinary
# Safe transaction, which the Guard blocks for exactly the same reason. Saying "just
# reject it" would be wrong: on a guarded Safe that does not work.
STUCK_NONCE = (
    " Until this nonce is cleared it holds every higher one behind it, and Safe{Wallet}'s on-chain "
    "rejection will not clear it: that rejection is itself an ordinary Safe transaction, which the "
    "Guard blocks for want of a pre-approval of its own. What does work is replacing it: create a "
    "new transaction in Safe{Wallet} at this same nonce, as an ordinary ERC-20 transfer (a dust "
    "amount to an address you control will do), approve that one here, and execute it. It takes "
    "this nonce and the queue moves on."
)


# ── nonce-order discipline ───────────────────────────────────────────────────

# A nonce no longer needs the Administrator: a row at it either already holds a live
# pre-approval ("approved"/"waiting") or needs none at all ("free" — an owners' escape
# call, or an unguarded Safe). Every other state — needing approval, blocked by the
# Guard, unsupported, hash-mismatched — leaves the nonce standing in the way, which is
# the whole point: the Safe executes in strict nonce order.
SETTLED_STATUSES = ("approved", "waiting", "free")


def _queue_sort_key(row):
    # Primarily by Safe nonce, never by expiry urgency. Rows sharing a nonce — competing
    # replacement candidates — sort by proposal time, oldest first, so "the row above"
    # means the same row in this service and in the app. safeTxHash breaks a tie between
    # two proposals recorded in the same instant, so the order is never random.
    return (row["nonce"], row.get("submitted") or "", row["safeTxHash"])


def apply_nonce_order(rows, now):
    """Fill in the nonce-order fields the specification makes mandatory, and return the
    lowest unapproved nonce.

    `authorize` is the only thing that may put an Authorize action on a row:
      "direct"   — this is the lowest unapproved nonce (and, among rivals for it, the
                   oldest proposal): approve it freely.
      "override" — approving this first leaves it un-executable behind an earlier nonce,
                   or hands one nonce to the newer of two rivals. It needs the
                   full-screen override and a typed confirmation.
      None       — nothing here can be approved.
    """
    rows.sort(key=_queue_sort_key)
    settled = {r["nonce"] for r in rows if r["status"] in SETTLED_STATUSES}
    open_nonces = sorted({r["nonce"] for r in rows} - settled)
    target = open_nonces[0] if open_nonces else None
    claimed = False
    previous = None
    for row in rows:
        row["conflictsWithAbove"] = previous is not None and previous["nonce"] == row["nonce"]
        earlier = [n for n in open_nonces if n < row["nonce"]]
        row["earlierUnapprovedNonces"] = earlier
        # Estimated time for the queue ahead of this row to clear, and the validity
        # window to suggest for it: that estimate, plus a slot for this transaction
        # itself, plus the policy margin.
        row["aheadSeconds"] = (len(earlier) * PER_NONCE_SECONDS
                               + (POLICY_MARGIN_SECONDS if earlier else 0))
        row["suggestedSeconds"] = min(
            MAX_VALIDITY, row["aheadSeconds"] + PER_NONCE_SECONDS + POLICY_MARGIN_SECONDS)
        if row["status"] != "needs_approval":
            row["authorize"] = None
        elif row["nonce"] == target and not claimed:
            row["authorize"] = "direct"
            claimed = True
        else:
            row["authorize"] = "override"
            if not earlier:
                # Not held up by an earlier nonce, so it is a rival for its own: either
                # another row at this nonce already holds an approval, or one was queued
                # first and is the row the Authorize action sits on.
                row["rivalHolds"] = "approval" if any(
                    r["nonce"] == row["nonce"] and r["status"] in SETTLED_STATUSES for r in rows
                ) else "queue-position"
        # Re-evaluation of the rows behind an earlier nonce. Recomputed on every poll
        # rather than on an event, so a rejection or replacement of an earlier nonce
        # shows up here within one refresh whether or not this service saw the event.
        a = row["approval"]
        if (row["status"] in ("approved", "waiting") and a
                and a["status"] in ("active", "scheduled")
                and a["validTo"] - now < row["aheadSeconds"]):
            row["windowRisk"] = {"remainingSeconds": max(0, a["validTo"] - now),
                                 "aheadSeconds": row["aheadSeconds"],
                                 "leaf": a["leaf"]}
        previous = row
    return target


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


def decode(host, tx, guard=None, safe=None):
    data = (tx.get("data") or "0x").lower()
    if int(tx["operation"]) != 0:
        return {"kind": "delegatecall", "summary": "Delegate call to " + tx["to"]}
    if (guard and tx["to"].lower() == guard.lower() and int(tx["value"]) == 0
            and data[:10] in GUARD_ESCAPE_CALLS):
        # The Guard's own safety calls. It lets these through whatever else is true of
        # the Safe — that is the property that stops a Safe locking itself out.
        return {"kind": "guard_escape", "summary": GUARD_ESCAPE_CALLS[data[:10]]}
    if data[:10] in DENIED_SELECTORS:
        return {"kind": "denied", "selector": data[:10], "method": DENIED_SELECTORS[data[:10]],
                "summary": DENIED_SELECTORS[data[:10]] + "() on " + tx["to"]}
    if safe and tx["to"].lower() == safe.lower() and data in ("0x", "") and int(tx["value"]) == 0:
        # Safe{Wallet}'s "on-chain rejection": a zero-value self-call with no calldata,
        # queued to burn a nonce. It is not an escape call, so the Guard blocks it too.
        return {"kind": "rejection", "summary": "On-chain rejection of Safe transaction #" + str(tx["nonce"])}
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
    head = host.rpc("eth_getBlockByNumber", ["latest", False])
    now = host.as_int(head["timestamp"])
    block = host.as_int(head["number"])
    guard_word = host.rpc("eth_getStorageAt", [safe, host.GUARD_SLOT, "latest"])
    protected = _addr(guard_word[2:].rjust(64, "0")).lower() == guard.lower()
    paused = protected and host.as_int(host.eth_call(guard, SEL_SAFE_PAUSED + _pad(safe))) == 1
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
            **decode(host, tx, guard=guard, safe=safe),
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
            row["reason"] = ("The Safe Transaction Service gave these fields for this transaction, "
                             "but the Safe contract does not hash them to this transaction hash. "
                             "One of them is wrong, and the fields shown here may not be the ones "
                             "the owners signed. Do not approve it and do not execute it: tell the "
                             "other owners and settle which is right away from this screen.")
        elif int(row["gasPrice"]) != 0:
            # checkTransaction step 0, before the escape hatch: a gas refund is refused
            # for every transaction, escape calls included.
            row["status"] = "blocked"
            row["reason"] = ("The Guard refuses any transaction that pays a gas refund, always — it "
                             "is the first thing it checks, before anything else about this Safe. "
                             "Re-create this transaction in Safe{Wallet} with a zero gas price."
                             + STUCK_NONCE)
        elif row["kind"] == "guard_escape":
            # The owners' safety calls, which the Guard may never block on account of any
            # Safe state: no pre-approval, no enrollment, and not even a pause.
            row["status"] = "free"
            row["reason"] = ("The Guard always lets this through, whatever the state of this Safe: "
                             "it needs owner signatures only.")
        elif not protected:
            row["status"] = "free"
            row["reason"] = ("This Safe is not protected by the FermionGuard, so its transactions "
                             "need only owner signatures.")
        elif paused:
            row["status"] = "paused"
            row["reason"] = ("This Safe is paused, so the Guard refuses every transaction that is "
                             "not an owner safety call — a valid pre-approval does not change that. "
                             "The owner threshold must request unpausing and wait out the timelock."
                             + (" The pre-approval on this transaction stays valid meanwhile, but "
                                "its validity window keeps running." if a and
                                a["status"] in ("active", "scheduled") else ""))
        elif a and a["status"] in ("active", "scheduled"):
            row["status"] = "approved" if row["nonce"] == first_pending_nonce else "waiting"
        elif row["kind"] == "denied":
            row["status"] = "blocked"
            row["reason"] = (f"The Guard refuses {row['method']}() for every Safe, always: an allowance "
                             "lets funds move later with no second authorization. No approval can make "
                             "this execute." + STUCK_NONCE)
        elif row["kind"] == "delegatecall":
            row["status"] = "blocked"
            row["reason"] = ("The Guard refuses delegate calls, always. No approval can make this "
                             "execute." + STUCK_NONCE)
        elif row["kind"] == "rejection":
            row["status"] = "unsupported"
            row["reason"] = (
                "Safe{Wallet}'s on-chain rejection is an ordinary Safe transaction, so the Guard "
                "requires a quantum pre-approval for it as well — and this version of the app signs "
                "only ERC-20 transfers, so it will not clear the transaction it was meant to cancel."
                + STUCK_NONCE)
        elif row["kind"] != "transfer":
            row["status"] = "unsupported"
            row["reason"] = ("This version of the app signs single ERC-20 transfers only, and the "
                             "Guard requires a quantum pre-approval for this transaction too." + STUCK_NONCE)
        else:
            row["status"] = "needs_approval"

    target = apply_nonce_order(rows, now)
    attach_jobs(rows, block)
    return {"nonce": nonce, "protected": protected, "paused": paused,
            "transactions": rows, "now": now, "block": block,
            "lowestUnapprovedNonce": target,
            "perNonceEstimateSeconds": PER_NONCE_SECONDS,
            "policyMarginSeconds": POLICY_MARGIN_SECONDS}


# ── relay failures ───────────────────────────────────────────────────────────

# What each Guard revert means for the person who just approved on the device, and what
# they should do next. `forge` prints custom errors by name, so the name is what we match;
# an unlisted one is still shown by name and with its arguments rather than swallowed,
# because "the Guard refused it" with no reason is not something anyone can act on.
RELAY_ERRORS = {
    "LeafAlreadyUsed":
        "The chain has already recorded an approval signed with that one-time signature. The "
        "device's counter and the chain disagree — which is also what a cloned or stolen key "
        "looks like. Do not retry: check the Key tab and treat the key as possibly compromised.",
    "InvalidXmssSignature":
        "The post-quantum half of the signature did not verify against the key registered for "
        "this Safe. The device that signed is not the enrolled Quantum Administrator device.",
    "InvalidEcdsaSignature":
        "The classical half of the signature did not verify against the registered Quantum "
        "Administrator address. The device that signed is not the enrolled one.",
    "LeafIndexDoesNotMatchSignature":
        "The one-time signature the device released does not carry the leaf index it declared. "
        "Do not retry; report this — it should be impossible.",
    "LeafIndexMismatch":
        "The device signed with a leaf index the registry did not expect. Do not retry; report it.",
    "WrongQuantumKey":
        "The approval was signed under a key that is no longer this Safe's active key — it was "
        "rotated or revoked while you were reviewing. Reload the app and approve again.",
    "NoActiveKey":
        "This Safe no longer has an active quantum key, so no approval can be recorded for it. "
        "Register or rotate a key first.",
    "TxHashAlreadyPinned":
        "Another live pre-approval is already pinned to this exact Safe transaction. Revoke it, "
        "or execute it — one Safe transaction carries one pin at a time.",
    "ApprovalExists":
        "An identical pre-approval already exists on-chain.",
    "InvalidWindow":
        "The Guard rejected the validity window: it must be at least 15 minutes long and must "
        "still end in the future when it lands on-chain. Approve again with a longer window.",
    "AdminTimelockNotRespected":
        "An administrative approval must start no sooner than the Guard's timelock allows.",
    "CommitmentQueueFull":
        "The Guard already holds the maximum number of pending pre-approvals for this exact "
        "transfer. Execute or revoke one of them before approving another.",
    "ZeroAddress":
        "The Guard rejected a zero address in the approval. Reload the app and try again.",
    "NonZeroClassFields":
        "The approval carried fields that do not belong to a transfer. Reload the app and try again.",
}
# The Guard may also refuse the relayer's own transaction before it reaches the Guard.
RELAY_PREFIXES = (
    ("insufficient funds",
     "The relayer account that submits approvals has no funds left to pay gas. The signature is "
     "spent; top the relayer up and the approval must be created again."),
    ("Failed to get EIP-1559 fees",
     "The service could not reach the chain to submit the approval. The signature is spent; check "
     "the chain connection and approve again."),
    ("nonce too low",
     "Two approvals were submitted at once and this one lost the race. The signature is spent; "
     "approve again."),
)


def relay_error(out):
    """Turn a failed `forge script` run into one sentence a treasury operator can act on."""
    m = re.search(r"script failed:\s*([A-Za-z_][A-Za-z0-9_]*)\(([^\n)]*)\)", out)
    if not m:
        matches = re.findall(r"\[Revert\]\s*([A-Za-z_][A-Za-z0-9_]*)\(([^\n)]*)\)", out)
        m = matches[-1] if matches else None
        name, args = m if m else (None, None)
    else:
        name, args = m.group(1), m.group(2)
    if name:
        known = RELAY_ERRORS.get(name)
        detail = f"The Guard reported {name}({args.strip()})."
        return f"{known} ({detail.rstrip('.')})" if known else (
            detail + " No remedy is known for this one — report it with the Safe transaction hash.")
    # Not a contract revert: the relayer or the chain refused the transaction itself.
    for needle, text in RELAY_PREFIXES:
        if needle in out:
            return text
    plain = re.search(r"execution reverted:?\s*(.+)", out)
    if plain:
        return "The Guard reported: " + plain.group(1).strip()[:200]
    return ("The service could not record the approval on-chain and reported no reason. Check the "
            "Approvals tab before approving again: the signature may or may not have landed.")


# ── signing jobs (the device can hold a decision for an hour) ────────────────

# The Ledger's decision screen belongs to a human, and the POST that starts it used to
# wait for them: close the tab and the device session was still live with nothing left
# to relay its result to. The work runs in a thread instead, and its progress is kept
# here, keyed by Safe transaction hash, so every client — including a tab opened after
# the fact — sees it on the next `queue` poll.
_jobs = {}
_jobs_lock = threading.Lock()
# How long a finished job stays visible after it ends. Long enough that a reloaded tab
# still learns what happened; short enough that the queue does not become a log.
JOB_KEEP_SECONDS = 300

JOB_TEXT = {
    "device": "Confirm on your Ledger. Check every screen against the fields above: token, "
              "recipient, amount, validity, and the Safe transaction it is pinned to.",
    "simulating": "Signed on the Ledger. Asking the chain whether the Guard will accept it, "
                  "before anything is submitted…",
    "submitting": "Submitting the approval to the chain…",
}


def _job_set(job, **fields):
    with _jobs_lock:
        job.update(fields)


def _job_finish(job, outcome, **fields):
    _job_set(job, phase="done", outcome=outcome, finishedAt=time.time(), **fields)


def attach_jobs(rows, block):
    """Put each row's in-flight (or just-finished) signing job on the row, and forget
    jobs whose result has been readable for long enough. Jobs are dropped by age only:
    one Safe's poll must never discard another Safe's running job."""
    now = time.time()
    with _jobs_lock:
        for h, j in list(_jobs.items()):
            if j.get("finishedAt") and now - j["finishedAt"] > JOB_KEEP_SECONDS:
                del _jobs[h]
        live = {h: dict(j) for h, j in _jobs.items()}
    for row in rows:
        job = live.get(row["safeTxHash"])
        if not job:
            continue
        if job.get("relayBlock"):
            job["confirmations"] = max(1, block - job["relayBlock"] + 1)
        row["signing"] = job


def _relay_receipt(host, guard, approval_id):
    """Where the approval landed: the Guard's own creation event carries the id, so the
    relaying transaction is found without parsing forge's output for it."""
    try:
        logs = host.rpc("eth_getLogs", [{"address": guard, "fromBlock": "0x0",
                                         "toBlock": "latest",
                                         "topics": [TOPIC_CREATED, approval_id]}])
    except Exception:  # noqa: BLE001  (a confirmation count is never worth failing over)
        return None, None
    if not logs:
        return None, None
    return logs[-1]["transactionHash"], host.as_int(logs[-1]["blockNumber"])


# ── simulation (Stage D: eth_call before submission) ─────────────────────────

def _encode_request(fields, leaf):
    """The ABI-encoded PreApprovalRequest, exactly as the relayer script decodes it."""
    req = "(" + ",".join([
        fields["safe"], fields["token"], fields["recipient"], fields["amount"], ZERO_ADDR, "0",
        ZERO32, str(fields["validFrom"]), str(fields["validTo"]), fields["nonce"],
        fields["quantumKeyId"], str(leaf), fields["policyHash"], fields["txHash"],
    ]) + ")"
    return subprocess.run(
        ["cast", "abi-encode", "f((address,address,address,uint256,address,uint256,bytes32,uint64,uint64,"
         "bytes32,bytes32,uint32,bytes32,bytes32))", req],
        capture_output=True, text=True, check=True).stdout.strip()


def _revert_name(out):
    m = re.search(r"script failed:\s*([A-Za-z_][A-Za-z0-9_]*)\(", out)
    return m.group(1) if m else None


def simulate_before_signing(host, fields, next_leaf, tree_height):
    """Dry-run the relay before the device is asked for a signature, and raise if the
    Guard would refuse it for any reason other than the missing signature.

    The one thing this cannot carry is a valid signature, so the run is expected to end
    at `InvalidEcdsaSignature` — and reaching that line means everything the contract
    checks before it passed: the Safe's key is the Active one and is the key named here,
    the class fields are well formed, the validity window is legal and not already over,
    and the approval id is free. The probe differs from the submission in the leaf index
    and the two signature blobs only, and no check before the signature line reads
    either of them (`PreApprovalEngine._create`). Anything else is a revert the real
    relay would hit too, and it is worth more than the leaf it saves.
    """
    probe = _encode_request(fields, next_leaf)
    blob = "0x" + "00" * (32 * (1 + 67 + tree_height))
    with host.FLOW_LOCK:
        code, out = host.forge_script(RELAY_SIG, [probe, PROBE_ECDSA, blob], broadcast=False)
    name = _revert_name(out)
    if code == 0 or name is None:
        # Neither can happen: 65 zero bytes never recover to the Administrator, so the
        # run must reach the signature check and stop there. Refuse rather than guess.
        raise ApiError(
            "The pre-approval could not be checked against the chain before signing, so the "
            "Ledger was not asked to spend a one-time signature. The simulated relay "
            "neither succeeded nor reported a reason; check the service log and retry.")
    if name != "InvalidEcdsaSignature":
        raise ApiError(
            "The Guard would refuse this approval, so the Ledger was not asked to sign it and "
            "no one-time signature was spent. " + relay_error(out))


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
    override = payload.get("overrideNonce")
    if override is not None and (isinstance(override, bool) or not isinstance(override, int)):
        raise ApiError("overrideNonce must be the Safe nonce of the transaction being approved")

    # One device session per Safe transaction. A second click, or a second tab, joins
    # the running job instead of asking the device to sign the same thing twice.
    with _jobs_lock:
        running = _jobs.get(h)
        if running and running.get("phase") != "done":
            return {"ok": True, "outcome": "pending", "job": dict(running),
                    "note": "This transaction is already being signed."}

    st = safe_status(host, safe)
    if not st["protected"]:
        raise ApiError("This Safe is not protected by the FermionGuard.")
    key = st["key"]
    if not key or key["status"] != "active":
        raise ApiError("This Safe has no active quantum key.")
    if key["leavesLeft"] <= 0:
        raise ApiError("The quantum key has no one-time leaves left. Rotate the key first.")

    # Nonce order. The queue this service builds is the authority on which row may be
    # approved: the app's Authorize button and its override modal are how an operator
    # reaches this, but a caller that skips the app gets the same answer.
    q = queue(host, safe)
    row = next((r for r in q["transactions"] if r["safeTxHash"].lower() == h.lower()), None)
    if row is None:
        raise ApiError("That transaction is not in this Safe's pending queue.")
    if row["authorize"] is None:
        raise ApiError(row.get("reason") or "This transaction cannot be approved from this app.")
    if row["authorize"] == "override":
        earlier = row["earlierUnapprovedNonces"]
        if override != row["nonce"]:
            if earlier:
                raise ApiError(
                    f"Safe transaction #{earlier[0]} is still unapproved, and a Safe executes in "
                    f"strict nonce order, so an approval of #{row['nonce']} could not execute until "
                    f"#{', #'.join(str(n) for n in earlier)} {'have' if len(earlier) > 1 else 'has'} "
                    "cleared — its validity window would start burning now. Approve the lowest "
                    f"unapproved nonce (#{q['lowestUnapprovedNonce']}) instead, or confirm the "
                    "override in the app, which requires typing the nonce.")
            raise ApiError(
                (f"Nonce #{row['nonce']} already carries a quantum approval on another queued "
                 "transaction. " if row.get("rivalHolds") == "approval" else
                 f"Another transaction was queued at nonce #{row['nonce']} before this one. ")
                + "Only one of them can ever take that nonce, so the other's one-time signature "
                "is spent for nothing. Approve the one the app offers, or confirm the override "
                "in the app, which requires typing the nonce.")
        # There is no audit log in this service yet, so the override is recorded where
        # this service records everything: its log, with the queue state it overrode.
        print(f"[fermionguard] NONCE OVERRIDE safe={safe} nonce=#{row['nonce']} tx={h} "
              f"earlierUnapproved={earlier} lowestUnapproved=#{q['lowestUnapprovedNonce']} "
              f"aheadEstimateSeconds={row['aheadSeconds']} chosenWindowSeconds={valid_for}",
              flush=True)

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
    # Stage D, before the leaf: everything the Guard checks ahead of the signature is
    # checked against the chain now, while refusing still costs nothing.
    simulate_before_signing(host, fields, key["leavesUsed"], key["treeHeight"])

    job = {"safeTxHash": h, "nonce": row["nonce"], "phase": "device", "outcome": None,
           "startedAt": time.time(), "validTo": fields["validTo"],
           "overridden": row["authorize"] == "override"}
    with _jobs_lock:
        running = _jobs.get(h)
        if running and running.get("phase") != "done":
            return {"ok": True, "outcome": "pending", "job": dict(running),
                    "note": "This transaction is already being signed."}
        _jobs[h] = job
    threading.Thread(target=_run_approval, args=(host, job, fields, key, guard),
                     daemon=True, name="approval-" + h[:10]).start()
    # The device now owns the decision, for as long as the reviewer takes. The job's
    # progress rides on every `queue` response, so this request does not wait for it.
    return {"ok": True, "outcome": "pending", "job": dict(job)}


def _run_approval(host, job, fields, key, guard):
    """Ask the device, simulate the exact submission, then submit. Runs in its own
    thread; every outcome ends up on the job, never only in an HTTP response."""
    h = fields["txHash"]
    try:
        try:
            res = host.sign_on_device(fields, key["root"], guard)
        except OSError as e:  # the device did not answer (urllib raises URLError/OSError)
            _job_finish(job, "error", error=(
                "The FermionGuard Ledger did not answer, so nothing was signed and no one-time "
                "signature was spent. Check that the device is connected and the FermionGuard "
                f"app is open on it, then try again. ({e})"))
            return
        except ValueError as e:  # the device refused the session (busy, key exhausted)
            _job_finish(job, "error", error=str(e))
            return
        if res.get("status") != "approved":
            _job_finish(job, "rejected", reason=res.get("status", "rejected"))
            return

        leaf = res["leaf"]
        _job_set(job, phase="simulating", leaf=leaf, digest=res["digest"])
        args = [_encode_request(fields, leaf), res["ecdsaSignature"], res["xmssSignature"]]
        spent = (f"The Ledger signed with one-time signature #{leaf} — which is now spent, "
                 "because the device commits its counter before it releases a signature — but ")
        with host.FLOW_LOCK:
            # The same script and the same three arguments as the broadcast below: the
            # only difference is that this run is not broadcast. A simulation over
            # different calldata would prove nothing about the submission.
            code, out = host.forge_script(RELAY_SIG, args, broadcast=False)
            if code != 0:
                _job_finish(job, "relay_failed", leaf=leaf, error=(
                    spent + "the Guard would refuse to record the approval, so nothing was "
                    "submitted and no gas was spent on it. " + relay_error(out)))
                return
            _job_set(job, phase="submitting")
            code, out = host.forge_script(RELAY_SIG, args, broadcast=True)
        m = re.search(r"APPROVAL_ID\s*\n\s*(0x[0-9a-f]{64})", out)
        if code == 0 and m:
            tx_hash, block = _relay_receipt(host, guard, m.group(1))
            _job_finish(job, "approved", leaf=leaf, approvalId=m.group(1),
                        relayTx=tx_hash, relayBlock=block)
            return
        _job_finish(job, "relay_failed", leaf=leaf, error=(
            spent + "the Guard refused to record the approval. " + relay_error(out)))
    except Exception as e:  # noqa: BLE001  (a thread that dies silently is the worst case)
        _job_finish(job, "error", error=f"The approval failed unexpectedly: {e}")
