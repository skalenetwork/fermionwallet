#!/usr/bin/env python3
"""Install Safe v1.4.1 at its canonical addresses on the local anvil chain.

Safe{Wallet}, the Client Gateway and the Transaction Service only recognise a
Safe whose singleton, proxy factory and libraries sit at the addresses published
in safe-global/safe-deployments. On a fresh anvil chain nothing is there, so this
places the exact mainnet runtime bytecode (safe-1.4.1-code.json; every entry's
keccak matches the codeHash in safe-deployments) at those addresses with
anvil_setCode. Stdlib only.
"""
import json
import os
import sys
import urllib.request

RPC = os.environ.get("RPC_URL", "http://127.0.0.1:8545")
CODE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "safe-1.4.1-code.json")
# The constructor of Safe/SafeL2 sets threshold = 1 on the singleton so nobody can
# set it up; mirror that (slot 4 = threshold) since anvil_setCode skips constructors.
SINGLETONS = ("Safe", "SafeL2")
THRESHOLD_SLOT = "0x4"


def rpc(method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(RPC, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        out = json.load(resp)
    if "error" in out:
        raise RuntimeError(f"{method}: {out['error']}")
    return out["result"]


def main():
    with open(CODE) as f:
        contracts = json.load(f)
    for name, c in contracts.items():
        rpc("anvil_setCode", [c["address"], c["code"]])
        if name in SINGLETONS:
            rpc("anvil_setStorageAt", [c["address"], THRESHOLD_SLOT, "0x" + "00" * 31 + "01"])
        if rpc("eth_getCode", [c["address"], "latest"]).lower() != c["code"].lower():
            sys.exit(f"install failed for {name}")
    print(f"installed {len(contracts)} Safe v1.4.1 contracts at canonical addresses")


if __name__ == "__main__":
    main()
