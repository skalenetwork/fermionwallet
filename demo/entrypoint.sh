#!/bin/sh
set -e

echo "[demo] starting anvil testnet (chain 31337) ..."
anvil --host 0.0.0.0 --port 8545 --chain-id 31337 --silent &

until cast chain-id --rpc-url http://127.0.0.1:8545 >/dev/null 2>&1; do
  sleep 0.3
done

echo "[demo] deploying Safe v1.5.0 + FermionWalletGuard + registering XMSS key ..."
cd /app/contracts
mkdir -p demo-state
forge script script/Demo.s.sol:Demo -s "setup()" \
  --rpc-url http://127.0.0.1:8545 --broadcast -vv | grep -E "DEMO_READY|Error" || true

if [ ! -f demo-state/deployment.json ]; then
  echo "[demo] FATAL: setup failed"; exit 1
fi

echo "[demo] ready — UI on port 8080, JSON-RPC on port 8545"
exec python3 /app/demo/server.py
