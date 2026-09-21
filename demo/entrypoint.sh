#!/bin/sh
set -e

# DEMO_MODE=standalone (default): one container, Safe v1.5.0 2-of-3, own dashboard.
# DEMO_MODE=wallet: the chain + FermionWallet Safe App for the real Safe{Wallet}
#   stack (demo/wallet/docker-compose.yml) — canonical Safe v1.4.1, SafeL2 1-of-1,
#   blocks mined every second so the Safe Transaction Service indexes steadily.
DEMO_MODE="${DEMO_MODE:-standalone}"

echo "[demo] starting anvil testnet (chain 31337, mode ${DEMO_MODE}) ..."
if [ "$DEMO_MODE" = "wallet" ]; then
  anvil --host 0.0.0.0 --port 8545 --chain-id 31337 --block-time 1 --silent &
else
  anvil --host 0.0.0.0 --port 8545 --chain-id 31337 --silent &
fi

until cast chain-id --rpc-url http://127.0.0.1:8545 >/dev/null 2>&1; do
  sleep 0.3
done

cd /app/contracts
mkdir -p demo-state
rm -f demo-state/deployment.json
if [ "$DEMO_MODE" = "wallet" ]; then
  echo "[demo] installing Safe v1.4.1 at canonical addresses ..."
  python3 /app/demo/wallet/install_safe_contracts.py
  echo "[demo] deploying the demo Safe (SafeL2 1.4.1) + FermionWalletGuard + registering XMSS key ..."
  SETUP="setupWallet()"
else
  echo "[demo] deploying Safe v1.5.0 + FermionWalletGuard + registering XMSS key ..."
  SETUP="setup()"
fi
forge script script/Demo.s.sol:Demo -s "$SETUP" \
  --rpc-url http://127.0.0.1:8545 --broadcast -vv | grep -E "DEMO_READY|Error" || true

if [ ! -f demo-state/deployment.json ]; then
  echo "[demo] FATAL: setup failed"; exit 1
fi

echo "[demo] starting the simulated FermionWallet Ledger (device API on 127.0.0.1:9999) ..."
rm -f demo-state/ledger-device.json  # fresh device counter for a fresh chain
python3 /app/demo/ledger_sim.py &
until curl -fsS http://127.0.0.1:9999/screen >/dev/null 2>&1; do
  sleep 0.3
done

echo "[demo] ready — UI on port 8080, JSON-RPC on port 8545"
exec python3 /app/demo/server.py
