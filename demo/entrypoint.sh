#!/bin/sh
set -e

# DEMO_MODE=standalone (default): one container, Safe v1.5.0 2-of-3, own dashboard.
# DEMO_MODE=wallet: the chain + FermionGuard Safe App for the real Safe{Wallet}
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

# With a real device (USB or Speculos) the key that will sign is the one generated
# on the device, so the setup must register *its* root and SEED. Ask it before
# deploying; the reference key is only right when nothing but the simulator signs.
case "${LEDGER_TRANSPORT:-simulator}" in
  usb|hid|ledger|speculos|emulator)
    echo "[demo] reading the public key from the Ledger ..."
    # Speculos starts in parallel with this container and takes a few seconds to
    # accept APDUs, so wait for it. The assignment is what carries python's exit
    # status: `eval "$(...)"` would report eval's, so a device that never answered
    # would leave the variables unset, register the reference key, and hand every
    # approval to the Guard with the wrong root — the failure this exists to avoid.
    KEY=""
    i=0
    while [ "$i" -lt 60 ]; do
      if KEY="$(python3 /app/demo/ledger_device.py key 2>/dev/null)" && [ -n "$KEY" ]; then
        break
      fi
      KEY=""
      i=$((i + 1))
      sleep 1
    done
    if [ -z "$KEY" ]; then
      echo "[demo] FATAL: no Ledger answered. Is the app open (USB) or Speculos running?"
      exit 1
    fi
    eval "$KEY"
    export DEVICE_XMSS_ROOT DEVICE_XMSS_SEED
    echo "[demo] device key ${DEVICE_XMSS_ROOT} (admin ${DEVICE_ADMIN_ADDRESS})"
    ;;
esac

if [ "$DEMO_MODE" = "wallet" ]; then
  echo "[demo] installing Safe v1.4.1 at canonical addresses ..."
  python3 /app/demo/wallet/install_safe_contracts.py
  echo "[demo] deploying the demo Safe (SafeL2 1.4.1) + FermionGuard + registering XMSS key ..."
  SETUP="deployWallet()"
else
  echo "[demo] deploying Safe v1.5.0 + FermionGuard + registering XMSS key ..."
  SETUP="deploy()"
fi
forge script script/Demo.s.sol:Demo -s "$SETUP" \
  --rpc-url http://127.0.0.1:8545 --broadcast -vv | grep -E "DEMO_READY|Error" || true

if [ ! -f demo-state/deployment.json ]; then
  echo "[demo] FATAL: setup failed"; exit 1
fi

# LEDGER_TRANSPORT picks the device: "usb" a physical Ledger, "speculos" the same
# app in Ledger's emulator, "simulator" (default) the Python stand-in.
case "${LEDGER_TRANSPORT:-simulator}" in
  usb|hid|ledger)
    echo "[demo] using a physical Ledger over USB — open the FermionGuard app on it"
    ;;
  speculos|emulator)
    echo "[demo] using the FermionGuard app in Speculos at ${SPECULOS_APDU_URL:-tcp://127.0.0.1:9999}"
    ;;
  *)
    echo "[demo] starting the simulated FermionGuard Ledger (device API on 127.0.0.1:9999) ..."
    rm -f demo-state/ledger-device.json  # fresh device counter for a fresh chain
    python3 /app/demo/ledger_sim.py &
    until curl -fsS http://127.0.0.1:9999/screen >/dev/null 2>&1; do
      sleep 0.3
    done
    ;;
esac

echo "[demo] ready — UI on port 8080, JSON-RPC on port 8545"
exec python3 /app/demo/server.py
