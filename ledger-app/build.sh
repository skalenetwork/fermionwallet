#!/usr/bin/env bash
# Build the FermionGuard Ledger app in Ledger's official container and put the ELF
# where the demo and Speculos expect it: build/<target>/bin/app.elf.
#
#   ./build.sh              # Nano S Plus (what the demo's Speculos profile runs)
#   ./build.sh nanox        # Nano X
#
# Nothing but docker is needed on the host — the toolchain, the BOLOS SDKs and
# cargo-ledger all live in the image.
set -euo pipefail

DEVICE="${1:-nanosplus}"
IMAGE="${LEDGER_APP_BUILDER:-ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Speculos and Ledger's tooling name the Nano S Plus target "nanos2".
case "$DEVICE" in
  nanosplus) OUT_DIR="nanos2" ;;
  nanox) OUT_DIR="nanox" ;;
  *) echo "unsupported device: $DEVICE (nanosplus, nanox)" >&2; exit 2 ;;
esac

docker run --rm -v "$HERE":/app -w /app "$IMAGE" \
  bash -lc "export PATH=/opt/.cargo/bin:\$PATH && cargo ledger build $DEVICE"

# The container writes as root; the copy and the ownership fix both happen there so
# the host needs no privileges.
docker run --rm -v "$HERE":/app -w /app "$IMAGE" bash -lc "
  mkdir -p build/$OUT_DIR/bin &&
  cp target/$DEVICE/release/fermionguard build/$OUT_DIR/bin/app.elf &&
  chown -R $(id -u):$(id -g) build target"

echo "built: ledger-app/build/$OUT_DIR/bin/app.elf"
