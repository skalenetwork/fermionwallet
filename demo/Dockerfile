# FermionWallet self-contained demo.
# Build from the REPO ROOT:  docker build -f demo/Dockerfile -t fermionwallet-demo .
# Run:                       docker run --rm -p 8080:8080 -p 8545:8545 fermionwallet-demo
# Then open http://localhost:8080
# DEMO_MODE=wallet runs it as the chain of the Safe{Wallet} stack (demo/wallet).
FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Foundry (anvil testnet + forge script driver + cast), pinned so a release tag
# always rebuilds the same demo. Bump deliberately, together with CI.
ARG FOUNDRY_VERSION=v1.8.3
RUN curl -fsSL https://foundry.paradigm.xyz | bash \
    && /root/.foundry/bin/foundryup --install "${FOUNDRY_VERSION}"
ENV PATH="/root/.foundry/bin:${PATH}"

WORKDIR /app

# Contracts first (better layer caching), compiled at image build time.
# Tests are skipped: the demo never runs them, and forge preprocesses test files
# into a temporary foundry-pp/DeployHelper*.sol that is gone after the build, so
# every later `forge script` would warn about "artifacts built from source files
# that no longer exist".
COPY contracts/ contracts/
RUN cd contracts && forge build --skip test

COPY demo/ demo/
RUN chmod +x demo/entrypoint.sh

EXPOSE 8080 8545
ENTRYPOINT ["/app/demo/entrypoint.sh"]
