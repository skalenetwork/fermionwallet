# Safe{Wallet} web UI (the real, open-source safe-wallet-web) pre-built for the
# local FermionGuard demo stack, served by the stack's reverse proxy.
#
# The upstream image compiles the Next.js static export at container start
# (minutes, several GB of RAM). Building it once here makes `docker compose up`
# start in seconds. NEXT_PUBLIC_* values are baked into the export, so the
# gateway URL fixes the host port the stack is served on (8000).
#
# Build from the REPO ROOT:
#   docker build -f demo/wallet/ui.Dockerfile -t fermionguard-demo-wallet .
ARG SAFE_WALLET_VERSION=v1.91.0
FROM ghcr.io/safe-global/safe-wallet-web:${SAFE_WALLET_VERSION} AS build

WORKDIR /app/apps/web
ENV NEXT_PUBLIC_IS_PRODUCTION=true \
    NEXT_PUBLIC_GATEWAY_URL_PRODUCTION=http://localhost:8000/cgw \
    NEXT_PUBLIC_DEFAULT_MAINNET_CHAIN_ID=31337 \
    NEXT_PUBLIC_SAFE_VERSION=1.4.1 \
    NEXT_PUBLIC_IS_OFFICIAL_HOST=false \
    NEXT_PUBLIC_BRAND_NAME="Safe{Wallet} · FermionGuard demo" \
    NODE_OPTIONS=--max-old-space-size=8192
# The one source change: show small balances by default. A local chain has no
# price feed, so every token is worth "$0" and would otherwise hide as dust.
RUN sed -i 's/^  hideDust: true,/  hideDust: false,/' src/store/settingsSlice.ts \
    && grep -q '^  hideDust: false,' src/store/settingsSlice.ts
RUN yarn build &&rm -f out/*.map out/_next/static/chunks/*.map out/_next/static/chunks/*/*.map

FROM nginx:1.27-alpine
COPY --from=build /app/apps/web/out /usr/share/nginx/html
# Chain / currency / Safe App icons referenced by the config service (MEDIA_URL).
COPY demo/wallet/media /usr/share/nginx/html/media
COPY demo/wallet/nginx.conf /etc/nginx/nginx.conf
EXPOSE 8000
