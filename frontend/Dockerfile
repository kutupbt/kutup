# The Kutup web apps: account, drive, chat and the OnlyOffice sandbox, each
# served on its own hostname by one nginx (frontend/docker/). Build context is
# the repository root, so the WASM crates compile here.
ARG KUTUP_OFFICE_ASSETS_IMAGE=ghcr.io/kutupbt/kutup-office-assets@sha256:0a88835f0f7cd245a82bfd5477fb889cb239dff6030e9dcd857fe399958804d8

FROM ${KUTUP_OFFICE_ASSETS_IMAGE} AS office-assets

FROM rust:1.96-bookworm AS browser-wasm

RUN apt-get update \
    && apt-get install -y --no-install-recommends protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*
RUN cargo install wasm-bindgen-cli --version 0.2.126 --locked

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates crates
COPY scripts/build-chat-wasm.sh scripts/build-chat-wasm.sh
COPY scripts/build-crypto-wasm.sh scripts/build-crypto-wasm.sh
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true
RUN --mount=type=cache,id=kutup-browser-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=kutup-browser-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=kutup-browser-root-target,target=/src/target,sharing=locked \
    --mount=type=cache,id=kutup-browser-chat-target,target=/src/crates/kutup-chat-core/target,sharing=locked \
    rustup target add wasm32-unknown-unknown \
    && bash scripts/build-crypto-wasm.sh \
    && bash scripts/build-chat-wasm.sh

FROM node:22-alpine AS builder

# The version in package.json's `packageManager` field.
RUN npm install -g pnpm@10.28.2

WORKDIR /app/frontend
COPY frontend .
RUN --mount=type=cache,id=kutup-pnpm-store,target=/root/.local/share/pnpm/store,sharing=locked \
    pnpm install --frozen-lockfile
COPY --from=browser-wasm /src/frontend/wasm ./wasm
COPY --from=office-assets /opt/kutup/onlyoffice/ ./apps/office/public/onlyoffice/
RUN o=apps/office/public/onlyoffice \
    && test -s $o/dist/v9/web-apps/apps/api/documents/api.js \
    && test -s $o/dist/v9/web-apps/apps/common/main/resources/img/header/header-logo_s.svg \
    && test -s $o/dist/x2t/x2t.wasm \
    && test -s $o/templates/oodoc_base.js \
    && test -s $o/LICENSES/ONLYOFFICE-ADDITIONAL-TERMS.md \
    && grep -Fx 'kutup-v9.4.0.131.2' $o/dist/v9/.version \
    && grep -Fx 'kutup-v9.4.0.131.1' $o/dist/x2t/.version \
    && grep -Fx '2025.6.0' $o/templates/.version
RUN pnpm run build \
    && mkdir -p /out \
    && for app in account drive chat maps photos office; do cp -r apps/$app/dist /out/$app; done

FROM nginx:1.29-alpine
COPY --from=builder /out /usr/share/nginx/html
COPY frontend/docker/40-kutup-hosts.sh /docker-entrypoint.d/40-kutup-hosts.sh
RUN chmod +x /docker-entrypoint.d/40-kutup-hosts.sh && rm /etc/nginx/conf.d/default.conf
EXPOSE 80
