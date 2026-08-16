ARG KUTUP_OFFICE_ASSETS_IMAGE=ghcr.io/kutupbt/kutup-office-assets@sha256:c3142b6f74a22f6c5db14256be59e9c160e25b77234b069c0cd889405f2bd8b3

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

FROM node:20-alpine AS builder

# Pin to the pnpm version declared in package.json's `packageManager` field.
# `corepack prepare pnpm@latest --activate` was hitting an npm-registry tag
# lookup that fails inside this builder; npm-installing the exact version
# bypasses corepack's signature/tag-lookup path entirely.
RUN npm install -g pnpm@9.1.1

WORKDIR /app
COPY frontend/package.json frontend/pnpm-lock.yaml* ./
RUN pnpm install --frozen-lockfile

COPY frontend .
COPY --from=browser-wasm /src/frontend/public/crypto-wasm ./public/crypto-wasm
COPY --from=browser-wasm /src/frontend/public/chat-wasm ./public/chat-wasm
COPY --from=office-assets /opt/kutup/onlyoffice/ ./public/onlyoffice/
RUN test -s public/onlyoffice/dist/v9/web-apps/apps/api/documents/api.js \
    && test -s public/onlyoffice/dist/v9/web-apps/apps/common/main/resources/img/header/header-logo_s.svg \
    && test -s public/onlyoffice/dist/x2t/x2t.wasm \
    && test -s public/onlyoffice/templates/oodoc_base.js \
    && test -s public/onlyoffice/LICENSES/ONLYOFFICE-ADDITIONAL-TERMS.md \
    && grep -Fx 'v9.2.0.119+5' public/onlyoffice/dist/v9/.version \
    && grep -Fx 'v7.3+1' public/onlyoffice/dist/x2t/.version \
    && grep -Fx '2025.6.0' public/onlyoffice/templates/.version
RUN pnpm run build:web

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
