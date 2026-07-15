FROM rust:1.96-bookworm AS chat-wasm

RUN apt-get update \
    && apt-get install -y --no-install-recommends protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*
RUN cargo install wasm-bindgen-cli --version 0.2.126 --locked

WORKDIR /src
COPY Cargo.toml Cargo.toml
COPY crates/kutup-chat-proto crates/kutup-chat-proto
COPY crates/kutup-chat-core crates/kutup-chat-core
COPY scripts/build-chat-wasm.sh scripts/build-chat-wasm.sh
COPY frontend/public frontend/public
RUN rustup target add wasm32-unknown-unknown \
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
COPY --from=chat-wasm /src/frontend/public/chat-wasm ./public/chat-wasm
RUN pnpm run build:web

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
