# The Kutup web apps (account, drive, chat, maps, photos, office, contacts) and the
# OnlyOffice editor sandbox, each
# served on its own hostname by one nginx (frontend/docker/). Build context is
# the repository root, so the WASM crates compile here.
ARG KUTUP_OFFICE_ASSETS_IMAGE=ghcr.io/kutupbt/kutup-office-assets@sha256:724ae7164bdfa79018a70b59fa7e84b96e300b05995183584bb5055fa7f8282a

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
# The workspace sources are touched before compiling, as Dockerfile.server
# does: Cargo decides what to rebuild by file time, the target directories
# below are a cache shared by every build on the machine, and copied sources
# can look older than artifacts another checkout left there. Without this the
# image can silently ship that other checkout's WASM. Dependencies stay cached.
RUN --mount=type=cache,id=kutup-browser-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=kutup-browser-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=kutup-browser-root-target,target=/src/target,sharing=locked \
    --mount=type=cache,id=kutup-browser-chat-target,target=/src/crates/kutup-chat-core/target,sharing=locked \
    rustup target add wasm32-unknown-unknown \
    && find crates -type f -exec touch {} + \
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
COPY --from=office-assets /opt/kutup/onlyoffice/ ./apps/editor/public/onlyoffice/
RUN o=apps/editor/public/onlyoffice \
    && test -s $o/dist/v9/web-apps/apps/api/documents/api.js \
    && test -s $o/dist/v9/web-apps/apps/common/main/resources/img/header/header-logo_s.svg \
    && test -s $o/dist/x2t/x2t.wasm \
    && test -s $o/templates/oodoc_base.js \
    && test -s $o/LICENSES/ONLYOFFICE-ADDITIONAL-TERMS.md \
    && grep -Fx 'kutup-v9.4.0.131.3' $o/dist/v9/.version \
    && grep -Fx 'kutup-v9.4.0.131.1' $o/dist/x2t/.version \
    && grep -Fx '2025.6.0' $o/templates/.version
RUN pnpm run build \
    && mkdir -p /out \
    && for app in account drive chat maps photos office contacts editor; do cp -r apps/$app/dist /out/$app; done

FROM nginx:1.29-alpine
COPY --from=builder /out /usr/share/nginx/html
COPY frontend/docker/40-kutup-hosts.sh /docker-entrypoint.d/40-kutup-hosts.sh
RUN chmod +x /docker-entrypoint.d/40-kutup-hosts.sh && rm /etc/nginx/conf.d/default.conf
EXPOSE 80
