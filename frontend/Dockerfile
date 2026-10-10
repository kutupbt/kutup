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
# The OnlyOffice client and x2t move to directories named for their
# versions, so their files can be cached for good: a new build of either is
# a new URL (docs/research/18-web-performance.md). Only the bridge pages
# name those directories.
RUN o=apps/editor/public/onlyoffice \
    && client=$(cat $o/dist/v9/.version) && x2t=x2t-$(cat $o/dist/x2t/.version) \
    && mv $o/dist/v9 "$o/dist/$client" && mv $o/dist/x2t "$o/dist/$x2t" \
    && sed -i "s#dist/v9/#dist/$client/#g" $o/inner.html \
    && sed -i "s#dist/x2t/#dist/$x2t/#g" $o/x2t.html $o/inner.html \
    && ! grep -n 'dist/v9/\|dist/x2t/' $o/inner.html $o/x2t.html \
    && grep -q "dist/$client/" $o/inner.html && grep -q "dist/$x2t/" $o/x2t.html
RUN pnpm run build \
    && mkdir -p /out \
    && for app in account drive chat maps photos office contacts editor; do cp -r apps/$app/dist /out/$app; done \
    && find /out -name '*.map' -delete

# Every text file and WASM over 1 KB is stored compressed beside itself,
# gzip and brotli, and nginx serves those as they are (gzip_static,
# brotli_static): nothing is compressed per request. Brotli copies the
# OnlyOffice image already ships are kept; its help pages get gzip only.
FROM node:22-alpine AS compress
RUN apk add --no-cache brotli
COPY --from=builder /out /out
COPY frontend/docker/precompress.sh /precompress.sh
RUN sh /precompress.sh /out

# Alpine's nginx, for its packaged brotli module (the nginx.org image has
# none).
FROM alpine:3.23
RUN apk add --no-cache nginx nginx-mod-http-brotli \
    && mkdir -p /run/nginx /etc/nginx/conf.d \
    && rm -f /etc/nginx/http.d/default.conf
COPY --from=compress /out /usr/share/nginx/html
COPY frontend/docker/nginx.conf /etc/nginx/nginx.conf
COPY frontend/docker/40-kutup-hosts.sh /usr/local/bin/kutup-hosts.sh
COPY frontend/docker/entrypoint.sh /usr/local/bin/kutup-entrypoint.sh
RUN chmod +x /usr/local/bin/kutup-hosts.sh /usr/local/bin/kutup-entrypoint.sh && nginx -t
EXPOSE 80
STOPSIGNAL SIGQUIT
ENTRYPOINT ["/usr/local/bin/kutup-entrypoint.sh"]
