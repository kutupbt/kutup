# Koru as Kutup's edge proxy (docker-compose.koru.yml; docs/self-hosting.md,
# "Koru edge (optional)"). Koru's sources are not in this repository: the
# `koru` build context is one commit of them (scripts/build-koru-image.sh).
# The proxy is built as Koru's own Dockerfile builds its `lite` target (no
# admin interface); beside it the image carries a static busybox, for the
# start script that writes koru.toml from Kutup's settings (render.sh) and
# for the health check, which the distroless base has no tool for.

ARG RUST_IMAGE=rust:1.99-slim-trixie
ARG BUSYBOX_IMAGE=busybox:1.37.0-musl
ARG RUNTIME_IMAGE=gcr.io/distroless/cc-debian13:nonroot

FROM ${RUST_IMAGE} AS build
# zlib-ng (through Pingora) builds with cmake and a C++ compiler.
RUN apt-get update && apt-get install -y --no-install-recommends cmake g++ make && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY --from=koru Cargo.toml Cargo.lock clippy.toml ./
COPY --from=koru crates crates
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target,id=kutup-koru-target \
    cargo build --release --locked -p koru-cli --no-default-features && cp target/release/koru /koru
# State (ACME account and certificates) and the written configuration,
# owned by the runtime user (65532 in distroless).
RUN mkdir -p /out/var/lib/koru/acme /out/etc/koru && chown -R 65532:65532 /out/var/lib/koru /out/etc/koru

FROM ${BUSYBOX_IMAGE} AS busybox
# Its tools as links, for the start script (tr, sed) and the health check (wget).
RUN mkdir /tools && /bin/busybox --install -s /tools

FROM ${RUNTIME_IMAGE}
COPY --from=busybox /bin/busybox /bin/busybox
COPY --from=busybox /tools /usr/local/busybox
ENV PATH=/usr/local/bin:/usr/local/busybox
COPY --from=build /koru /usr/local/bin/koru
COPY --from=build /out/var/lib/koru /var/lib/koru
COPY --from=build /out/etc/koru /etc/koru
COPY render.sh /usr/local/lib/kutup-koru/render.sh
USER 65532:65532
EXPOSE 8080 8443
ENTRYPOINT ["/bin/busybox", "sh", "/usr/local/lib/kutup-koru/render.sh"]
CMD ["run"]
