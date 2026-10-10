# Applies Kutup's Stalwart settings (setup.sh). Stalwart's CLI image has no
# shell, so its static binary runs here beside one.
FROM stalwartlabs/cli:1.0.12 AS cli

FROM alpine:3.22
COPY --from=cli /usr/local/bin/stalwart-cli /usr/local/bin/stalwart-cli
COPY plan.ndjson certificate.ndjson reload.ndjson reload-certificates.ndjson setup.sh /etc/kutup-stalwart/
# Root, to hand Stalwart (uid 2000) a readable copy of the root-only
# certificate key; it publishes nothing and talks only to Stalwart.
ENTRYPOINT ["/bin/sh", "/etc/kutup-stalwart/setup.sh"]
