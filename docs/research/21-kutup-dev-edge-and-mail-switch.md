# kutup.dev: mail MX and edge switch (2026-11-24)

An operations record: what changed on kutup.dev, what went wrong on the way,
why, and what is left. Current behaviour is in
[`../self-hosting.md`](../self-hosting.md) ("Moving MX to Kutup", "Koru edge
(optional)") and [`../architecture.md`](../architecture.md) ("Edge and
serving").

## 1. Mail: kutup.dev's MX moved to Kutup

**Problem.** Mail sent to `admin@kutup.dev` never arrived. Stalwart's log
showed no delivery at all, only scanners.

**Cause.** kutup.dev's MX still pointed at Cloudflare Email Routing
(`route{1,2,3}.mx.cloudflare.net`), the setup from before Kutup had Mail.
The planned last step of the mail rollout, the MX switch, had never been
done. The SPF record named only Cloudflare (`include:_spf.mx.cloudflare.net`),
the two DKIM keys Stalwart had made on 2026-10-10 were not published, and
there was no DMARC record. Outside mail therefore went to Cloudflare, and
mail Kutup sent as `@kutup.dev` would have failed SPF and carried no DKIM.

**Fix** (Cloudflare DNS, done by the operator; `scripts/check-mail-ready.sh`
before and after):
- SPF: `v=spf1 ip4:95.217.238.230 -all`.
- DKIM: `v1-ed25519-20261010._domainkey` and `v1-rsa-20261010._domainkey`,
  read from Stalwart (`stalwart-cli get Domain <id>`, its DNS zone file);
  the keys survived the wipe in the `stalwart_data` volume.
- DMARC: `_dmarc` → `v=DMARC1; p=none; rua=mailto:postmaster@kutup.dev`.
- Cloudflare Email Routing disabled (it locks the MX and adds its own
  records), then `MX 10 mail.kutup.dev`.
- Not published: the SRV records Stalwart also lists (CalDAV, CardDAV, IMAP,
  POP, JMAP, autoconfig): Kutup does not expose those
  ([`../roadmap.md`](../roadmap.md): no DAV, as Proton).

**Check.** A, PTR, MX, SPF, DKIM, DMARC and WKD pass. A resolver that had
cached the earlier "no such record" kept reporting DKIM and DMARC missing for
some minutes; Cloudflare's own name servers and public resolvers had them.
An inbound test message from an outside account is still to be sent.

## 2. Edge: nginx replaced by Koru

**Why.** Koru (a Rust WAF and reverse proxy on Pingora, the operator's own
project) adds request inspection and keeps link secrets out of every log
line, error lines included. It is opt-in: self-hosters keep nginx until Koru
is published with a licence.

**Before the switch.** Koru's author ran all of Kutup's single-server browser
suites and the two-server federation suite through Koru in detect and in
block mode. One false positive was fixed in Koru: a tus upload's
`Upload-Metadata` header holds base64, and one value happened to contain the
letters of a scanner's name. A lane run then had Koru as the only edge in
block mode: 0 blocks in about 29,300 requests; Drive 29/29, Chat and
meetings with the SFU, specs 39, 114 and 156, and STUN and an authenticated
TURN allocation through the pass-through on 443. That run also found spec 41
reading an old request shape; CI had never run it, having no SFU.

**What the switch had to get right**, found before touching kutup.dev
(an independent review of the plan, then a rehearsal of the in-place switch
on a lane; PR #445):
1. **The overlay files had to be on the server before `.env` named them.** A
   `COMPOSE_FILE` naming a missing file makes every `docker compose` call
   fail, the nightly backup included. So the release with the overlay was
   deployed first on the nginx path.
2. **kutup.dev would have gone dark.** Production's ports 80 and 443 came from
   `docker-compose.acme.yml` (`ports: !override`), which the switch removes.
   The Koru overlay publishes `KUTUP_HTTP_PORT` and `KUTUP_HTTPS_PORT`,
   unset on production, so Koru would have listened on 38080 and 38443. The
   switch sets both.
3. **The running nginx kept the ports.** The overlay disables nginx with a
   profile, and Compose neither stops a running container of a disabled
   service nor counts it as an orphan. The deploy now removes it
   (`docker compose rm -sf nginx`, then `up --remove-orphans`).
4. **Key permissions.** Koru and, with the overlay, coturn run as UID 65532;
   the key was root-only. It is now owned by 65532, still 0600; LiveKit and
   Stalwart's setup read it as root.

**What went wrong during the switch itself.**
- **The deploy script shifted the Koru arguments** (PR #447). The first dry
  run against kutup.dev showed the image id as the image and the Koru commit
  as the id. `ssh` joins its arguments into one command line that the
  server's shell splits again, so the empty `KUTUP_DEPLOY_HOSTS` argument
  vanished and every later one moved one place. On the nginx path that empty
  argument came last, so it had never mattered; the lane rehearsal used a
  stand-in `ssh` that kept arguments apart. The `.env` backup was restored
  at once, so production never ran with the wrong values. The fix quotes
  each argument for the server's shell (`printf %q`).
- **The deploy stopped at its last check.** It waits for Stalwart's setup to
  report its mail check after the start; redeploying the same release does
  not recreate that container, so no new line came. Restarting it gave the
  check, which passed. Harmless, but a redeploy of an unchanged tag will
  stop there again.

**After the switch** (detect mode, the existing certificate files):
- all 11 app hosts, `editor.` and `sfu.` answer; HTTP redirects with 308;
- both CSP headers come through from the frontend container unchanged; HSTS,
  `nosniff` and `Referrer-Policy` are set by Koru;
- STUN Binding Success over TLS on 443 for `turn.` (coturn) and `sfu-turn.`
  (LiveKit); coturn's new TLS port 5350 is not reachable from outside;
- mail check, storage check, MX, SPF and WKD pass; 0 backend error lines;
- Koru's events in the first half hour: 8 path probes from one scanner
  range, none from users.

**Rollback** (from `/opt/kutup`; the backup is `.env.bak-pre-koru`): remove
the `koru` container, restore the edge lines of `.env` from the backup, and
`docker compose up -d --wait --remove-orphans` ([`../self-hosting.md`](../self-hosting.md)).

## 3. Left to do

- **Certificate renewal stopped with the switch.** It ran through
  `docker-compose.acme.yml` and nginx's ACME webroot, which Koru does not
  serve. The certificate on kutup.dev is valid until 2027-01-20. The fix
  keeps certbot rather than moving to Koru's own ACME, because three other
  services read the same files: with Koru's ACME, coturn, LiveKit and
  Stalwart would all have to read Koru's state volume, and Stalwart's setup
  would have to change. Instead `docker-compose.koru-certbot.yml` runs the
  same certbot (same account and volumes), Koru answers its HTTP-01
  challenges from the shared webroot (on every site, since Let's Encrypt
  follows Koru's redirect to HTTPS, and on a plain-HTTP catch-all for the
  TURN names, which have no site), certbot writes the key owned by Koru's
  user, and a systemd path unit reloads Koru and restarts the relays when
  the certificate changes; Stalwart already watches the files. To do on
  kutup.dev: add the file to `COMPOSE_FILE`, install the path unit, and run
  `certbot renew --dry-run` against the staging service.
- **Block mode** after some days in detect mode, once the events show only
  attacks. `/api/csp-report` bodies (URLs and script samples) are a likely
  false positive to check first.
- **Koru serving the app files**, which retires the frontend container's
  nginx: Koru now has the per-response nonce, body substitution and
  precompressed files this needs; Kutup's browser suites have not yet run
  against it.
- **The deploy's mail check** on a redeploy of an unchanged release (above).
- An inbound test message to `admin@kutup.dev`.
