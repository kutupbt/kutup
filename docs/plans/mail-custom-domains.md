# Mail: custom domains, following Proton

Status: decided (2026-10-20): the main session's review and the user's
answers (see Decisions). Second session (server); third session (web UI,
later). Nothing is built yet.

- Decided: custom domains move up and run alongside groups and Calendar,
  following Proton (user, 2026-10-20).
- Copies: Proton WebClients:
  - `packages/components/containers/domains/` (`DomainModal`, `VerifySection`,
    `MXSection`, `SPFSection`, `DKIMSection`, `DMARCSection`, `CatchAllModal`,
    `DeleteDomainModal`, `DomainsSection`);
  - `packages/shared/lib/interfaces/Domain.ts` (states);
  - `packages/shared/lib/api/domains.ts` (routes);
  - `packages/account/domains/actions.ts`, `packages/account/addresses/actions.ts`;
  - `packages/shared/lib/organization/domain.ts` (`getIsDomainActive`).
- Proton's server isn't public. Where only the server can answer (the
  verification code's format, DKIM hostnames, rotation, what an unverified
  domain's addresses do), this note says so and proposes Kutup's rule.
- Related:
  - [`mail-address-keys.md`](mail-address-keys.md): "Aliases and custom
    domains are Phase E";
  - [`mail-parity.md`](mail-parity.md), row "Custom domains … catch-all";
  - [`mail-forwarding.md`](mail-forwarding.md), "ARC" (DMARC for forwarded
    mail).

## What Proton has

### The wizard

`DomainModal` has seven tabs, in this order (`STEPS`, `DomainModal.tsx:48-56`):

1. **Domain:** `POST domains {Name}`. A name starting with `www.` gets a
   warning.
2. **Verify:** a TXT record at `@` whose value is the domain's `VerifyCode`,
   made by the server. "Verify" is `GET domains/{id}?Refresh=1`; there is no
   separate verify route.
   - Every later tab stays disabled until `VerifyState` is `GOOD`.
   - Failure messages: "Verification did not succeed, please try again in an
     hour", and for a wrong code, "…It can take up to 24 hours for changes
     to take effect".
   - The record must stay: "do not remove this TXT record as it is needed to
     confirm that you continue to own the domain".
3. **Addresses**, **before** MX on purpose: someone moving from another
   provider adds their addresses first, so nothing bounces when MX switches.
4. **MX:** `mail.protonmail.ch` priority 10 and `mailsec.protonmail.ch`
   priority 20. "Delete any other MX records or make sure Proton Mail's
   Priority is the lowest number."
5. **SPF:** `v=spf1 include:_spf.protonmail.ch ~all`, with a hint to merge
   into an existing record, since a domain may have only one.
6. **DKIM:** three CNAME records the server lists (`Config[]` of `{Hostname,
   CNAME}`), pointing at keys Proton hosts; "all 3 of the following".
   - These are per-domain targets with per-domain keys (`DKIM.Config[].Key`),
     e.g. `protonmail.domainkey.d<id>.domains.proton.ch`. Proton Pass's alias
     domains differ: fixed `dkim._domainkey`, `dkim02`, `dkim03` targets
     under `alias.proton.me` (`DomainUtils.tsx:55-60`). Kutup follows Mail's.
7. **DMARC:** `_dmarc` TXT `v=DMARC1; p=quarantine`, editable, with
   `quarantine`, `reject` and `none` explained.

The modal never checks DNS itself: each record's state changes only when the
server refreshes it ("Refresh status" refreshes all).

### States (`Domain.ts`)

| | Values |
| --- | --- |
| `DOMAIN_STATE` | `DEFAULT` 0 (not yet verified, or deactivated), `VERIFIED` 1, `WARN` 2 ("backward DNS change after active") |
| `VERIFY_STATE` | `DEFAULT` 0, `EXIST` 1 (a TXT that doesn't match), `GOOD` 2 |
| `MX_STATE` | `DEFAULT` 0, `NO_US` 1, `INC_US` 2 (ours, wrong priority), `GOOD` 3, `BACKUP` 4 (our backup MX first; warn) |
| `SPF_STATE` | `DEFAULT` 0 (none), `ONE` 1 (a record without us), `MULT` 2 (several), `GOOD` 3 |
| `DKIM_STATE` | `DEFAULT` 0, 1–2 (record found, wrong), `ERROR` 3, `GOOD` 4, `DELEGATED` 5 (turned off by the user through DNS), `WARNING` 6 |
| `DMARC_STATE` | `DEFAULT` 0, `ONE` 1 (wrong format), `MULT` 2, `GOOD` 3, `RELAXED` 4 (good, relaxed DKIM) |

DKIM's lifecycle, from the alerts:
- `WARNING`: "We detected a problem with your DNS configuration… If the
  problem persists, we will have to switch DKIM signing off."
- `ERROR`: "We stopped DKIM signing due to problems with your DNS
  configuration."

### Addresses, catch-all, limits, removal

- **Usable domains.** A domain offers addresses while it is `VERIFIED` or
  `WARN` and meant for mail (`getIsDomainActive`): a warned domain keeps
  working.
- **Addresses.** Each address on a domain is created like any other: `POST
  addresses {Local, Domain, DisplayName}`, then its own key, a token
  encrypted to the user key, and a signed key list. An address without keys
  shows "Missing keys", with a repair action.
  - No key is ever per domain.
  - No WKD for custom domains in the client.
- **Catch-all.**
  - At most one address per domain (`PUT domains/{id}/catchall {AddressID |
    null}`).
  - The address must be enabled and receiving.
  - Only paid plans have it.
- **Limits.**
  - Per plan: `MaxDomains` and `MaxAddresses` (Free 0 domains and 1 address;
    Mail Plus 1 and 10; Family 5 and 75; Business 10 domains and 15 addresses
    per user).
  - "Add domain" is disabled at the limit.
- **Removal.** "If you delete this domain …, all the addresses associated
  with it will be disabled."
- **Not in the client:**
  - a banner for a mail domain that lost its TXT (only SSO domains have one);
  - MTA-STS and BIMI records;
  - what happens on a duplicate domain (another account's): it is a server
    error passed through.

## Kutup today

- One mail domain per server: `MAIL_DOMAIN` (= `CHAT_SERVER_NAME`). The
  following all compare against it:
  - the RCPT hook (`mail::resolve_target`, `local_address`);
  - sender folding (`sender_key`);
  - WKD;
  - Stalwart's single `Domain` upsert (`stalwart/plan.ndjson`).
- `mail_addresses` already holds several addresses per account (the model
  was made for Phase E). But the only address an account gets is its
  username's, and no route creates another (aliases aren't built).
- A key per address, the signed key list and `key_list_owed` exist
  ([`mail-address-keys.md`](mail-address-keys.md)).
- Stalwart signs outbound DKIM for `MAIL_DOMAIN` only, with keys it
  generated at setup. The operator publishes them from `dnsZoneFile`
  (`self-hosting.md`).
- Stalwart 0.16's registry can do the rest at runtime:
  - `Domain` objects carry `catchAllAddress` and `aliases`;
  - `DkimSignature` is per domain, with `selector`, `privateKey`, and manual
    or automatic management including rotation (`nextTransitionAt`).

## Settled (wipe-sensitive: fixed before anything is built)

These change stored bytes or what customers publish, so they are fixed now,
not left to the build:
- **DKIM targets are per domain from v1** (§4): customers publish
  `kutupN._domainkey.<domain>` → `<domain id>.kutupN._dk.<server>`, and those
  targets never change.
- **The canonical mail-address form** is its own function, not the account
  name rule (§0), and it is what keys and key lists bind.
- **Folding:** on custom domains, lowercase only (Proton's own rule,
  `WebClients shared/lib/helpers/email.ts:150-154`: "they also apply the
  default scheme in those cases"). Delivery strips a `+tag` first, as for
  the server's own addresses. The server's own domain keeps its `. _ -`
  folding.
- **The ownership code** is `kutup-verification=<26 base32 characters>`
  (16 random bytes). The same account re-adding the same name gets the same
  code back.
- **`mail_addresses.domain_id`:** a permanent domain id on every address;
  null means the server's own domain.
- **No WKD for custom domains in v1** (Proton has none; adding it later is
  additive).

## Proposal

### 0. Aliases and the address form

Custom-domain addresses are extra addresses, so an account first needs more
than its username's address, as Proton has.
- **Route:** `POST /api/mail/addresses {local, domainId | null}` creates an
  address. The client generates its key as now.
  - The server checks that the domain is the caller's and usable (`verified`
    or `warn`).
  - It checks that the key's user id is exactly the new address in its
    canonical form.
- **Aliases on the server's own domain** would share the username namespace
  (`account_names`: holds, renames, freed names). They are refused until that
  is designed, so §0 covers custom domains only.
- **The limit** counts the account's addresses in states `active` and
  `receiving` on every domain: its username address, custom-domain
  addresses, and addresses kept for rekeying.
- **Groups on custom domains** (distribution lists and shared mailboxes,
  `mail-groups.md`) are out of v1. Their addresses live on the server's
  domain.
- **The canonical form** gets its own function now:
  `kutup_crypto::mail_address::canonical`.
  - The local part may contain dot-atom characters (RFC 5322 atext and
    dots, no leading, trailing or double dot), at most 64 bytes, lowercase.
  - The domain is an IDNA A-label, lowercase.
  - `mail_key::canonical_address`, `MailAddressPrivateKeyV1` and
    `MailKeyListV1` use it in place of `named_share::canonical_account`,
    which allows no `.` and would refuse `john.doe@example.com`.
  - Every address that is valid today stays valid under it, so no stored
    key or key list changes.
  - Folding is a separate step, applied only for the server's own domain.

### 1. A domain belongs to an account

Kutup has no organisations yet, so a domain belongs to one permanent account
id. It moves to the organisation when Phase E brings organisations, as
Proton's.

```
mail_domains (
  id uuid,                      -- permanent; its base32 is the DKIM label
  user_id uuid,
  name text,                    -- lowercase, IDNA A-label, no trailing dot
  verify_code text,             -- reused when the same account re-adds
  state smallint,               -- Proton's DOMAIN_STATE: 0 default, 1 verified, 2 warn
  verify_state, mx_state, spf_state, dkim_state, dmarc_state  smallint,
  dkim_good_once boolean,
  approved_at timestamptz NULL,     -- in `admins approve` mode
  checked_at, verified_at, warned_at, failing_since timestamptz,
  catch_all_address_id uuid NULL
)
UNIQUE (user_id, name)
UNIQUE (name) WHERE state IN (1, 2)          -- one holder at a time
```

- Every state column stores Proton's numbers (the table above), so the web
  UI copies Proton's badges and texts one to one.
- `inactive` is `DOMAIN_STATE` 0 with `verified_at` set: once held, now not.

### 2. Adding and verifying

- **Add:** `POST /api/mail/domains {name}`.
  - The name is normalized: lowercase, IDNA, no trailing dot.
  - It is refused when it is:
    - the server's own domain or a subdomain of it;
    - a public suffix, ICANN and private sections both (the `psl` list);
    - an IP address;
    - longer than 253 bytes.
  - The `www.` warning is the client's, as Proton's.
- **Verify** is `GET /api/mail/domains/{id}?refresh=1`, as Proton.
  - It does an uncached lookup of TXT `@` through the server's validating
    resolver (§3).
  - It is limited to 30 an hour per account.
- **Before verification nothing flows:**
  - no address can be made on the domain;
  - Stalwart doesn't know the domain;
  - the RCPT hook refuses its recipients.
  - A pending domain is only a row and a code.
- **Several accounts may add the same name,** each with its own code. Only
  one holds it (`verified` or `warn`; the partial unique index enforces it).
- **A transfer happens when another account proves the domain while it is
  held.** It is immediate once proven, with these safeguards:
  - two fresh checks at least an hour apart both find the holder's TXT
    absent and the challenger's present;
  - one transaction compares and sets: the holder's row goes to `inactive`
    and the challenger's to `verified`, conditional on both rows' states as
    read;
  - the holder gets a security notice (email and the Mail banner) naming
    the domain, not the new holder;
  - until then the challenger's verify answers "this domain is in use",
    the same for every account.

### 3. Records and checks

The server checks records in Proton's order and keeps every record's state.

| Record | What Kutup asks for | State |
| --- | --- | --- |
| Ownership | TXT `@` = the code | `VERIFY_STATE` |
| MX | `MX @ <MAIL_HOSTNAME>` priority 10 | `MX_STATE`; `BACKUP` when the operator configured a backup MX (`MAIL_BACKUP_MX`) and it is first |
| SPF | `v=spf1 include:_spf.<server> ~all` | `SPF_STATE`: exactly one `v=spf1` record that reaches ours (the include chain is resolved, within SPF's 10 lookups) |
| DKIM | three CNAMEs (§4) | `DKIM_STATE` |
| DMARC | `_dmarc` TXT `v=DMARC1; p=quarantine` (editable, as Proton) | `DMARC_STATE`; `RELAXED` when `adkim` isn't `s` |

- **The resolver:** the backend validates DNSSEC itself (hickory), asking
  `MAIL_DNS_RESOLVER` or the system's resolver, which must pass the DNSSEC
  records through. Docker's embedded DNS forwards to the host's resolver,
  which may strip them; self-hosting.md says to point `MAIL_DNS_RESOLVER` at
  one that keeps them.
- **Timing:**
  - every 6 hours for held domains, with jitter;
  - every 15 minutes for 2 hours after a domain is added;
  - on "Refresh".
  - A global cap on concurrent lookups, and a minimum of 5 minutes between
    checks of one domain.
- **SERVFAIL or timeout is "unknown":** the state stays as it was. A record
  counts as failing only after two failing checks at least 12 hours apart.
- **Grace, by cause:**
  - **TXT missing, MX still ours:** the domain goes to `warn`. It keeps
    working, the holder is told (a banner and one email), and it goes
    `inactive` after 14 days.
  - **TXT and MX both gone:** sending from the domain and internal
    delivery to it stop at once. It goes `inactive` within 72 hours.
  - **MX, SPF, DKIM or DMARC drift alone** only changes badges, except
    DKIM's own lifecycle (§4).
- **SPF** needs a new record from the operator: `_spf.<server>` TXT with the
  server's outbound addresses (`ip4:`/`ip6:`). `self-hosting.md` gets it, and
  `scripts/check-mail-ready.sh` learns to check it.
- **No MTA-STS and no BIMI,** as Proton. Our MX is our own host name, so
  receiving needs no certificate per domain.

### 4. DKIM: per-domain targets, Proton Mail's model

Proton Mail (not Pass) gives each domain its own CNAME targets and its own
keys (`Domain.ts`, `DKIM.Config[].Key`; targets like
`protonmail.domainkey.d<id>.domains.proton.ch`). A customer's targets can
never change later, so Kutup uses per-domain targets from v1:

- `kutup1._domainkey.<domain>` → `<domain id>.kutup1._dk.<server>`
- `kutup2._domainkey.<domain>` → `<domain id>.kutup2._dk.<server>`
- `kutup3._domainkey.<domain>` → `<domain id>.kutup3._dk.<server>`

`<domain id>` is the domain row's random id in lowercase base32, so a target
names no domain.

- **v1 serves shared keys through wildcards:** the operator publishes one
  `*.kutupN._dk.<server>` TXT per selector, so every domain's target
  resolves to that selector's key. Nothing is published per customer.
- **Per-domain keys later are server-side only:** a DNS API, RFC 2136, or a
  delegated `_dk.<server>` zone, at the operator's option. Each domain's
  targets then get their own TXT, with no change on the customer's side.
- **Keys:** RSA-2048, as Proton. They are kept in Kutup's database, sealed
  under a new `MAIL_DKIM_KEYS` (the `MAIL_FORWARDING_KEYS` format), so a
  Stalwart restore keeps signing.
- **Rotation, one selector at a time:**
  - the next key is published on the idle selector;
  - after the TTL and a day, signing moves to it;
  - the old one stays published for a week for mail in flight.
- **Signing:** Kutup creates a domain's Stalwart `DkimSignature` (`d=<domain>`,
  the active selector) only after its DKIM state was `GOOD` once.
- **States, as Proton's:**
  - `GOOD`: all three CNAMEs resolve to our targets.
  - `WARNING`: a CNAME missing or wrong after `GOOD`; signing goes on.
  - `ERROR`: after 7 days in `WARNING`, signing stops, as Proton's alert
    says.
  - `DELEGATED`: the `kutupN._domainkey` names hold the domain's own TXT keys
    instead of our CNAMEs, meaning the owner signs elsewhere. We don't sign
    and don't warn.

### 5. Addresses on the domain

- **Made while the domain is usable** (`verified` or `warn`, Proton's
  `getIsDomainActive`), within the account's address limit (§0).
- **Keys as any address:** a key per address, the signed key list, the
  outside key lookup (`/api/mail/keys/lookup`) and Autocrypt. No WKD (settled
  above).
- **Chat and Drive identities don't change.** A person stays `username@server`
  (their `AccountRef`). A custom-domain address is Mail only, as Proton's are.
- **Sending:** every send is checked by Kutup, not left to Stalwart:
  - the From header and the envelope sender must be one of the caller's
    active addresses;
  - if that address is on a custom domain, the domain must be `verified` or
    `warn`;
  - the message is signed `d=<domain>`, with the envelope sender at that
    domain (SPF through the include);
  - outside forwarding (`mail-forwarding.md`) applies as to any address.
- **What else learns the domain table:** these places compare against the
  server's name today and take the domain table:
  - auto-replies (`auto_reply.rs` around 366 and 425);
  - sender rules;
  - `sender_key`, which lowercases only on custom domains;
  - the local-recipient shortcut (mail between two Kutup addresses).
- **`postmaster@` and `abuse@`** on a custom domain go to the domain's
  owner if they made those addresses, and are otherwise refused as unknown,
  as any address is. The settings page says so.
- **MX elsewhere** (the owner keeps another provider): mail to unknown local
  parts isn't relayed to it. This is documented as Proton's behaviour:
  addresses on the domain are ours, the rest belongs to whoever the MX names.

### 6. Catch-all

As Proton:
- one address per domain, an active and receiving one on that domain;
- `PUT /api/mail/domains/{id}/catch-all {addressId | null}`.

The RCPT hook strips a `+tag`, then resolves an unknown local part on a held
domain to the catch-all. These are caught too:
- closed addresses on the domain;
- local parts whose addresses are `freed`.

Group addresses and forwarding return paths are never caught.

- **Rate cap:** per domain, 500 caught messages a day. Past that, RCPT
  answers `452 4.2.2` until the next day. Caught mail counts in the
  account's storage pool like any other.
- **Not forwarded:** caught mail is never forwarded outside, so a catch-all
  can't be turned into an open relay.
- **Stalwart's `catchAllAddress` is never set:** Kutup decides at RCPT.

### 7. Limits and the admin settings

Kutup has no paid plans, so every limit is a site setting the admin console
edits, with a per-user override on the admin user page (decided). The
defaults:

| Setting | Default |
| --- | --- |
| Custom domains: `everyone` / `admins approve` / `off` | `everyone` (kutup.dev too) |
| Custom domains per account | 3 |
| Addresses per account, the username address included (§0) | 10 |
| Held domains on the whole server | 1,000 |
| Grace, TXT missing and MX ours | 14 days in `warn` |
| Grace, TXT and MX both gone | sending and delivery stop at once; `inactive` within 72 hours |
| Domain adds per account per day | 10 |
| Pending domains dropped after | 14 days unverified |
| Catch-all | allowed |
| Catch-all cap per domain per day | 500 |

- **`admins approve`:** a domain the account verified waits in the admin
  console (Mail → Domains) until an administrator approves it. Until then it
  is `pending`, and nothing flows.
- **Outside sending:** custom domains also follow Mail's outside-sending rule
  (`mail_outside_sending`, admins only today). An account that may not send
  outside may still hold a domain and receive on it. Its sends from that
  domain are refused like any outside send (`403 outsideSendingOff`).
- **The per-user override** sets an account's domain count, address count
  and catch-all on its own; an empty field means the site default.
- **Storage** stays the one pool per account, for every app.

### 8. Addresses and keys when a domain changes hands

This covers a transfer (§2), `inactive`, and removal.

**The old account's addresses on the domain go `freed`** (the username
renames' states). Their keys stay, so old mail still opens, but nothing is
published for them anymore:
- the key list drops them;
- the outside lookup and Autocrypt no longer serve them;
- their forwardings and the domain's catch-all end.

**The new holder starts clean.** `mail_addresses_live` is unique on
`folded` among non-freed rows, so freeing is also what lets the new holder
make the same address. Its keys and Autocrypt then serve only the new
account.

**Clients pin the account id.** A new holder of `john@example.com` therefore
shows as a different person with a changed key, never as inherited trust.

**Removing a domain** (`DELETE /api/mail/domains/{id}`) shows Proton's text:
"all the addresses associated with it will be disabled".
- The addresses go `freed` as above, with their mail kept in the mailbox.
- Stalwart's `Domain` and `DkimSignature` go (§10).
- Adding the same name again gets the same code back (§Settled).

**An `inactive` domain that its holder proves again** returns to `verified`.
Its addresses were freed when it went `inactive` (as for a transfer), so the
holder makes them again, each with a new key; their old mail stays in the
mailbox.

**Mail in flight:** what arrives after addresses are freed is refused at RCPT
(`550 5.1.1`). The sending server bounces it, as for any unknown address.
What Stalwart has already queued for delivery to Kutup is delivered if the
address is still the account's, and otherwise bounced with a DSN.

**An account reset keeps its domains and addresses.** Domains belong to the
permanent account id, not to the incarnation. The address keys were sealed
under the old master key, so those addresses come back as "Missing keys"
(Proton's repair) and stay closed until rekeyed.

**A deleted account** frees its domains and addresses.

### 9. Abuse

- Verification comes before any mail flows (§2), so nobody receives a domain
  they don't control.
- The periodic recheck means control that ends ends the domain, with the
  grace by cause (§3).
- "This domain is in use" is the same for every account and names no one.
- Outbound from custom domains uses the account's sending limits and Mail's
  outside-sending policy and pauses, like the account's own address.
- The admin console lists domains per account, shows their states, and can
  deactivate one.

### 10. What self-hosting changes

- **Stalwart sync is a reconcile loop.** The database is the truth.
  - One runner holds a Postgres advisory lock and runs at start, every 10
    minutes, and on notify when a domain changes.
  - It diffs the Kutup-tagged `Domain` and `DkimSignature` objects (by their
    `description` tag) against the held domains, and never touches
    `MAIL_DOMAIN`'s.
  - **Enabling** creates the Stalwart `Domain` first, and only then marks the
    domain usable.
  - **Disabling** refuses at the RCPT hook and in the send checks first, and
    only then removes the Stalwart objects.
  - A Stalwart volume restored from backup catches up on the next run.
- **A scoped credential:** a dedicated Stalwart account, `kutup-domains`,
  whose permissions are replaced by `authenticate` and managing domains and
  DKIM signatures (`sysDomain*`, `sysDkimSignature*`), signing in with a
  password (`MAIL_STALWART_DOMAINS_TOKEN`; Stalwart sets an API key's secret
  itself, so a plan can't share one with the backend). Its management port
  (8080) is never published, so only the internal network reaches it.
  - **Residual risk:** a compromised backend can still add a domain to
    Stalwart, and so make it accept relaying for that domain. The loop only
    ever touches objects carrying its tag, so it can't repair other drift.
    Instead, an alert fires when `MAIL_DOMAIN`'s objects change.
- **The RCPT hook** resolves recipients on every held domain (and the
  catch-all), not only `MAIL_DOMAIN`. `local_address` takes the domain table.
- **DNS the operator publishes once:**
  - `_spf.<server>`;
  - `*.kutup1._dk.<server>`, `*.kutup2._dk.<server>` and
    `*.kutup3._dk.<server>`. Kutup generates the keys and prints the
    records; the admin console shows them and their state.
- **Nothing per customer domain on the operator's side:** no certificates
  (MX is our host), and no DNS API until per-domain keys (§4).
- **The resolver:** the backend validates; `MAIL_DNS_RESOLVER` points to one
  that passes DNSSEC records through (§3).

### 11. Web UI (third session, later)

**Admin console** (Kutup's own, Proton has no counterpart):
- Mail → Domains: every held and pending domain with its owner and states,
  approve (in `admins approve` mode), deactivate;
- the site settings in §7, each editable;
- the per-user overrides on the admin user page;
- the DKIM keys' records and their state, and the rotation.

**The account's settings,** copied from Proton, one component each:
- **Settings → Domains:**
  - the list with badges (Verified, addresses, MX, SPF, DKIM, DMARC,
    catch-all) and "{used} / {max} domains used";
  - "Refresh status";
  - "Add domain".
- **The seven-tab wizard,** in Proton's order, with its texts and the
  editable DMARC value.
- **The catch-all modal** (one checkbox per address) and **the delete
  modal**.
- **Addresses:** "Add address" with the verified custom domains; "Missing
  keys" with its repair.
- **Banners:** a domain in `warn`, a domain gone `inactive`, and a transfer
  notice.

### 12. Tests

- **Unit:**
  - name normalization and refusals, including PSL private suffixes;
  - the canonical address form, with vectors: dots accepted, every
    username-form address unchanged;
  - every record's state from fixture DNS answers (one SPF, several, an
    include chain; MX priorities; DMARC with `adkim=r`; SERVFAIL kept as
    unknown);
  - the state machine and its grace by cause.
- **Live (mail gate):**
  - a test DNS server (CoreDNS in the gate's compose) serves a customer
    domain and the wildcard DKIM records;
  - add, verify, add an address, receive through Stalwart and the RCPT hook,
    send with `d=<domain>` verified by the sink;
  - the catch-all, its cap, and that caught mail isn't forwarded;
  - removing the TXT → `warn` → `inactive` → RCPT refused;
  - a transfer to a second account: two checks, the notice, the old
    addresses freed, the new holder making the same address.
- **Browser:** the wizard to "Verified" against the gate's DNS, an address on
  it, a message both ways.

## Decisions

The user (2026-10-20, relayed by the main session):
- **Defaults:** 3 domains and 10 addresses per account (the username address
  counts), plus a server-wide cap on domains.
- **An abuse gate:** the site setting "custom domains: everyone / admins
  approve / off", with kutup.dev at "everyone". Domains also follow the
  outside-sending rule (admins only today).
- **DNS breakage as proposed:**
  - TXT missing but MX ours: 14 days in `warn`, then the addresses off;
  - TXT and MX both gone: sending and delivery stop at once, and the domain
    goes `inactive` within about 72 hours.
- **Everything is editable:** every default in §7 is changeable in the admin
  console, with a per-user override on the admin user page as well as the
  site-wide defaults.

Settled from Proton's code by the main session's review, not asked: folding
(lowercase only on custom domains), WKD (none in v1), DKIM (per-domain
targets).

## Order

1. The canonical address form and aliases on custom domains (§0).
2. The domains server: table, add and verify, checks and states, the recheck
   sweep, grace, transfer, removal and the address lifecycle (§1–3, 7–9).
3. Stalwart's reconcile loop, the scoped credential, DKIM with rotation, the
   RCPT hook, the send checks and the catch-all (§4–6, 10).
4. Self-hosting docs and `scripts/check-mail-ready.sh` (the `_spf` record and the DKIM wildcards).
5. Gates: mail with the test DNS server, then browser once the web UI exists.
6. Web UI (third session).
