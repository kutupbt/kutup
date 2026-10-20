# Mail: custom domains, following Proton

Status: proposal (2026-10-20), second session. For the main session, then the
user. Nothing is built yet.

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
   - Proton Pass's alias domains show the shape: `dkim._domainkey`,
     `dkim02._domainkey`, `dkim03._domainkey` → targets under
     `alias.proton.me` (`DomainUtils.tsx:55-60`).
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

## Proposal

### 0. Aliases first

Custom-domain addresses are extra addresses, so the account first needs more
than its username's address, as Proton has:
- `POST /api/mail/addresses {local, domain}` creates an address with its key
  (the existing key creation, client-side as now);
- the address list, the sender picker and the per-address settings already
  read several addresses;
- the limit is per account (below).

Aliases on the server's own domain stay Proton-like as a later option. This
note only needs the mechanism.

### 1. A domain belongs to an account

Kutup has no organisations yet, so a domain belongs to one account. When
organisations come (Phase E), it moves to the organisation, as Proton's.

```
mail_domains (
  id uuid, user_id uuid,
  name text,                    -- lowercase, IDNA A-label
  verify_code text,             -- random, per (account, domain)
  state text,                   -- pending | verified | warn | inactive
  verify_state, mx_state, spf_state, dkim_state, dmarc_state  smallint,
  checked_at, verified_at, warned_at timestamptz,
  catch_all_address_id uuid NULL
)
```

The states take Proton's values exactly (the table above), so the web UI
copies Proton's badges and texts one to one.

### 2. Adding and verifying

- **Add:** `POST /api/mail/domains {name}`.
  - The name is normalized: lowercase, IDNA, no trailing dot.
  - It is refused when it is:
    - the server's own domain, or one of its subdomains;
    - a public suffix (the `psl` list);
    - an IP address;
    - longer than 253 bytes.
  - The `www.` warning is the client's, as Proton's.
- **The code:** `kutup-verification=<32 random bytes, base32>`, one per
  account and domain. Proton's format isn't public; this is the common form.
- **Verify** is `GET /api/mail/domains/{id}?refresh=1`, as Proton.
  - The server looks up TXT `@` with a validating resolver.
  - It is limited per account: 30 refreshes an hour.
- **Before verification nothing flows:**
  - no address can be made on the domain;
  - Stalwart doesn't know the domain;
  - the RCPT hook refuses its recipients.
  - A pending domain is only a row and a code.
- **Several accounts may add the same name:** each gets its own code.
  - Only one can be verified at a time.
  - While one account holds the domain verified, another's verification is
    refused ("verified by another account"). It succeeds only once the
    holder's TXT is gone and the holder's domain has dropped to `inactive`
    (below).
  - So an ownership change is: the new owner adds their TXT, and the old
    owner's TXT is removed (by the new owner, who controls the DNS).
  - The two accounts never learn each other's identity.

### 3. Records and checks

The server checks in Proton's order and keeps every record's state. It
rechecks:
- every 6 hours for verified domains;
- every 15 minutes for 2 hours after a domain is added;
- and on "Refresh".

| Record | What Kutup asks for | Check |
| --- | --- | --- |
| Ownership | TXT `@` = the code | `VERIFY_STATE` |
| MX | `MX @ <MAIL_HOSTNAME>` priority 10 | `MX_STATE`; `BACKUP` when the operator configured a backup MX (`MAIL_BACKUP_MX`) and it is first |
| SPF | `v=spf1 include:_spf.<server> ~all` | `SPF_STATE`: exactly one `v=spf1` record that includes ours (the include is resolved, not string-matched) |
| DKIM | three CNAMEs, below | `DKIM_STATE` |
| DMARC | `_dmarc` TXT `v=DMARC1; p=quarantine` (editable, as Proton) | `DMARC_STATE`; `RELAXED` when `adkim` isn't `s` |

- **SPF** needs a new record from the operator: `_spf.<server>` TXT listing
  the server's outbound addresses (`ip4:`/`ip6:`). `self-hosting.md` gets it,
  and `scripts/check-mail-dns.sh` checks it.
- **No MTA-STS and no BIMI:** Proton has neither. Our MX is our own host
  name, so receiving needs no certificate per domain.

### 4. DKIM: Proton's CNAME model, shared keys

As Proton Pass's alias domains, every custom domain publishes the same three
CNAMEs:
- `kutup1._domainkey.<domain>` → `kutup1._domainkey.<server>`
- `kutup2._domainkey.<domain>` → `kutup2._domainkey.<server>`
- `kutup3._domainkey.<domain>` → `kutup3._domainkey.<server>`

How it works:
- **The keys are the operator's.** The operator publishes three TXT records
  once, under the server's own domain, and never touches the customers'
  DNS.
- **Signing.** Kutup gives Stalwart one manual `DkimSignature` per verified
  domain, with `d=<domain>` and the active selector's key.
- **Rotation, one selector at a time, as three CNAMEs allow:**
  - the next key is published on the idle selector;
  - after the DNS TTL (and a day), signing switches to it;
  - the old one stays published for a week for mail in flight, then becomes
    the next idle selector.
  - No customer does anything, which is what the CNAMEs are for.
- **What it costs:** one key set signs every custom domain on the server.
  Its compromise affects them all, as with the server's own domain. That is
  Proton's trade too (its targets are its own keys).
- **The other option** is per-domain keys published as TXT by each
  customer. It isolates domains, but each rotation needs every customer to
  edit DNS, so in practice keys never rotate. Not proposed.
- **States, as Proton's:**
  - a missing or wrong CNAME is `WARNING`, and signing goes on;
  - after 7 days in `WARNING` it becomes `ERROR`, and signing for that domain
    stops, since a signature receivers can't verify hurts more than none;
  - a domain whose owner removed the CNAMEs deliberately reads as
    `DELEGATED` (they sign elsewhere), and we don't sign.

### 5. Addresses on the domain

- **Made while the domain is usable** (`verified` or `warn`, Proton's
  `getIsDomainActive`), within the account's address limit.
- **Keys as any address:** a key per address, the signed key list, the
  outside key lookup (`/api/mail/keys/lookup`) and Autocrypt.
- **WKD for custom domains:** not built, as Proton has none. Outside senders
  find keys through Autocrypt and our lookup. If wanted later, it needs
  `openpgpkey.<domain>` pointed at us and a certificate per domain.
- **Folding:** custom-domain local parts are compared lowercased and folded,
  as the server's own names are (`kutup_fold`). One rule for every address,
  and no lookalikes (`a.b` and `ab`) on one domain. A domain owner who wants
  both can't have them. Proton's behaviour here isn't visible.
- **Chat and Drive identities don't change.** A person stays `username@server`
  (their `AccountRef`). A custom-domain address is Mail only, as Proton's are.
- **Sending:** From a custom-domain address, signed `d=<domain>`, the envelope
  sender at the same domain (SPF through the include). Outside forwarding
  (`mail-forwarding.md`) applies to these addresses as to any other.

### 6. Catch-all

As Proton:
- one address per domain, an active and receiving one on that domain;
- `PUT /api/mail/domains/{id}/catch-all {addressId | null}`.

The RCPT hook resolves an unknown local part on a verified domain to the
catch-all. A group address and a forwarding return path are never caught.

Spam guard: the catch-all takes only what the RCPT hook would otherwise
refuse, and the account's inbound limits apply to it as to its own address.

### 7. Limits

Kutup has no paid plans, so limits are site settings in the admin console,
with defaults:
- custom domains per account: 3 (admin can set 0 to turn the feature off);
- addresses per account, all domains together: 10 (Mail Plus);
- catch-all: allowed (Proton gates it by plan; we have none).

Storage stays the one pool per account, for every app. New domains are
limited to 10 adds a day per account; pending domains not verified in 14
days are dropped.

### 8. When DNS breaks, and removal

- **The TXT disappears** (or verification fails on a recheck):
  - the domain goes to `warn` (Proton's `WARN`) and keeps working;
  - the owner sees a banner in Mail settings and gets one notice email.
- **After 14 days in `warn`,** or at once when another account proves the
  domain, it goes `inactive`:
  - its addresses stop receiving (RCPT refuses: `550 5.1.1`) and can't send;
  - they are disabled, not deleted, and their mail, keys and settings stay;
  - verifying again restores them.
  - Proton's 14-day figure isn't visible; ours is a proposal.
- **MX moves away:** nothing to do; mail no longer reaches us. `MX_STATE`
  shows it.
- **Removing a domain** (`DELETE /api/mail/domains/{id}`), Proton's text:
  "all the addresses associated with it will be disabled".
  - The addresses are closed, with their mail kept in the mailbox.
  - Their keys are retired, and the key list drops them.
  - Stalwart's `Domain` and `DkimSignature` go.
  - Adding the domain again later starts over with a new code.
- **An account reset** removes its domains (they were the old incarnation's).
  **A deleted account** frees them.

### 9. Abuse

- Verification comes before any mail flows (§2), so nobody receives a domain
  they don't control.
- The periodic recheck means control that ends ends the domain, after the
  grace above.
- A domain that is already verified elsewhere answers the same for every
  account: "this domain is in use". No identity is revealed.
- Outbound from custom domains uses the account's sending limits and Mail's
  outside-sending policy, like the account's own address.
- The admin console lists domains per account, can deactivate a domain, and
  sees its states.

### 10. What self-hosting changes

- **Stalwart at runtime.** Kutup upserts a `Domain` (`allowRelaying` as for
  `MAIL_DOMAIN`) and its manual `DkimSignature` when a domain is verified,
  and removes them when it goes inactive or is deleted. This needs Stalwart's
  management API from the server, with an admin credential
  (`STALWART_ADMIN_TOKEN`), where today only `stalwart-setup` uses it.
  - A sweep re-applies every verified domain at start, so a Stalwart volume
    restored from backup catches up.
- **The RCPT hook** resolves recipients on any verified domain (and the
  catch-all), not only `MAIL_DOMAIN`. `local_address` takes the domain table.
- **DNS the operator publishes once:**
  - `_spf.<server>`;
  - `kutup1..3._domainkey.<server>` (Kutup generates the keys and prints
    the records; the admin console shows them and their state).
- **Nothing per customer domain on the operator's side:**
  - no certificates (MX is our host);
  - no DNS API.
- **Backups:** the shared DKIM keys are kept in Kutup's database, sealed
  under a new `MAIL_DKIM_KEYS` (the `MAIL_FORWARDING_KEYS` format), instead of
  in Stalwart's volume, so a restore keeps signing.

### 11. Web UI (third session, later)

Copied from Proton, one component each:
- **Settings → Domains:**
  - the list with badges (Verified, addresses, MX, SPF, DKIM, DMARC,
    catch-all) and "{used} / {max} domains used";
  - "Refresh status";
  - "Add domain".
- **The seven-tab wizard,** in Proton's order, with its texts and the
  editable DMARC value.
- **The catch-all modal** (one checkbox per address) and **the delete
  modal**.
- **Addresses:** "Add address" with a domain picker (own domain and verified
  custom domains); "Missing keys" with its repair.
- **Banners:** a domain in `warn` and a domain gone `inactive`.

### 12. Tests

- **Unit:**
  - name normalization and refusals;
  - every record's state from fixture DNS answers (one SPF, several, an
    include chain; MX priorities; a DMARC with `adkim=r`);
  - the state machine (`pending` → `verified` → `warn` → `inactive` → back).
- **Live (mail gate):**
  - a test DNS server (CoreDNS in the gate's compose) serves a customer
    domain;
  - add, verify, add an address, receive through Stalwart and the RCPT hook,
    send with `d=<domain>` verified by the sink;
  - the catch-all;
  - removing the TXT → `warn` → `inactive` → RCPT refused;
  - a second account can't verify a held domain.
- **Browser:** the wizard to "Verified" against the gate's DNS, an address on
  it, a message both ways.

## Open questions for the user

1. **DKIM: shared keys behind three CNAMEs** (proposed, Proton's model and
   rotation without customers), or per-domain keys published by each
   customer (isolated, but never rotated in practice)?
2. **Defaults:** 3 domains and 10 addresses per account, admin-settable?
3. **Grace before a lost domain stops** (proposed 14 days in `warn`)?
4. **Folding on custom domains** (proposed: as the server's names, one rule)?
5. **WKD for custom domains:** left out as Proton does (proposed), or offered
   later?

## Order

1. Aliases: several addresses per account, with the limit (§0).
2. Domains server: table, add and verify, checks and states, recheck sweep,
   limits, removal and grace (§1–3, 7–9).
3. Stalwart at runtime and DKIM with rotation; the RCPT hook and catch-all
   (§4, 6, 10).
4. Self-hosting docs and `check-mail-dns.sh`.
5. Gates: mail with the test DNS server, then browser once the web UI exists.
6. Web UI (third session).
