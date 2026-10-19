# Mail: forwarding, following Proton

Status: decided (2026-10-19; the user's answers are under "Decisions").
The user decided on 2026-10-19 to build
Proton's forwarding now, on the current v4 address keys, independent of
post-quantum mail ([`mail-pq-openpgp.md`](mail-pq-openpgp.md), which waits for
rPGP). Rule ([`mail-address-keys.md`](mail-address-keys.md)): copy Proton's
answer where its code has one; where it doesn't, say so and propose ours.

Sources read (paths under `kutup-references/`):
- WebClients:
  - `packages/shared/lib/api/forwardings.ts`
  - `packages/shared/lib/interfaces/AddressForwarding.ts`
  - `packages/shared/lib/keys/forward/`
  - `packages/mail/store/forwarding/`
  - `packages/components/containers/forward/`
- pmcrypto: `lib/key/forwarding.ts`.
- go-crypto, Proton branch: `openpgp/forwarding.go`, `packet/forwarding.go`
  and `packet/encrypted_key.go` (`ProxyTransform`).
- openpgpjs-proton.
- Kutup's own code: rPGP 0.21.0 (the version we lock) and the Kutup arrival
  path.

Proton's server isn't public. Wherever a behaviour is only on its server,
this note says "Proton's server: not in client code".

## What Proton has

### Two kinds of forwarding

The type is chosen from the forwardee's address alone (`ForwardModalActions.ts:83`):
- **To another Proton address: end-to-end** (`InternalEncrypted`). The
  forwarder's client makes a forwardee key and a proxy factor. The server
  turns each arriving message's key packet into one for the forwardee
  without opening the message. This is draft-wussler-openpgp-forwarding:
  proxy re-encryption on Curve25519.
- **To any outside address: not end-to-end** (`ExternalUnencrypted`), even
  when the outside address has a published key.
  - Setting it up turns end-to-end encryption off for the forwarding
    address: the address's keys get `EMAIL_NO_ENCRYPT`.
  - From then on, senders seal to it zero-access, readable by the server,
    so the server can re-send everything.
  - Copy: "Forwarding to an address without end-to-end encryption will
    disable end-to-end encryption for your {email} address, but zero-access
    encryption remains enabled."
  - Deleting the last outside forwarding turns it back on.
- **Another provider that is "Proton-style"** (for us: another Kutup
  server) is an outside address. Proton has no cross-provider end-to-end
  forwarding.
- Catch-all addresses are refused as forwardees ("This address cannot be
  used as forwarding recipient").

### Setup and acceptance

- **The forwarder's client makes everything** (`forward.ts`, pmcrypto
  `generateForwardingMaterial`):
  - **A forwardee key:** a new v4 key with one Curve25519 ECDH subkey for
    each of the forwarder's encryption subkeys. Each has:
    - KDF version 0xFF, with the forwarder subkey's fingerprint as the
      *replacement fingerprint*;
    - the forwarded-communication flag 0x40. pmcrypto and openpgpjs-proton
      set 0x40 alone; go-crypto's Proton branch and the draft's vector set
      0x10 | 0x40 (split key too).
  - **A proxy factor for each subkey:** k = dC⁻¹·dB mod ℓ (dB the
    forwarder's secret scalar, dC the forwardee's). It is sent as a
    `ProxyInstance {PgpVersion, ForwarderKeyFingerprint,
    ForwardeeKeyFingerprint, ProxyParam}`, hex.
  - **The forwardee key** is encrypted under a random 32-byte passphrase.
  - **An `ActivationToken`:** that passphrase, encrypted to the forwardee
    address's public key and signed by the forwarder's key.
- `POST mail/v4/forwardings` carries:
  - `{Type, ForwarderAddressID, ForwardeeEmail}`;
  - `ForwardeePrivateKey`, `ActivationToken` and `ProxyInstances`;
  - a filter `{Tree, Version}`.
  The server keeps the proxy factors and the locked forwardee key.
- **The forwardee accepts in the app** ("To me" → Accept). Their client:
  1. opens the token, verifying the forwarder's signature against the
     forwarder's keys as fetched (key-transparency checked at Proton);
  2. unlocks the forwardee key, and if the user ID differs, re-issues it
     under their own address;
  3. re-locks it like their other address keys;
  4. uploads it as an address key with `AddressForwardingID`, not primary.
  - The new key is left out of the signed key list and out of exports. The
    key list shows it with "This key is used for email forwarding"; it can
    only be deleted.
  - The state moving to Active follows the upload (Proton's server: not in
    client code). Decline is a DELETE.
- **An outside forwardee** gets an email with a link to a public
  accept/decline page (`/email-forwarding/accept|decline#<jwt>`). An expired
  link sends a new one.

### States and actions

States: `Pending`, `Active`, `Outdated`, `Paused`, `Rejected`.

| State | Forwarder can | Forwardee can |
|---|---|---|
| Pending | edit conditions; re-send the confirmation (outside); delete | accept, decline |
| Active | edit conditions, pause, delete | delete |
| Paused | resume, delete | delete |
| Outdated (end-to-end only) | re-enable: new material, `PUT mail/v4/forwardings/{id}` | delete |
| Rejected | request confirmation again; delete | delete |

- **Outdated:** a forwarding becomes outdated when the forwarder's primary
  key changes. Before that change, Proton warns: "Existing end-to-end
  encrypted email forwardings will need to be manually re-enabled".
- **Conditions** are the filter conditions without recipient:
  - subject or sender, each with contains / is / begins / ends / matches /
    does not contain;
  - or with / without attachment;
  - joined with all or any.
  - No conditions means everything is forwarded.
  - The original stays in the forwarder's mailbox (`Redirects: [{Copy:
    true}]`).
- **Chains:** mail forwarded to an address is not forwarded on by that
  address. Copy: "Emails forwarded to you are excluded and will not be
  forwarded."
- **Decryption:** the forwardee's client allows forwarded keys only for
  messages flagged as auto-forwarded (`FLAG_AUTO_FORWARDEE`,
  `allowForwardedMessages`), never otherwise.
- **Post-quantum:** v6 keys can't forward.
  - Setting up an end-to-end forwarding demotes a v6 primary, so the
    address stays on v4. Copy: "For compatibility, post-quantum encryption
    will be disabled for {email}."
  - Turning PQ on warns: "This will disable end-to-end encrypted email
    forwardings".
  - Deleting the last end-to-end forwarding makes the v6 key primary again.
- **Limits:** Proton's client has none. Forwarding is a paid feature
  there. Rate limits, SRS, ARC: Proton's server, not in client code.

## Kutup today

- **Arrival** (`crates/kutup-server/src/mail/mod.rs`): outside mail comes
  from Stalwart over LMTP.
  - The server seals the whole raw message to the address's **primary** key
    with rPGP: a v4 key with a Curve25519 ECDH subkey, SEIPDv1 and one v3
    PKESK.
  - It also seals mail that arrived already PGP-encrypted, which it then
    marks `end_to_end`.
  - Every stored copy passes `insert_message`, where filters run.
- **Kutup-to-Kutup mail** on one server never touches SMTP
  (`handlers/mail_send.rs`). The sender's browser makes one data packet and
  a key packet per recipient. The server checks each key packet's key ID
  against the recipient's primary subkey and stores `key packet ‖ data
  packet`. Another Kutup server is an outside address: there is no mail
  federation.
- **Keys:** keys live in `mail_address_keys`, with Proton's flags (incl.
  `FLAG_EMAIL_NO_ENCRYPT` = 4) and one primary per address. They are listed
  in a signed, hash-chained key list (`MailKeyListV1`) that requires
  exactly one primary.
- **Forwarding:** none exists. There is no forward action in filters and
  no Sieve. Stalwart has no SRS, and its ARC sealing is commented out.
- **rPGP 0.21.0** has the draft behind the feature
  `draft-wussler-openpgp-forwarding` (no new dependencies):
  - the proxy factor: `SecretSubkey::generate_proxy_parameter`, which needs
    both secret keys;
  - the transform: `PublicKeyEncryptedSessionKey::forwarding_transform`,
    v3 PKESK only. It checks for small-subgroup points and rewrites the key
    ID to the forwardee's.
  - the replacement-fingerprint KDF (`EcdhKdfType::Replaced`);
  - the 0x40 key flag;
  - decryption behind `DecryptionOptions::enable_draft_forwarding`.
  - There is no builder for a forwardee key; its tests build one by hand.
  - It ships draft vectors (§A.2 and §A.3, in `tests/forwarding.rs`).

Our keys are exactly what the draft needs, so the end-to-end case fits
without changing any key.

## Proposal

### Kinds, as Proton

- **To a Kutup address on this server: end-to-end**, by proxy
  re-encryption.
- **To anything else, another Kutup server included: outside, not
  end-to-end.** Setting it up sets `FLAG_EMAIL_NO_ENCRYPT` on the
  address's keys through a new signed key list, as Proton does.
  - Kutup senders then seal to the address zero-access (the composer
    already follows the flag), so the server can re-send everything.
  - Mail from outside is readable at arrival anyway.
  - Deleting the last outside forwarding clears the flag again.
- **Catch-all forwardees refused, as Proton.** No forwarding to an address
  of the same account. No forwarding to a list or shared mailbox (theirs
  aren't person keys). A forwarding is of an address: mail a member gets
  through a list or shared mailbox arrives at the list's address, so it
  isn't forwarded by the member's.

### Crypto (kutup-crypto, the `mail` feature plus rPGP's forwarding feature)

- `mail_forwarding::material(forwarder_key, forwardee_email) ->
  {forwardee_key (locked), passphrase, proxy_instances}`:
  - Mirrors pmcrypto: one forwardee subkey per forwarder encryption subkey,
    built as rPGP's tests do (`Replaced`, the forwarder's KDF hash and
    cipher). We set 0x10|0x40 as go-crypto and the draft vector do; a check
    of a forwardee key accepts 0x40 with or without 0x10.
  - k comes from `generate_proxy_parameter`.
  - It refuses a forwarder subkey that isn't v4 Curve25519 ECDH. That never
    happens with our keys, but an imported key could be one.
- **The activation**, Proton's locked key plus `ActivationToken` in one:
  Kutup's address keys live unlocked inside account envelopes, so there is
  no passphrase to send. The activation is a signed, encrypted message to
  the forwardee address's primary key, signed by the forwarder's key, whose
  plaintext is a small canonical structure: a magic, the forwarding id, the
  forwarder and forwardee addresses, an expiry, and the forwardee key.
  Binding the id and expiry closes what Proton's token leaves open (a
  token replayed for another forwarding, or accepted late).
- `mail_forwarding::transform(pkesk, forwardee_public, k)` wraps
  `forwarding_transform`. It is the only server-side step, and it reads no
  message.
- `decrypt` gains an `allow_forwarded` option, set only for messages stored
  as forwarded, as Proton does with `FLAG_AUTO_FORWARDEE`.
- WASM exports `material`, the activation, and the accept steps (open and
  check the activation, then seal the key in an account envelope like any
  address key).

### Server

- **Tables:**
  - `mail_forwardings`: `id`, `forwarder_address_id`, `forwardee_email`,
    `forwardee_address_id` (end-to-end), `kind`, `state`, the conditions
    (Kutup's filter condition JSON, not Sieve), and `created_at`.
  - `mail_forwarding_keys`: `forwarding_id`, the forwarder subkey
    fingerprint, the forwardee subkey fingerprint, k, the locked forwardee
    key and the token.
  - `mail_address_keys.forwarding_id`: a forwardee key is an address key
    that is never primary and stays out of `MailKeyListV1` (as Proton keeps
    it out of its signed key list). The list's check skips such rows.
- **Storing k.** k must be usable at arrival with nobody signed in, so it
  can't be sealed to a user. It is still sensitive: **k together with the
  forwardee's secret key gives the forwarder's secret key** (dB = k·dC).
  - The server never returns k to anyone. The forwardee's API answers carry
    the locked key and the token only.
  - At rest it is sealed under a server secret (new `MAIL_FORWARDING_KEY`,
    32 bytes), so a database dump alone doesn't hold it. Each sealed k
    stores the secret's version beside it, so the secret can be rotated by
    re-sealing, and the AAD binds (forwarding id, forwarder fingerprint,
    forwardee fingerprint): a sealed k moved to another row doesn't open.
  - `MAIL_FORWARDING_KEY` goes in the backup and restore runbook
    (`docs/self-hosting.md`). A server started without it, or with a
    version it lacks, marks those forwardings Outdated with a notice to the
    forwarder; arrival never fails because of it.
  - k is never logged (request bodies with `proxyInstances` are left out of
    request logs, as passwords are) and no GET returns it, the forwarder's
    own included.
  - Proton's server: not in client code.
- **The life of k.** k plus the forwardee's secret key gives the
  forwarder's secret key, and an old k plus the forwardee key still opens
  the mail of the key it was made for. So k is deleted, not kept, on:
  - deletion by either side;
  - decline (internal) or reject (outside link);
  - Outdated (the forwarder's key changed; re-enabling makes new material);
  - deletion of the forwarder address, or of the forwardee's account or
    address;
  - the forwardee deleting the forwarding key from their key list.

  Pause keeps k, and resume needs no new material. The activation is
  dropped once it is accepted or declined, and at its expiry.
- **Arrival:** in `insert_message`'s caller, after the forwarder's own copy
  is stored and its filters have run, for each Active forwarding of the
  address whose conditions match, and which didn't itself arrive by
  forwarding (no chains, as Proton):
  - **End-to-end:**
    - Take the forwarder copy's PKESK for the forwarder's subkey:
      - the server's own seal, for outside mail;
      - the sender's key packet, for Kutup mail.
    - Transform it to the forwardee subkey and store `transformed PKESK ‖
      the same data packet` in the forwardee's mailbox.
    - The copy is flagged `forwarded`, with the forwarder address, and goes
      through the forwardee's filters and quota.
    - Kutup mail stays end-to-end: the server only multiplies a curve
      point.
    - **When a key packet can't be transformed**, the message isn't
      forwarded, and the forwarder's own delivery never fails because of
      it. The skip is counted per forwarding and shown to the forwarder
      ("N messages couldn't be forwarded"). Today that can't happen: the
      server seals outside mail itself (v3 PKESK to the primary), and
      `mail_send` already refuses a Kutup key packet that isn't to the
      recipient's current primary subkey, wildcard ids included. It
      becomes possible with v6 PKESKs (SEIPDv2, usable even with v4 keys),
      with key packets to an older subkey, or with outside mail that
      arrived already encrypted. All of those take the skip path.
  - **Outside:**
    - The server has the plaintext at arrival (outside mail; Kutup mail
      sealed zero-access while the flag is set).
    - It submits the message unchanged to the forwardee through Stalwart,
      with the envelope sender rewritten by **SRS** (SRS0, HMAC under a
      server secret; we do it, Stalwart doesn't). As built, the return
      path is SRS's purpose in a VERP form, `fwd-<forwarding>-<day>-<hmac>`
      at our domain: bounces are counted per forwarding, not relayed, so it
      names the forwarding rather than the original sender.
    - Stalwart DKIM-signs it as our domain. No ARC: Stalwart's sealing is
      off, and Proton's choice isn't visible.
    - **Bounces:** a bounce to an SRS address is checked at RCPT: its HMAC
      and timestamp (21 days, as SRS0) must hold, or it is refused there,
      so nothing becomes backscatter. A valid one is counted against the
      forwarding and dropped. After 5 bounces in a day the forwarding is
      paused and the forwarder told.
    - **Not forwarded:** mail the arrival marked as spam, and mail that
      arrived already PGP-encrypted to the address's key. Outside senders
      who found the key before the flag was set can still encrypt; that
      mail can't be forwarded as plaintext, so it is skipped and counted
      like a transform failure. While the flag is on, WKD and the outside
      key lookups stop serving the address's key, so new outside senders
      send plaintext. Proton's server behaviour here isn't in client code.
    - **A budget of its own:** outside forwards don't spend the account's
      sending limit; each forwarding may re-send 200 messages a day and
      each account 500. When the budget is spent, forwarding pauses for the
      day and the forwarder is told.
    - **DMARC:** the redirected message keeps its original From, and our
      DKIM signature (d= our domain) doesn't align with it. A receiver may
      reject mail from domains with `p=reject` unless ARC vouches for our
      hop. Stalwart's ARC sealing is commented out in this version, so
      that is an open question (below).
- **Loops.** Mail forwarded by us carries a marker header
  (`X-Kutup-Forwarded`, an HMAC of the forwarding id under a server
  secret) and, for outside forwards, our SRS envelope sender. Neither
  breaks the original DKIM signature. Mail that arrives with our marker,
  with an envelope sender in our SRS form, or with more than 20 `Received`
  headers is delivered but never forwarded again. That covers loops through
  outside providers (A → outside → A, or A → outside → B → …), which
  arrive without our internal flag.
- **Primary key change** makes the address's end-to-end forwardings
  Outdated, as Proton, and deletes their k (above). The key-change dialogs
  warn first, with Proton's wording.
- **The forwardee key never signs or verifies either** (as built, from
  review): its forwarder made it and knows its secret, so a signature by it
  would prove nothing about the forwardee whose address it names. Its
  primary only certifies its subkeys, and kutup-crypto refuses it as a
  signer, as a key to verify with and as a recipient.
- **A forwarded copy is the forwardee's mail**: it goes through their
  block, spam and allow lists and their filters like any arrival; one they
  block isn't stored and counts as not forwarded.
- **Abuse:** at most 5 forwardings pending to one address at a time. A
  deactivated account's forwardings, either side, lose k and become
  Outdated.
- **The forwardee key is never an encryption target.** It stays out of the
  keys endpoint, WKD, the outside key lookups and the composer's choice of
  keys. At accept the server checks that the uploaded key's subkey
  fingerprints are exactly the stored forwardee fingerprints of that
  forwarding.
- **Accept checks (the forwardee's client).**
  - The activation's signature verifies against the forwarder's key taken
    from the forwarder's `MailKeyListV1` (checked under the account's
    pinned authority), not against a key the server hands over.
  - Each subkey's replacement fingerprint equals the forwarder's current
    encryption subkey.
  - The forwarding id, both addresses and the expiry in the activation
    match the forwarding being accepted, and it hasn't expired.
  - An internal Pending forwarding expires after 7 days, like the outside
    link.
- **Clearing `FLAG_EMAIL_NO_ENCRYPT`.** The key list is signed by the
  account's authority, so only the forwarder's client can sign the list
  that clears the flag. When the last outside forwarding ends from the
  server's side (a decline through the link, or a deletion by the system),
  the server marks the address as owing a new key list. The forwarder's
  client signs it at its next Mail sign-in, as it does for key changes.
  Until then encryption stays off, the state the forwarder chose, and Mail
  says so.
- **Renamed addresses.** An address in a rename hold (receive-only) can't
  be made a forwarder or a forwardee. Its existing forwardings go on while
  it still receives, and are deleted with their k when it closes.
- **Limits** (decided; Proton's are not visible):
  - at most 10 forwardings per address and 25 per account;
  - outside forwarding has its own budget (above);
  - creating forwardings: 10 an hour per account; outside confirmations
    and re-invites: 3 a day per forwarding;
  - a forwardee address can't forward on what it got by forwarding.
- **Submission.** The server submits to Stalwart as its one relay account,
  so Stalwart can't tell which From an account owns. Kutup checks it: user
  sends from `mail_send` must come from the sender's own addresses (checked
  in the build), and only the forwarding path submits mail with a From that
  isn't ours.
- **API**, Proton's shape under `/api/mail/forwardings`:
  - `GET outgoing|incoming`;
  - `POST`, `PUT {id}` (new material), `DELETE {id}`;
  - `PUT {id}/pause|resume|reinvite|conditions`;
  - `GET {id}/activation`, `POST {id}/accept` (the forwarding key as an
    address key), `POST {id}/decline`;
  - `DELETE /api/mail/addresses/{address}/forwarding-keys/{key}` (the
    forwardee deletes the key; its forwarding ends);
  - the forwarder's client chooses the forwarding's id (a UUID v4), so the
    activation can bind it before anything is stored (as built; see
    `docs/api.md`, "Mail forwarding").
  - The outside confirmation goes through `GET|PUT|DELETE
    /api/mail/forwardings/external/{token}`. That token is single-use and
    lives 7 days; an expired one sends a new link.
  - Outside confirmation needs the server to send its own mail. Our
    `submit` path can (auto-replies use it), so this doesn't wait on the
    roadmap's system-email item.

### The post-quantum hook, for later

Decided (2026-10-18): an address with an end-to-end forwarding stays on
classic encryption while it lasts, and the person is told.

- Today every address is v4 with SEIPDv1 and v3 PKESKs, so nothing changes
  yet.
- The build adds one function: `arrival_key(address) = if
  has_e2e_forwarding { the v4 primary } else { the primary }`, used by
  arrival and by the keys endpoint's order. Once v6 exists that is the one
  line to change, as Proton's `unsetV6PrimaryKey` / restore-on-delete
  does.
- The same holds for the message format: the transform needs v3 PKESKs,
  which SEIPDv2 replaces with v6 even for v4 keys. So the switch also
  decides the format: an address with an end-to-end forwarding keeps
  advertising and receiving SEIPDv1 when Kutup moves to SEIPDv2.
- The UI copy waits for PQ mail, so it isn't in the web build now:
  - the setup confirmation;
  - the "Classic encryption (forwarding on)" label;
  - the note when forwarding goes off.

### What the server learns, and can do (as Proton)

- **With k, the server can transform any key packet** to the forwarder's
  key: past mail, and mail that fails the conditions. So the server
  together with the forwardee can read all of the forwarder's mail, not
  only what is forwarded. The conditions are enforced by the server alone.
- The server learns the forwarding graph (who forwards to whom) and the
  conditions, which are readable to it as filters are.
- That is Proton's design too. We say it in this note and in the setup
  dialog's text ("Forwarding lets the server re-encrypt your mail for the
  recipient; only set it up with someone you trust with your mail.").

### Web UI (the third session's part, if the main session agrees)

- **Mail → Settings → Forwarding:** the "From me" / "To me" tabs, state
  badges, and per-state actions as in the table above.
- **The setup modal:** forward from, forward to, conditions (reusing the
  filter condition editor), and the outside warning.
- **Acceptance in the app.** Accept runs the WASM steps, then uploads the
  key.
- **The public accept/decline page** on the account app, for outside
  forwardees.
- **In the key list:** the forwarding-key badge, delete only, and the
  primary-change warning.
- **Opening forwarded messages:** pass `allow_forwarded` for messages flagged
  forwarded.
- Strings in `en.json` and `tr.json`.

The crypto, the server, the gates and the WASM exports are mine (second
session).

### Tests

- **Vectors:**
  - rPGP's draft vectors (§A.2 transform, §A.3 proxy factor, transform and
    decryption), run through our wrappers with the feature on;
  - go-crypto's Proton-branch vectors (`curve25519_test.go`, the proxy
    factor and transformed point) as a second implementation;
  - a checked-in vector for our forwardee key's shape: flags, KDF and
    replacement fingerprint.
- **Live, two users and a third sender:** A forwards to B, and B accepts.
  - An outside message (LMTP) to A, and an end-to-end message from C to A,
    both open in B's mailbox with B's keys.
  - For C's message, B's stored copy is the transformed PKESK followed by
    the same data packet as A's, byte for byte. The server only ever held
    ciphertext.
  - Paused: nothing reaches B. Outdated after A's key change: nothing
    reaches B until the forwarding is re-enabled.
  - B forwarding on to D gets nothing forwarded from A.
- **Live, outside:**
  - A forwards to an outside address. The mail gate's GnuPG correspondent
    receives an SRS envelope and a DKIM-signed message.
  - A's keys carry `EMAIL_NO_ENCRYPT` while the forwarding exists, and
    lose it when it's deleted.
- **Browser (third session):** set up, accept, read forwarded, pause and
  resume, delete.

## Order

1. This note → main session → user.
2. Crypto, with the vectors.
3. Server: tables, arrival, the outside path with SRS, the API, live tests.
4. WASM exports, then the web UI (third session).
5. Gates: mail, backup, browser.

## Open questions

- **ARC.** Without ARC sealing, outside forwards of mail from `p=reject`
  domains may be rejected by the forwardee's provider. Turn on Stalwart's
  ARC sealing if a later version supports it, seal ARC ourselves, or accept
  the gap (it's Proton's choice that isn't visible).

## Decisions (user, 2026-10-19)

- **Limits:** at most 10 forwardings per address and 25 per account.
- **Outside forwarding copies Proton:**
  - While any outside forwarding of an address is on, the address's signed
    key list carries `FLAG_EMAIL_NO_ENCRYPT` (Proton's `encryptionDisabled`).
  - The settings page says so plainly, when the forwarding is set up and
    for as long as it lasts.
  - Deleting the last outside forwarding restores end-to-end encryption.
