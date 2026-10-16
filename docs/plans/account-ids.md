# Permanent account ids: the server side

Status: draft for approval by the main and third sessions (2026-10-15), before the
wipe release.
- Companion: the third session's client note (Chat on Signal's ACI model).
- Source: the identifier audit of 2026-10-15
  (`/home/aa/.cache/kutup-pool/identifier-audit-2026-10-15.md`).

## The rule

The user's rule, behind the first wipe and restated today:
- Changeable things (username, address, password, display name, device label) are never a record key.
- They are never bound into keys, signatures or encryption.
- Everything hangs off a permanent random id; the changeable value is an attribute.
- Where a reference already does it right, copy it.

The one stated exception: OpenPGP keys per mail address, as Proton does.

## The account id (one definition for both notes)

- **What it is:** `users.id`, a random UUID minted once: at sign-up, admin create or the bootstrap admin. It's Signal's ACI (`AccountsManager`: a random UUID at registration).
- **What keeps it:** the same row is updated in place through renames, password changes, rotation, recovery and admin reset. An admin reset gives a new incarnation under the same id, as Signal's `reclaimAccount` keeps the ACI and replaces identity keys and devices.
- **What ends it:** only deleting the account. A freed name taken later belongs to a new account with a new id.
- **Names:**
  - JSON: `accountId`, lowercase hyphenated UUID.
  - Columns: `*_account_id uuid`.
- **Across servers:** a person is the pair `{ "server": "<domain>", "accountId": "<uuid>" }`. They're two fields everywhere: JSON, signed and sealed bytes, and columns (`*_server`, `*_account_id`).
  - Never one `uuid@server` string: our address parsers would accept it as a name.
  - Where one string is unavoidable (an MLS credential identity, a libsignal `ProtocolAddress` name), use `aci:<uuid>@<server>`. No address parser accepts the prefix.
  - Within one server the bare UUID is enough, as in Signal, where a `ServiceId` string is the bare ACI.
- **How a client trusts it:** the account authority signs (`server`, `accountId`, incarnation) inside the Chat manifest and inside the Drive key binding.
  - The server refuses a publish whose `accountId` is not the account's `users.id`.
  - An admin reset is a new authority signing the same id, so clients show "safety number changed" in the same conversation, as Signal does.
- **Names are handles:**
  - address → (server, accountId) only through `GET /api/users/by-address/:address` and its federated twin;
  - a held name answers `409 renamed`;
  - the answer is server-asserted, as Signal's username lookup returns an ACI;
  - the client checks it against its pins and the signed rename chain.
- **The incarnation id** (hash of the authority key) stays: it means "this account's current keys". The account id is the person; the incarnation is their current key generation.
- **One shared type:** `AccountRef { server, account_id }` in kutup-crypto, re-exported by chat-proto. It serializes as `{ "server", "accountId" }` and parses its `aci:<uuid>@<server>` string form strictly: lowercase hyphenated UUID, a valid server name, nothing else. It lands first, as its own commit, so both sides build on it.
- **Agreed with the third session (client note):**
  - **One string form in clients:** clients always write the prefixed form (`aci:<uuid>@<server>`) as the libsignal `ProtocolAddress` name, the MLS credential identity and local store keys, even for peers on the same server. A peer's records never change key when federation context does. Server routes and JSON within one server use the bare UUID.
  - **A different id is a different person:** a by-address answer that maps a pinned address to another `accountId` is someone new (a new thread, "not the person you verified"), never a key change. This replaces the formerly/detached/moved pin machinery.
  - **Renames are display history:** continuity through a rename is "same accountId, same authority". `AccountRenameV1` chains are used only to show "X changed their username to Y". Without a verified chain, the new address is a server-asserted label, as Signal's usernames are.

## Format changes (crypto and proto crates)

The server-checked formats below are mine; the third session takes the chat-proto content formats:
- `ConversationId::Direct`, `ContactControlBody.peer`, `SentTranscriptBody.peer`, `GroupUpdateBody.actor`;
- mentions, backup records and the attachment ledger reference;
- the chat-core stores.

Each one gets new checked-in vectors in `crates/kutup-crypto/tests/vectors` (or the chat-proto
vectors). The Rust and WASM vector tests run on every change. All formats keep their V1 names:
pre-wipe, nothing stored needs reading under the old layout.

| Format | Today | After | Reference copied |
|---|---|---|---|
| `drive_key_binding` | signs `username@server`, incarnation, authority, Drive keys; re-signed on every rename | signs `server`, `accountId`, incarnation, authority, Drive keys; never re-signed on a rename | Signal binds identity keys to the ACI; the username is a lookup handle |
| `named_share` (folder and file share envelopes) | HPKE AAD and Ed25519 signature bind sender and recipient addresses (exact match) and incarnations | bind sender and recipient (`server`, `accountId`) and incarnations | Signal: everything addressed by ServiceId |
| `profile_key_share` | both addresses in header AAD and signature | both (`server`, `accountId`) | as above |
| `MailKeyListV1` | signs `account` (`username@server`) and requires it unchanged along the chain | `account` removed; the list stays bound to its address, incarnation and authority key id | Proton's SignedKeyList data names keys and flags, no account |
| Shared-mailbox group key share | OpenPGP-encrypted to the member's active per-address key; lost on a rename | sealed (HPKE, the account envelope suite) to the member's account-level HPKE key (`drive_hpke_public_key`, bound by the key binding to `accountId`); AAD binds group id, group key fingerprint and member `accountId`. A member who leaves or is removed gets no new keys: the manager's browser rotates the group key on removal and shares the new one to the remaining members' account keys only (as now, `rotate_group_key`); the server refuses a rotation that still shares to a removed member | Proton wraps address keys to the account's user key, one level above addresses, and rotates on member removal |
| `AccountManifestV1` (Chat) | signs `account` (address) and incarnation | signs `server`, `accountId`, incarnation; no address. The server checks `accountId` = `users.id` on publish | Signal: identity bound to the ACI |
| Sealed-sender `SenderCertificate` | `sender_uuid` = address; no id | `sender_uuid` = `accountId`, plus `sender_server`; identity key as now | Signal `CertificateGenerator`: `sender_uuid` = ACI plus identity key |
| Chat profile envelope | AAD header and HKDF info bind the address | bind `server`, `accountId` | Signal profile keys are per ACI |
| Sealed delivery capability | HKDF salt = recipient address | salt = recipient `server`, `accountId` | as above |
| MLS (frozen, but durable bindings): group delivery capability, anonymous-MLS AAD, roster commitment (sorted ids), owner candidate, membership delivery digest, private control roster, credential identity (`aci:<uuid>@<server>#<device>`) | addresses | account ids | Signal group membership by ACI |
| Federation delivery messages (`FederatedChatTransaction.sender/recipient`, sealed, media offer, anonymous MLS, key-package requests and bundles) | addresses | (`server`, `accountId`) | Signal routes by ServiceId (`MessageController`) |

Unchanged:
- `AccountRenameV1`: the signed history of names.
- Per-address OpenPGP keys, the address in their sealed payload and their user ID: the exception.
- `device_registration`, `account_envelope`, `opaque`, `kdf`, `account_head`, `mail_names`, `contact_card`, `pass_vault`, `collection_*`, `drive_envelope`, collab frames, `photos_library`: they already bind permanent ids.

## Server: tables (one migration, the next free number at build time)

**Drive:**
- `drive_profile_keys`:
  - primary key `(user_id, direction, peer_server, peer_account_id)`;
  - `peer_incarnation_id` NOT NULL;
  - `peer_account` kept as a display column.
- `federated_outgoing_shares` and `federated_outgoing_file_shares` gain `recipient_account_id uuid NOT NULL`. `recipient_username` becomes display only.
- `federated_incoming_shares` and `federated_incoming_file_shares`: `owner_user_id` already holds the owner's account id (rename it `owner_account_id`). `owner_account` becomes display only.
- `file_versions` gains `remote_author_server` and `remote_author_account_id`. `remote_author` becomes display only.

**Chat:**
- `chat_mailbox`: `sender` is replaced by `sender_server` + `sender_account_id`.
- `chat_federation_outbox`, `chat_sealed_federation_outbox`, `chat_mls_federation_outbox`, `chat_media_federation_pull_grants`: `recipient` is replaced by `recipient_account_id` in the rows and in the unique keys. The destination is already a column.
- `chat_mls_invitation_feedback` and `chat_mls_invitation_feedback_outbox`: `member_address` is replaced by `member_server` + `member_account_id` in the primary key.
- `chat_mls_pending_requests` (unused, unique on an address) is dropped.
- `chat_call_link_seats` and `chat_call_link_knocks` gain `account_id` next to the display `account`.

**Renames:**
- `remote_account_renames` gains `account_id` (from the peer's manifest or key binding) for lookups by id.

**Mail:**
- `mail_group_key_shares` is keyed by `(group_key_id, user_id)` (as now), with the new share format.

Untouched (FINE in the audit):
- `account_names` (the name registry) and `users.username` (a mirror);
- throttle keys, sender rules, image senders, auto-reply records, contact emails and mail history (addresses by nature, as in Proton);
- display labels.

## Server: routes

- **Address → account in one place only:** `GET /api/users/by-address/:address` and `GET /api/fed/{chat|drive}/users/:username`.
  - They answer `{ server, accountId, incarnationId, … }`, or `409 renamed`.
  - Every other route takes an account id. This ends today's two lookup rules: some Chat, MLS and media paths accept a held name, while `kutup_current_user` answers `409`.
- **Chat:**
  - `/api/chat/users/:username/{keys,messages,manifest,manifest-history,profile/:version}` and the anonymous variants become `/api/chat/accounts/:accountId/…`, with `?server=` for a remote account.
  - The federated twins become `/api/fed/chat/accounts/:accountId/…`.
  - Delivery, MLS, media and key-package handlers resolve recipients by account id.
- **Drive federation:**
  - `/api/fed/drive/accounts/:accountId` (the identity, by id);
  - `DriveInviteResponse` and `FileInviteResponse` carry the recipient's `accountId` and incarnation;
  - accept and refresh compare those, not usernames.
- **`?server=` for a remote account** (Chat routes and by-id):
  - checked with `validate_server_name` (a canonical DNS name, no IP, no single label);
  - this server's own name means local;
  - a remote server is reached only through the federation stack's discovery and pinned identity, the same path as #209's lookups. Never a URL built from the parameter, so the parameter cannot point the server at an arbitrary host;
  - the account id must be a canonical UUID (`AccountRef::new`) before any request is made, and the request path is checked against the transport's namespace rule.
- **New lookup by id:** `GET /api/users/by-id/:accountId[?server=]`, with federated twins `/api/fed/{chat|drive}/accounts/:accountId`. It answers the current address and identity, so a client refreshes a contact's handle by id. It is rate-limited like by-address (the user-lookup limit per account; remote fetches per account and per peer, coalesced per id, as #209's renames lookup).
- **`/user/me`** gains `accountId`; `POST /api/users/drive-identities` answers it too.
- **Renames:** `/api/users/renames/:address` stays (the chain is the proof of names). Remote rows are found by account id too.

## The bugs the audit found

| Bug | Fix | Test |
|---|---|---|
| Federated share invites compare usernames: a share made before a rename on either side can't be accepted or refreshed | invites carry the recipient's account id and incarnation; compare those | two-server: share, rename the recipient, accept |
| An old mail address's keys can't be updated (the write authorizes through the current username) | authorize by address-row ownership (`user_id`); take the address from the row | renames_live: rename, then mark the old address's key compromised |
| A renamed member loses a shared mailbox (group key wrapped to the old address key) | the account-level group key share above | mail live: member renames, still opens the shared mailbox |
| `drive_profile_keys` collisions on a rename (address in the key) | the new key | database test: a freed name's new holder does not take the old row |
| `remote_pair_shares` and `list_people` match people by name | match by account id or incarnation | live: profile key exchange after a rename |
| Envelopes verified against current names at seal or re-seal | follows the envelope format | live: re-seal after a rename |
| The CLI's cached username goes stale after a rename elsewhere | refresh from `/user/me` with the session; self check by account id | CLI test against a renamed account |
| The break-glass admin is matched by name | record its `users.id` when bootstrapped, compare by id | unit test |
| `mail_groups` audit entries mix addresses and usernames | group id and user ids, names as snapshots | live: audit payload shape |
| `file_versions.remote_author` has no id | the author's server and account id | collab federation test |
| `chat_mls_pending_requests` unused and keyed by address | dropped | migration test |
| `chat_sealed_federation_outbox.recipient` stores the bare username while its transaction holds the canonical address | account id | covered by the routing change |

Docs only (done alongside, never holding the format work):
- the account-head comment on the contacts scope (it lists the uid);
- the TOTP label note (display, stale after a rename).

## Sequencing with the third session

1. **Approve this note and the client note** together: the same definition, field names and string form.
2. **`AccountRef` first (me):** the shared type, with its parser tests and vectors, as a tiny first commit both sides base on.
3. **Formats (me):** the crypto and proto changes above, with vectors and the WASM bindings, in one PR. The third session builds clients against it at once. It does not wait for routes.
4. **Server (me), in parallel with clients:** migration, routes by account id, by-address as the only name entry, by-id lookups, Drive invites, mail key-list authorization, the group key share check, the small bugs, the CLI. One PR, on top of the formats PR.
5. **Clients (third session):** pins keyed by (server, accountId), Chat on account ids (conversation keys, ProtocolAddress, content), Drive and Mail on the new formats, and the shared-mailbox key on the account key.
6. **Gates:** the full local gates per PR. The two-server gate once, on the final branch, run by the main session.

## Estimate (honest)

| Part | Effort |
|---|---|
| Formats PR (six crypto/proto formats, vectors, WASM) | about a day |
| Chat server (routes, tables, MLS stores, delivery, federation, tests); the largest, Chat and MLS touch many stores | 2–3 days |
| Drive federation, mail, renames lookups by id, small bugs, CLI | about a day |
| Review rounds and gates (going by #204 and #209, each took two or three) | 1–2 days |

Total: about 5–7 working days of my time, partly in parallel with the third session's clients.

## Slice 1 as built (Drive and accounts)

What landed, and where it differs from the note above:
- **Minting.** `register/start` mints a sign-up's id (random UUID) with an HMAC proof bound to the key binding, stateless as the registration answer is. `register` takes the id back only with its proof (`accountIdInvalid`) and only if no account has or had it (`accountIdTaken`). Deleting an account retires its id (`retired_account_ids`), so nobody comes back as that person. An admin-made account has its id from creation. The first sign-in's setup answer carries it (`userId`), and `complete-setup` refuses a minted one.
- **Formats.** The Drive key binding, the folder and file share envelopes and the profile key envelope bind `AccountRef` bytes (u16 server length, server, 16 id bytes). A rename sends no binding. Vectors: `crates/kutup-crypto/tests/vectors/account-refs-v1.json`, checked in Rust and in the browser build. The WASM functions take `{ server, accountId }` objects, as the client branch's do.
- **Lookups.** By-address, the federated user lookup, `drive-identities` and `/user/me` answer `server` and `accountId`. `GET /api/users/by-id/:accountId[?server=]` and `/api/fed/drive/accounts/:accountId` are as above (`RATE_LIMIT_ACCOUNT_PEER_FETCHES_PER_MIN`, coalesced per account).
- **Drive answers name accounts.**
  - Shared folders carry `ownerServer`, so the owner is `(ownerServer, ownerUserId)`.
  - `GET /api/shared-files` carries `server` and `sharerUserId`.
  - Folder and file access lists carry the federated recipient's `recipientAccountId`; the owner re-seals to it through the by-id lookup.
- **Break-glass admin** is protected by `users.is_break_glass`, set when `bootstrap_admin` makes it (one at most). The configured name stays reserved as a name.
- **Kept as is:**
  - `drive_profile_keys` keeps no address column. People's labels come from the shares and accounts when listed.
  - `federated_incoming_*_shares.owner_user_id` keeps its name: it already is the owner's account id, as `collections.owner_user_id` and the JSON `ownerUserId` are.
- **Moved to the Chat slice:** `remote_account_renames.account_id`. Rename chains are display only, and the peer's account id arrives signed in the account manifest that slice changes.

## Slice 2 as built (Mail)

- **Key lists name no account.** `MailKeyListV1` signs the incarnation, the authority key id and the address only (Proton's SignedKeyList names keys). A rename never touches a list. Vectors re-signed (`mail-address-key-v1.json`, `KUTUP_WRITE_MAIL_VECTORS=lists`).
- **Key-list writes by the address row.** `PUT /api/mail/addresses/:id/key-list` and new keys are authorized by the row's `user_id` (current or receiving address), and the address comes from the row. A renamed account still manages its old address's keys (marking one compromised).
- **`/api/mail/keys` names the account** by `server` and `accountId` (absent for a shared mailbox), not by a username.
- **Shared-mailbox key shares on the account key**, as specified above:
  - HPKE to the member's Drive HPKE key; the AAD binds the group id, the group key fingerprint, the member's AccountRef and their incarnation.
  - The share carries the incarnation, so the server checks it against the member's current keys (`keyChanged`) without opening anything. `mail_group_key_shares.member_incarnation_id` replaces the address-key fingerprint.
  - Browsers look members up by id and check their Drive key binding before sealing.
  - The group id is drawn by the creating browser (`id` on create, `idTaken`), since the shares bind it.
  - The server already refuses a rotation that does not share to exactly the remaining members.
  - Beyond the note: the incarnation is in the AAD, as for named shares.
- **Audit entries** for mail groups name the group by id and members by account id; the address is a snapshot.
- **Shared mailboxes' key lists are signed by the group's own signing key** (review, decided by the main session, copying Proton's Signed Key Lists):
  - an Ed25519 key made in a manager's browser, shared with each owner and manager sealed to their account keys as the group key is; the server stores and serves the chain and never signs (its mail-group authority is deleted);
  - lists stay `MailKeyListV1`, their `incarnation_id` naming the signer (not an account incarnation; nothing reads it as one);
  - a signer change is a `GroupSignerHandoverV1` signed by the outgoing signer and linked to its last list; losing an owner or manager needs one; a list an old signer signs after its handover is refused by the server and every client;
  - only an administrator may start a new chain (no handover); senders who pinned the old signer then see a change;
  - senders pin the signer by (server, group id) on first sight (TOFU) and check continuity after: the third session's `groups` pin section, with the same vectors. Until it lands, #212 pins a group's first signer by address in the address-keyed pins and verifies the whole chain on every lookup;
  - an owner or manager whose account is deleted or deactivated may still hold the signer's seed: the group is marked `needsNewSigner`, nothing is published until a handover to a new signer for the active owners and managers (or an administrator's new chain), and their managers' group dialog asks for it (en/tr). Deactivated accounts get no shares (they hold no live keys); a manager seals the keys to them again if they come back (`needsKeys`);
  - an administrator without a share of the signer who promotes someone to owner or manager starts a new chain (senders see a change), as when they remove one;
  - inherent: a former signer and a colluding server can fork the chain at the handover point, serving a list the old signer signs instead of the handover to someone who never saw the handover. A sender who saw the chain past the handover refuses it (rollback guard, and the third session's group pins keep the digests); a sender meeting the group for the first time cannot tell, as with any TOFU pin.
- **Members are checked against the manager's pins before sealing** (`confirmRecipient`, as Drive sharing): someone never met is pinned on first use; a changed or invalid identity stops the sealing until the manager confirms.
- **Changes are checked under the group's lock:** rotations and membership changes take the group row first, then read members and check coverage inside the transaction (a test forces a rotation to wait on a removal).
- **Re-sealing after a reset:** a member whose shares no longer open (`needsKeys`) may be given the keys again, after the manager's confirmation of their new identity; nobody else gets a share that way.
- **Key-list rollback guard:** each device keeps the highest key-list sequence seen per address and signer (revision guard); an older chain is refused. A shared mailbox counts per group id and first signer, so a chain cut back to before a handover is refused too.
- **This server's senders compare folded** in block, spam and allow lists, image senders and auto-reply records (any spelling of a name is one sender). Outside senders stay lowercased, as Proton keeps them.
