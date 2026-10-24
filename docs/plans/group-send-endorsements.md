# Group send endorsements for the multi-recipient route

Status: **design note for approval** (third session, client and crypto parts;
second session, the server and federation parts marked *(server)*;
2026-10-24). Nothing here is built yet.

**Decision being implemented (the user, 2026-10-24):** "do it Signal's way".
Replace the per-group delivery capabilities of slice 2
([`pairwise-groups.md`](pairwise-groups.md), "Slice 2") with libsignal's
zero-knowledge **group send endorsements** (GSE), so no server learns an
account's group count or a group's membership from the multi-recipient
route. The #334 re-review found the capability design's padding can't hide
the count (a dummy re-added with the same hash marks itself, and a newly
linked device publishes the dummy set alone); endorsements need no padding.

**In one paragraph:** each account's **own server** endorses it once a day:
one `GroupSendEndorsementsResponse` over the account's id encrypted under a
fixed public params set. The member checks it and uploads it, with its proof,
sealed under each group's state key, to each group's home. A sender checks
the endorsements of the recipients on one destination server, combines them
into one token, and that server verifies the token with its own key, as
Signal-Server does. Issuer and verifier are the same server, which is what
libsignal's keyed verification needs; the home never issues and never sees an
account, and no server learns anything per group.

(Revised 2026-10-24 after an independent review against libsignal 4e9bd5d,
Signal-Server and Signal-Desktop: an earlier draft had per-group, per-day
params, call-link credentials and dummy presentations. `to_token` unblinds to
`sk·M1(ACI)` whatever the params, so a per-group endorsement is the same
credential as any other, and that machinery only added leaks: a daily
bucketed count, daily co-membership clusters, join timing.)

## 1. How Signal does it

Sources: libsignal `rust/zkgroup/src/api/groups/group_send_endorsement.rs`,
`rust/zkcredential/src/endorsements.rs` and `rust/zkgroup/src/api/endorsement_expiration.rs`
(checkout 4e9bd5d, 2026-07-10); Signal-Server `MessageController.java`,
`GroupSendTokenUtil.java`, `auth/GroupSendTokenHeader.java`; Signal-Desktop
`ts/util/groupSendEndorsements.preload.ts`, `ts/util/sendToGroup.preload.ts`,
`ts/groups.preload.ts`.

- **What an endorsement is.** A MAC (3HashSDHI, like Privacy Pass) over a
  member's service id and an expiration. The issuer signs a *hidden* point,
  the first point of the member's `UuidCiphertext` (`a1·M1(uid)`, encrypted
  under the group's secret params), so it never learns the id
  (`endorsements.rs:1-50`).
- **Issuance.** The groups server answers every group fetch and change with a
  `GroupSendEndorsementsResponse`: one endorsement per member ciphertext it
  stores (sorted by point), one batch proof, and the expiration. The same for
  every requesting member; cached while membership doesn't change
  (`group_send_endorsement.rs:66-130`). An endorsement is deterministic for a
  key and point (`R_i = sk'·E_i`, `endorsements.rs:348-380`).
- **Receiving.** The client checks the batch proof with the server's public
  key (`receive_with_service_ids` / `receive_with_ciphertexts`) and stores one
  endorsement per member plus a combined one (Desktop's migration 1050).
- **Sending.** Per send, the client combines the endorsements of the
  recipients (`combine`, `remove`: set operations), turns the result into a
  token with the group's key (`to_token`: unblinds by `a1⁻¹`, hashes), attaches
  the expiration (`into_full_token`) and sends it in the `Group-Send-Token`
  header of `PUT /v1/messages/multi_recipient`.
- **Verifying.** The chat server recomputes the token from the plain
  recipient ids (`Σ M1(uid)`) with a key derived from **its secret** for that
  expiration (`GroupSendFullToken::verify`, `GroupSendTokenUtil.java`). It
  covers every recipient of the request, resolved or not. The same token also
  authorises one sealed send and pre-key fetches between members.
- **Expiry and rotation.** Day-aligned; the server picks the end of the next
  day (at least 25 hours ahead, `endorsement_expiration.rs`); clients refuse
  one under 2 hours away or more than 7 days (Desktop: more than 2 days) and
  fetch the group again when theirs is close to expiry. A removed member
  keeps what it has until it expires: removal takes effect within about a day.
- **Why it works for Signal: one operator.** Verification needs the issuer's
  secret key (`verify(..., &GroupSendDerivedKeyPair)`): the groups server and
  the chat server share `ServerSecretParams`.

## 2. Why the home can't issue

Kutup's issuer and verifier would be different operators: the group's home
would issue, the recipient's server would verify, and verification needs the
issuer's secret ([`research/20`](../research/20-federated-group-credentials.md)
§2 found the same for credentials). The alternatives fail:
- **Share the key.** A home holding a destination's endorsement key could
  forge tokens for every account there.
- **The destination issues on the home's word** (the home attests "these
  ciphertexts are members of a group of mine"). Any federated operator could
  run a fake group, attest ciphertexts of any account it likes and get
  endorsements for them: anonymous sealed sends to anyone, which today's
  capabilities prevent. The destination would also learn each group's home.

## 3. The design: each account's own server endorses it

**What an endorsement is here.** `to_token` unblinds an endorsement to
`sk_e·M1(ACI)` for whatever params it was issued under, so an endorsement
says only "server D endorses account A until this expiration". There is
nothing per group to hide, so nothing is per group: one endorsement per
account and day, shared with every group it is in. It authorises
multi-recipient sends to that account, by anyone holding it, until it
expires: the scope today's delivery capability had, bounded by the
per-recipient budget (§3.6); the recipient's client still drops a group
message whose sender isn't a verified member.

**3.1 Fixed public params.** `P0 = GroupSecretParams::derive_from_master_key(
GroupMasterKey(SHA-256("kutup/chat-group-send/params/v1")))`, a protocol
constant every client and server computes. They hide nothing (anyone can
derive them); they only give the issuance and the token their encryption
layer, as libsignal's API needs one. Vectors pin the bytes.

**3.2 Issuance** *(server)*. `GET /api/chat/group-send/endorsement` (bearer,
the account's own server D) answers
`GroupSendEndorsementsResponse::issue([P0.encrypt_service_id(ACI)], key pair
for exp)` for the signed-in account, with `exp` on D's fixed schedule:
libsignal's `default_expiration` (the end of the next day UTC, at least 25
hours ahead). D can cache one per account and expiration, and may push it with
every sync instead, so even the fetch says nothing; every account asks once a
day whatever it is in, so the request itself carries no group information.
- **What D learns:** nothing about groups: that its user fetched its daily
  endorsement (or nothing at all, pushed).
- Limits: requests per account and day (site setting, `429` past it).

**3.3 Sharing it with each group** *(server, the home)*. The member checks
the response (`receive_with_service_ids([ACI], now, &P0, D's endorsement
public key)`, and the expiration cap of §3.7), then uploads the **full
response, with its proof**, sealed, to the home of each of its groups:
- **The operation:** `PUT …/groups/{id}/endorsement` on the home (local or
  through the federated group route, authenticated as the pseudonym like any
  member operation), body `{ expiration, sealed }`:
  - `sealed` is opaque to the home: the member's `{ server, keyId, response }`
    under the group's state key, padded to one size before sealing
    (`ENDORSEMENT_BLOB_BYTES`, 512, a protocol constant), so every blob is the
    same length;
  - `expiration` is in clear (day-aligned, at most the cap of §3.7 ahead,
    refused otherwise), so the home can drop expired blobs without reading
    them;
  - at most two per pseudonym (the current and the next); a third replaces the
    oldest; uploads per pseudonym and day are limited (site setting,
    `chatGroupEndorsementUploadsPerDay`, default 8).
- **Storage:** `chat_group_endorsements (group_id, pseudonym, expiration,
  sealed, uploaded_seq)`, primary key `(group_id, pseudonym, expiration)`;
  rows go when the pseudonym leaves the group (in the removal's transaction),
  when the group is deleted, and an hour after their expiration.
- **Reading:** `GET …/groups/{id}/endorsements?after=<seq>`, for members,
  paged, returning what was uploaded after the client's cursor. State reads
  don't carry them.
- **What the home learns:** one opaque blob per member per day and when it
  arrives; no account, no server (sealed), and the blobs of one account in
  two groups are unrelated ciphertexts under two keys.
- Every member checks every blob it reads (§3.4); a junk or replayed blob is
  rejected there, so a member can't poison anyone's token.

**3.4 Sending.** For each destination server D:
1. take the recipients' blobs from the home's endorsement read, and check
   each response once (`receive_with_service_ids([recipient ACI], now, &P0,
   D's key from its signed discovery)`, the expiration cap, and that the
   blob's `server` is D); keep the endorsement;
2. take the recipients with the newest expiration they share; `combine`
   their endorsements, `to_token(&P0)`, `into_full_token(exp)`;
3. send the multi-recipient request with `groupSendToken` in place of
   `capabilities`.
- A recipient without a valid current endorsement goes pairwise (slice 1's
  path stays the fallback), as one without a capability does today.
- Recipients with different expirations go in one request per expiration.
- Own devices go pairwise, as now.

**3.5 Verifying** *(server)*. D recomputes the token over the
**deduplicated** recipient account ids of the payload (a request naming an id
twice is `400`, and the token is checked over each id once) with its derived
key for the token's expiration (`GroupSendFullToken::verify`), before devices
are looked at (Signal's order, access first).
- **Which key:** the token carries no key id. D tries its current key, then
  the previous one while it is in its verification window (§4).
- **A bad token is `401 groupSendTokenInvalid`, as Signal's** (expired, a
  recipient added or missing, another server's key). The check is over the
  ids the sender named, before any is looked up, so there is no existence
  oracle. The client sends pairwise, re-reads the group's endorsements, and
  fetches its own anew if its own is the stale one. A federated `401` passes
  back unchanged.

**3.6 Budgets on the multi route** *(server, site settings)*:
- **per recipient account,** `chatMultiPerRecipientPerMinute`, across all
  senders: **the real limit**. A recipient over it is `rateLimited` in the
  answer, and the client sends that recipient's copy pairwise (with back-off),
  never dropping it;
- per token, `chatMultiPerTokenPerMinute`, keyed by the full token's hash:
  **weak**, as anyone holding n endorsements can combine 2^n − 1 different
  subsets, each a different token; it only caps replays of one request;
- the existing per-request, per-origin and payload-size limits stay.

**3.7 Expiry and removal.**
- **Schedule** (protocol constants): D issues `default_expiration(now)`
  (libsignal: the end of the next day UTC, between 25 and 49 hours ahead).
  Clients, homes and senders refuse an expiration more than
  `MAX_ENDORSEMENT_LIFETIME` (3 days) ahead or not day-aligned. A client
  fetches its next endorsement when its current one has less than 25 hours
  left, and uploads it to each group.
- **Removal is enforced by the home**: a removed pseudonym can't read the
  endorsements any more, and its own blob is deleted. What it already read
  stays valid until expiry: **a removed member can send to the others on the
  multi route for up to about 2 days (at most 3, the cap)**, as in Signal,
  where removal takes effect when the endorsements a member holds expire (up
  to about 2 days). The state key doesn't rotate with membership (the master
  key isn't rotated, as in Signal), so sealing under it adds no protection
  after removal; the home's access control is what stops new reads. Its
  messages still reach only clients that drop them (it isn't a verified
  member any more), so what is left is budgeted spam within that window.
- Rejoining is a new pseudonym and new uploads.

## 4. Federation *(server)*

- **The keys.** One `ServerSecretParams` per server and key id; only its
  endorsement root (`get_endorsement_root_key_pair`) is used. Generated on
  first start, as the VAPID key is.
  - Stored in `chat_zk_server_keys (key_id, server_secret_sealed, created_at,
    issues_until, verifies_until)`, the secret sealed at rest under the
    server's sealing keys (`OPAQUE_SETUP_KEYS`, with their key id), as DKIM
    private keys are; never logged, never in a backup in clear.
  - **Rotation** is an admin command, `kutup-server chat-zk-keys rotate`: the
    new key issues from then on; the old one stops issuing at once and keeps
    verifying until the latest expiration it issued (at most 49 hours, the
    window being `MAX_ENDORSEMENT_LIFETIME`), then its row is deleted.
- **Discovery.** The signed federation identity document gains
  `chatGroupSend: [{ keyId, endorsementPublicKey, issuesUntil }]`: **only the
  `EndorsementPublicKey`**, the current one and, during its window, the
  previous one. Senders check other servers' endorsements with it, and
  members their own server's; a local client reads the same from `GET
  /api/chat/group-send/params`. Verification never needs another server's
  key: D verifies only tokens it issued itself.
- **The federated route.** The origin forwards `groupSendToken` with the
  multi-recipient body to the destination's `/api/fed/chat/sealed/multi`
  unchanged; only the destination verifies it.
- **Not post-quantum,** as Signal's: endorsements are ristretto255 MACs. A
  future quantum adversary could forge tokens from a public key, but nothing
  recorded now helps it later: a token names only recipients the request
  already names, and expires within days.

## 5. What a server learns, against today

| Who | With capabilities (#297/#334) | With endorsements |
| --- | --- | --- |
| A member's own server | the account's capability count (≈ its group count), hashes used together on each send, rotations | nothing about groups: one endorsement per account per day, or a push |
| A destination at send time | the recipient set; which capability hashes are used together | the recipient set |
| The home | — | one sealed blob per member per day (timing only) |
| The origin (a remote send) | the raw capabilities, so it could sealed-send to those members within their budget | a token for that recipient set until it expires (Signal has the same) |

## 6. What changes

**Replaced (remove):**
- server: `chat_group_capabilities`, `PUT /api/chat/group-capabilities`,
  `POST …/set`, the `chatGroupCapabilitiesPerAccount` site setting and its
  admin field (#297, #310), the capability check on the multi route and the
  per-capability budget;
- client (#334, parked): `DeliveryBook`, `HeldCapability`,
  `CapabilityLedger`, `group_delivery.rs`, the `groupDelivery` content kind,
  `DeliveryPaddingKey` and its vectors, `settle_delivery`, the group list
  entry's `delivery` field, the transport's capability calls and
  `groupCapabilityLimitReached`.

**Kept from #334 and #297:** the multi-recipient route (origin and federated),
shared-payload storage and drain assembly, the budgets other than the
per-capability one, `seal_group_multi` and the trusted-identity check, the
durable legs (`multi`, `sender_key_message`), the per-leg answer handling
(`409`/`410`, unmatched answers counted, non-200 as errors), the pairwise
amendment for devices the sender key hasn't reached, and the harness.

**Added:**
- `zkgroup` from the same libsignal revision as `libsignal-protocol`
  (AGPL-3.0, like the rest of libsignal here) in chat-core, its WASM and FFI;
  the chat WASM budget grows by zkgroup's size (to measure);
- client: the daily fetch and check, the upload to each group's home and the
  paged read, token building per destination and expiration, and refreshing
  before expiry;
- server: the endorsement route, the key and its rotation, the home's
  endorsement storage, the token check and budgets on the multi route.

**Protocol constants, not settings:** `P0`, `ENDORSEMENT_BLOB_BYTES` (512),
the expiry schedule (`default_expiration`) and `MAX_ENDORSEMENT_LIFETIME`
(3 days), and with it the old key's verification window. Rate limits stay
site settings.

## 7. Migration

None for users: the capabilities never left the server side and no client
release used them. One ordinary migration (numbered above master and open
PRs when built) drops `chat_group_capabilities` and the site setting's row.
#334 is rebuilt on endorsements before it merges.

## 8. Tests and vectors

- Vectors, Rust and WASM, with fixed randomness: `P0`'s bytes; a response
  issued for a fixed ACI and expiration under a fixed test key; the token for
  two ACIs.
- libsignal's own GSE tests cover the cryptography; Kutup tests the
  composition:
  - a token over the members on one server verifies there, and fails with one
    recipient added or missing, or under another server's key;
  - duplicate recipient ids: refused, and never counted twice in the token;
  - a junk blob, a response for another account, another server's, or one
    past the cap is rejected by the reader and never reaches a token;
  - a token across a key rotation verifies in the window and not after;
  - expirations: not day-aligned or past the cap refused at D, the home and
    the sender; endorsements combine only when their expirations are equal;
  - a removed member reads no new endorsements, and its token stops at expiry;
  - `rateLimited` for one recipient sends that copy pairwise.
- The chat-core harness: its server double issues and verifies with a test
  `ServerSecretParams`; the existing `group_multi_*` tests move over.
- Live, one and two servers *(server)*: issuance, the home's blob storage, a
  federated multi send with a token, a bad token refused whole, key rotation
  in discovery.

## 9. Settled by the second session (revised with the design)

- **Keys:** one `ServerSecretParams` per server and key id, sealed at rest
  under `OPAQUE_SETUP_KEYS`, made on first start, rotated by an admin
  command, the old key verifying until its last expiration (§4).
- **Discovery:** `chatGroupSend` with only the endorsement public key, and the
  previous one during its window; `GET /api/chat/group-send/params` locally.
- **Limits:** endorsement requests per account and day, uploads per pseudonym
  and day; site settings (§3.2, §3.3).
- **Budgets on the multi route:** per recipient account (the real one) and
  per full-token hash (weak), replacing the per-capability one (§3.6).
- **The home:** a separate endorsement operation and paged read, blobs of one
  size, two per pseudonym, dropped on leave and after expiry (§3.3).
- **A bad token:** `401 groupSendTokenInvalid`, as Signal (§3.5).

## 10. Estimate

Client and crypto (third session): 3–4 days (one fetch, the upload and read,
token building, moving the harness). Server and federation (second session):
3 days, confirmed: the key table, sealing and rotation command (½), the daily
endorsement route and its limit (½), the discovery field (¼), the home's
endorsement operation and read, local and federated (¾), the token check over
deduplicated ids and the per-recipient budget on the multi route (½), removing
the capability tables, routes and settings (¼), and live tests on one and two
servers (½).
