# Group send endorsements for the multi-recipient route

Status: **design note for approval** (third session, client and crypto parts,
2026-10-24; the server and federation parts are drafted for the second
session to settle, marked *(server)*). Nothing here is built yet.

**Decision being implemented (the user, 2026-10-24):** "do it Signal's way".
Replace the per-group delivery capabilities of slice 2
([`pairwise-groups.md`](pairwise-groups.md), "Slice 2") with libsignal's
zero-knowledge **group send endorsements** (GSE), so no server learns an
account's group count or a group's membership from the multi-recipient
route. The #334 re-review found the capability design's padding can't hide
the count (a dummy re-added with the same hash marks itself, and a newly
linked device publishes the dummy set alone); endorsements need no padding.

**In one paragraph:** each member gets, once a day, an endorsement of itself
for each of its groups from **its own server**, proving with a zkgroup
credential presentation that the encrypted id is its own, without saying
which group. It shares the endorsement with the group through the group's
home, encrypted under the group key. A sender combines the endorsements of
the members on one destination server into one token, and that server
verifies the token with its own key, as Signal-Server does. Issuer and
verifier are the same server, which is what libsignal's keyed verification
needs; the home never issues and never sees an account.

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

## 3. The design: the recipient's own server endorses its own user

The endorsement for member M on server D is issued by D, to M, for M's own
encrypted id. D can check that cheaply, because M is its own signed-in user;
what M must prove is that the ciphertext encrypts *its* id without revealing
the group's key. zkgroup has exactly that proof.

**3.1 Per group and day: shared params.** Every member derives, for the group
and UTC day `d`, the same `CallLinkSecretParams`
(`CallLinkSecretParams::derive_from_root_key`) from
`HKDF-SHA256(master key, salt "kutup/chat-group/send/v1", info group id ‖ d)`.
- `CallLinkSecretParams` is used, not `GroupSecretParams`, because its
  credential (below) carries only an ACI; `AuthCredentialWithPni` needs a
  PNI, which Kutup doesn't have. Its uid encryption is the same domain
  (`UidEncryptionDomain`), so endorsements are issued over it and `to_token`
  takes it (`AsRef<uid_encryption::KeyPair>`).
- New params every day: D sees unrelated ciphertexts each day, so it can't
  follow a group across days.
- A removed member still knows the master key and can derive later days'
  params, but gets no endorsements of the others (3.4), so that is useless.

**3.2 The credential.** D issues each of its users, on request, a
`CallLinkAuthCredential` for its ACI and a day-aligned redemption time
(`CallLinkAuthCredentialResponse::issue_credential`, D's
`GenericServerSecretParams`), as Signal-Server does for call links
(`GET /v1/call-link/auth`). One a day is enough.

**3.3 Issuance** *(server)*. `POST /api/chat/group-send/endorsements`
(bearer, the user's own server):
- body: the expiration wanted, and a list of
  `CallLinkAuthCredentialPresentation`s, each with that day's group
  `CallLinkPublicParams`, one per group the account is in, **padded to a
  multiple of 8 with dummies** (presentations under fresh random params:
  valid, and indistinguishable from real ones);
- D checks each presentation (`verify(now, generic params, call link public
  params)`: its own credential, redemption time current), takes
  `get_user_id()` (the `UuidCiphertext`), and answers, per presentation, a
  `GroupSendEndorsementsResponse::issue([ciphertext], key pair for the
  expiration)`, each with its own proof so it can be checked alone;
- the endorsement key is D's `ServerSecretParams` endorsement root
  (`get_endorsement_root_key_pair`), derived per expiration as Signal does;
- limits (site settings): presentations per request and requests per account
  and day.
- **What D learns:** that its user is in at most that many groups (the
  bucket), daily; the day's public params of each (unrelated across days).
  Two of its users in one group present the same public params on the same
  day, so D learns that they share a group. The multi-recipient route already
  tells D that (one send, both recipients), as it tells Signal's server.

**3.4 Sharing it with the group** *(server, the home)*. The member checks its
endorsement (`receive_with_ciphertexts([its ciphertext], now, D's endorsement
public key)`), seals it under the group's state key and uploads it to the home
as a new group operation, keyed by its pseudonym and the expiration. The home
keeps the newest two per pseudonym, serves them with state reads, and deletes
a pseudonym's when it stops being a member.
- **What the home learns:** one opaque blob per member per day, and when it
  arrives. It already sees members by pseudonym and the timing of their
  requests; it learns no account or server (the blob is sealed).
- Signal's server hands endorsements out with each group fetch; here the home
  only stores what members bring, as it can't issue.

**3.5 Sending.** For each destination server D:
1. take the endorsements of the recipients on D, from the home's last state,
   with the newest expiration they share; check each once
   (`receive_with_ciphertexts`, D's public key from its signed discovery);
2. `combine` them, `to_token` with the day's params, `into_full_token(expiration)`;
3. send the multi-recipient request with `groupSendToken` in place of
   `capabilities`.
- A recipient without a current endorsement goes pairwise, as a recipient
  without a capability does today (slice 1's path stays the fallback).
- Recipients whose endorsements have different expirations go in one request
  per expiration.
- Own devices go pairwise, as now.

**3.6 Verifying** *(server)*. D recomputes the token over every recipient
account id in the payload with its derived key for the token's expiration
(`GroupSendFullToken::verify`), before devices are looked at (Signal's order,
access first). A token that doesn't verify refuses the whole request: Signal
answers `401`; Kutup answers `200` with every recipient `refused` (the same
outcome as a refused capability today, no existence oracle), and the client
sends pairwise, refreshes the group, and asks for fresh endorsements.

**3.7 Expiry and removal.**
- Expiration: the start of day `d+2` UTC for day `d`'s params, so every
  member's endorsement for a day combines. D issues only day-aligned
  expirations between 2 hours and 7 days ahead (libsignal's own check); the
  client refreshes in the last 6 hours of a day for the next.
- Removal: the removed member can send to the others until their current
  endorsements expire (at most about two days), as in Signal. It gets no new
  ones: it can't read the home's state, and the home deletes its blob.
  Rejoining is a new pseudonym and a new upload.

## 4. Federation *(server)*

- **Keys in discovery.** Each server publishes its `ServerPublicParams`
  endorsement public key and its `GenericServerPublicParams` in its signed
  federation identity document (or a key document signed by that identity),
  with a key id, so members check issuance proofs and senders check
  endorsements of any destination. Verification never needs another server's
  key: D verifies only tokens it issued itself.
- **Rotation.** A new key id keeps the old one for verification until the
  last expiration issued under it (at most 7 days).
- **The federated route.** The origin forwards `groupSendToken` with the
  multi-recipient body to the destination's `/api/fed/chat/sealed/multi`
  unchanged; only the destination verifies it. The origin learns nothing new
  (the token is unlinkable to any group).

## 5. What a server learns, against today

| Who | With capabilities (#297/#334) | With endorsements |
| --- | --- | --- |
| A member's own server | the account's capability count (≈ its group count), hashes used together on each send, rotations | a bucketed group count per day (dummies indistinguishable, nothing stable across days); which of its users share a group on a day (it already learns that from each send) |
| A destination at send time | the recipient set; which capability hashes are used together | the recipient set |
| The home | — | one sealed blob per member per day (timing only) |
| The origin (a remote send) | the raw capabilities, so it could sealed-send to those members within their budget | a token for that recipient set until it expires (Signal has the same) |

## 6. What changes

**Replaced (remove):**
- server: `chat_group_capabilities`, `PUT /api/chat/group-capabilities`,
  `POST …/set`, the `chatGroupCapabilitiesPerAccount` site setting and its
  admin field (#297, #310), the capability check on the multi route and the
  per-capability budget *(server: re-key that budget, e.g. per recipient and
  token hash)*;
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
- client: the day's params, credential fetch and presentations, the daily
  issuance with dummies, the upload to and read from the home, token building
  per destination and expiration, and refresh before expiry;
- server: the credential and issuance routes, the endorsement keys and their
  rotation, the home's endorsement storage, the token check on the multi
  route.

## 7. Migration

None for users: the capabilities never left the server side and no client
release used them. One ordinary migration (numbered above master and open
PRs when built) drops `chat_group_capabilities` and the site setting's row.
#334 is rebuilt on endorsements before it merges.

## 8. Tests and vectors

- Vectors: the day's params derivation (master key, group id, day →
  `CallLinkSecretParams` bytes), checked in, Rust and WASM.
- libsignal's own GSE and call-link credential tests cover the cryptography;
  Kutup tests the composition:
  - a token over the members on one server verifies there, and fails with one
    recipient added, one missing, another day's params, or another server's
    key;
  - a dummy presentation issues and is indistinguishable in the request;
  - a removed member gets no new endorsement, and its old token stops at
    expiry;
  - expirations combine only when equal;
  - a presentation of another account's credential is refused.
- The chat-core harness: its server double issues and verifies with a test
  `ServerSecretParams`; the existing `group_multi_*` tests move over.
- Live, one and two servers *(server)*: issuance, the home's blob storage,
  a federated multi send with a token, a bad token refused whole, key
  rotation in discovery.

## 9. Open for the second session

- Where the two server key sets live, their generation and rotation, and the
  discovery fields.
- The issuance request's limits and budgets, and the per-recipient budget on
  the multi route without capability hashes.
- The home's endorsement operation (format, padding bucket, retention), and
  whether the state read carries the blobs or a separate read does.
- `refused` for everyone vs `401` on a bad token.

## 10. Estimate

Client and crypto (third session): 4–6 days, mostly the issuance and home
round trip and moving the harness. Server and federation (second session):
to estimate.
