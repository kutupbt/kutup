# Chat groups on one-to-one sessions (replacing MLS)

Status: draft for review by the main and second sessions (2026-10-17). No code
before both accept it.
- Replaces: [`chat-mls.md`](../chat-mls.md) and [`chat-invite-links.md`](../chat-invite-links.md). MLS groups were never enabled in the beta (`CHAT_GROUPS` is off).
- Background: the research report "Self healing encrypted group chat"
  (2026-10, outside the repository). It compares per-sender keys, pairwise fan-out
  and MLS, and recommends per-sender keys under a membership log that clients
  verify.
- Identity: everything is keyed by the permanent account
  ([`account-ids.md`](account-ids.md)), never by an address.

## The rule

The user's rules (2026-10-08 and 2026-10-17):
- Groups heal by themselves, as one-to-one chats do.
- Copy Signal's group model. Deviate only where federation or Kutup's existing
  design gives a stated reason; every deviation below says why.

Signal's groups have two layers, and we copy both:
1. **Sender keys** for messages. Each sending device has its own key for the
   group. It hands that key to each member device over the existing one-to-one
   (pairwise) sessions, then encrypts each group message once.
2. **Groups v2** for the group itself: members, roles, title, access rules and
   the invite link. The state lives on a server, encrypted with a group master
   key only members hold. It changes by versioned actions.

References used:
- libsignal at the tag chat-core pins, v0.97.2. These are the `rust/` paths in
  the Cargo checkout.
- `Signal-Desktop` and `Signal-Server` in `kutup-references/`. Desktop files have
  `.preload.ts` / `.std.ts` / `.dom.ts` suffixes.
- Signal's groups server is not public. Desktop's calls to it and
  libsignal's `zkgroup` show its contract.
- RingRTC, Signal's calling library, is in none of these repositories, so
  Signal's call keying is only partly visible (see "Group calls").

## 1. Sender keys: copied as they are

**The primitive.** We use libsignal's own `group_encrypt`, `group_decrypt`,
`create_sender_key_distribution_message` and
`process_sender_key_distribution_message`. The code is in
`rust/protocol/src/group_cipher.rs:11-287` and `sender_keys.rs`.
- A sender key is a chain key, its iteration and a signing key pair.
- Each message key is HMAC-derived from the chain. Each message is AES-256-CBC
  encrypted, and signed over its header and ciphertext with the private signing
  key (`protocol.rs:535-560`).
- A receiver keeps at most 5 states per sender, 2000 skipped message keys per
  state, and accepts a forward jump of at most 25 000 (`consts.rs:8-12`).
- chat-core already has the store: `SenderKeyAdapter` (`store.rs:703-740`),
  the IndexedDB `SENDER_KEYS` store and the SQLite `sender_keys` table. Both are
  marked "groups; reserved". No new storage format is needed.

**Distribution.**
- The distribution message carries the chain key at the current iteration, so a
  new holder can't read anything sent before it.
- It travels as a hidden content kind over the pairwise libsignal session to
  each member device, as Desktop's `sendSenderKeyDistributionMessage` does
  (`SendMessage.preload.ts:2812-2865`).
- The distribution id is a random UUID per group, kept with the group
  (`sendToGroup.preload.ts:334-344`). A reset keeps the id and starts a new
  chain id and signing key (`:842-869`).

**Who holds the key: the sender's book.** Copied from Desktop's `senderKeyInfo`
(`model-types.d.ts:60-70`): `{createdAt, distributionId, memberDevices[{account, deviceId, registrationId}]}`.
- Before every send, the device diffs that list with the current member devices
  (`_analyzeSenderKeyDevices`, `sendToGroup.preload.ts:1367-1409`).
- The member devices are those in each member's *verified* manifest, the same
  source as one-to-one sends today.
- New devices get a distribution message pairwise first, then the send restarts
  (`:455-505`).

**Sending once: multi-recipient sealed sender.**
- Kutup already uses libsignal's sealed sender for direct chats
  (`sealed_sender_encrypt` in `session.rs`). Groups use its multi-recipient form,
  as Desktop's `encryptForSenderKey` does (`sendToGroup.preload.ts:1215-1301`):
  1. `group_encrypt` the content.
  2. Wrap it in `UnidentifiedSenderMessageContent` with our sender certificate,
     a content hint and the group id.
  3. `sealed_sender_multi_recipient_encrypt` (`sealed_sender.rs:1362`) over
     that destination's member devices.
- The payload is encrypted once. Each device gets a small header.
- **Federation (a deviation, by necessity).** Signal has one server. We send one
  multi-recipient message per destination server. Each goes over the existing
  sealed path: the client's own server forwards it to `/api/fed/chat/sealed/...`
  without learning the sender, and the destination splits it into its users'
  mailboxes.
- The server parses the format the way Signal-Server does through libsignal
  (`SealedSenderMultiRecipientMessage`). The second session decides whether the
  server links that one libsignal module or uses a parser in `kutup-chat-proto`
  tested against libsignal's vectors.
- Device mismatch is handled as in Signal:
  - `409` lists missing and extra devices;
  - `410` lists stale ones (a changed registration id);
  - the client refetches, rearranges its book and retries
    (`sendToGroup.preload.ts:1059-1168`).
- Today's direct-send recovery (`MAX_SEND_ATTEMPTS = 5`) already has that shape.

**Who may send anonymously to a member: a group delivery capability (a
deviation).**
- Signal proves the sender is in a group with exactly these recipients using
  zero-knowledge *group send endorsements* that its groups server issues
  (`MessageController.java:694-706`; `group_send_endorsement.rs`). They depend on
  one central zkgroup issuer, which a federation of servers does not have.
- We reuse Kutup's own direct-chat design instead (`chat-protocol.md` §7):
  - **The secret.** The group state holds a random `deliverySecret`.
  - **Publishing.** Each member publishes `SHA-256(capability)` to its own
    server, where `capability = HKDF(deliverySecret, salt = canonical recipient AccountRef, "kutup/group-delivery-capability/v1")[0..16]`.
  - **Sending.** A sender attaches each recipient's capability.
  - **What a server learns.** It learns that its user accepts sealed mail under
    one more capability, and nothing about the sender.
  - **Removal.** The secret is replaced when a member is removed (§4). A
    removed member's sends then get the same uniform 404 a blocked contact gets
    today.

**When the sender key is replaced.** Signal replaces it:
- when a member is removed (`sendToGroup.preload.ts:442-453`);
- when a member's identity key changes (`conversations.preload.ts:3468-3473`);
- by age, at most 90 days (`:346-354, 900-922`).

We copy all three. We add one trigger: **a device leaving a member's manifest**.
- Signal only drops that device from the book (`:507-525`), so it could still
  read.
- Our reason: a removed device is often a lost one. Kutup already treats
  manifest changes as security events, and the cost is one distribution per
  remaining device at the next send.
- Replacing is lazy, as in Signal: the device deletes its own state, and the
  next send distributes a new key.

**Fallback.** As in Desktop (`sendToGroup.preload.ts:191-261, 424-428`), a send
falls back to plain pairwise fan-out when sender key cannot apply:
- fewer than two recipient accounts;
- a recipient with no delivery capability yet;
- a malformed answer.

Content kinds that are never group history (receipts, typing, call signalling)
always go pairwise, as today.

## 2. Self-healing

The aim: no group state that only a group-wide agreement can repair. Every
failure is fixed by one pairwise exchange between two devices. That is why
sender keys heal where MLS epochs froze (the research report's main finding).

**Healing at send time** (§1):
- The book is diffed with verified manifests before each send.
- New devices get the key first.
- `409`/`410` are amended and retried.
- `devicesChanged` and a higher `deviceListVersion` drop cached device lists, as
  for direct chats.

**Healing at receive time: retry receipts.** Signal's flow is:
- The receiver sends a `DecryptionErrorMessage` (`handleRetry.preload.ts:621-690`;
  libsignal `protocol.rs:874-960`).
- The sender answers from its send log with a pairwise resend, adding the
  current distribution message (`:129-261, 552-619`).

Kutup already has the same loop for direct chats (`sessionControl{refresh, sendIds}` → `resend` / `unavailable` / `lost`,
`chat-protocol.md` "Unreadable messages and session repair"). Groups reuse it
with three additions:
1. **The trigger.** A group message that fails with `NoSenderKeyState`, an
   unknown chain id or a bad signature writes the same `undecryptable`
   placeholder in the group thread. The request goes to the *sending device*
   (named by the sealed certificate) and also names the group id and
   distribution id.
2. **The sender checks before answering.** The requester must be a member of the
   group at the message's revision, and the device must be in that member's
   verified manifest. The sender uses its own verified group state, never the
   server's word. Otherwise it answers `unavailable`, an explicit refusal, as
   the report's invariant 9 requires.
3. **The answer.** A pairwise `resend` of the stored content, with the current
   distribution message attached. If the ratchet key in the request matches the
   current session, that session is archived first
   (`archiveSessionOnMatch`, `handleRetry.preload.ts:338-368`). A message no
   longer in the log gets just the distribution message, as Desktop's
   `sendDistributionMessageOrNullMessage` sends (`:370-440`).

The limits are today's direct-chat limits, and Desktop's `RETRY_LIMIT = 5` per
message has the same purpose:
- a session is reset at most once an hour per device;
- a message is resent at most once an hour per peer;
- placeholders are asked for again every 10 minutes, and given up after a week
  (`WAITING_GIVE_UP_MS`, `engine.rs:161`).

The sender answers from its own stored history, as for direct chats. There is
no separate send log, so anything still in the sender's history can be sent
again.
- Desktop keeps a send log of 14 days at most (`background.preload.ts:1166-1181`),
  and in practice about a day (`Server.node.ts:1681-1696`).
- We keep ours: it already exists for direct chats and reaches further back.
- A disappearing message that has expired on the sender's side is gone, and the
  answer is `lost`.

**A new device of mine.**
- It learns my groups from the account's group list (§5).
- It fetches each group's state.
- It gets each sender's key at that sender's next send. This is lazy, as in
  Signal, and the retry path covers anything that arrives first.
- No admin action, no other member's help and no group-wide operation is
  involved, so roles survive device replacement.

**State lag.** Every group message carries the group's revision, as Signal's
`GroupContextV2 {masterKey, revision, groupChange}` does
(`SignalService.proto:947-951`).
- A member that is behind fetches the change log from the group's server (§3).
- A change of at most 2 KiB rides inside the message itself
  (`SendMessage.preload.ts:111, 407-414`).

**The group's server down.**
- Messages still flow: keys are pairwise, and delivery goes to each member's own
  server.
- Only membership and setting changes wait, and the person is told. This is the
  report's invariant 10 for messaging; changes need the group's server, as
  Signal's need its one groups server.

## 3. Group state: Groups v2, on the group's own server

**What we copy from `Groups.proto:23-124` and `groups.preload.ts`:**
- **Master key.** A random 32-byte group master key. From it, the group id,
  the state key and the delivery-secret wrapping key are derived. Signal derives
  `GroupSecretParams` the same way (`zkgroup/src/api/groups/group_params.rs:67-86`).
  Our derivation is HKDF in `kutup-crypto`, as every Kutup format is.
- **The state.** It holds:
  - the members, each `{account, role, joinedAtRevision}`;
  - roles `ADMINISTRATOR` / `DEFAULT`;
  - `AccessControl {attributes, members, addFromInviteLink}` with
    `ANY / MEMBER / ADMINISTRATOR / UNSATISFIABLE`;
  - the title, description, avatar and disappearing timer;
  - `announcementsOnly`;
  - requesting members (`MemberPendingAdminApproval`) and banned members;
  - the invite-link password;
  - the `deliverySecret` (ours, §1);
  - the revision.
- **Encrypted attributes.** The title, description, timer and avatar are
  encrypted with the state key. The limits are Signal's: a title of at most 1024
  encrypted bytes and a description of at most 8192 (`groups.preload.ts:255-256`).
  The cipher is the `kutup-crypto` AEAD, XChaCha20-Poly1305, not Signal's
  AES-256-GCM-SIV: one AEAD suite per `cryptographic-dependencies.md`.
- **Changes.** A change is `Actions {revision = current + 1, ...}`: add, remove,
  modify-role, modify title/avatar/description/timer/access, invite-link
  password, request, approve, ban and unban.
  - The server takes exactly `current + 1`.
  - On `409` the client refetches and tries again, up to 5 times within a minute
    (`modifyGroupV2`, `groups.preload.ts:1507-1716`).
- **Catching up.** In order:
  1. apply a change that rides in the message, if it is exactly one revision on;
  2. otherwise fetch `logs/<from>` in pages;
  3. otherwise fetch the whole state (`getGroupUpdates`, `:3585-3792`).

  A member reads the log only from its `joinedAtRevision`
  (`WebAPI.preload.ts:4978-4996`).
- **Announcing.** After a change, the actor sends a group-update message to all
  members, and to a removed member pairwise. Each receiver shows a
  timeline line per change (`'group-v2-change'`).

**Where the state lives (federation).** Signal has one groups server. A group
here lives on **the server of the account that created it, the group's server**.
- Members on other servers reach it through their own server, over
  authenticated federation (`/api/fed/chat/groups/...`). The member's server
  attests the account, as federated chat already does.
- This is the shape the report calls "one owning server per group" (also RCS and
  MIMI). It replaces MLS's replaceable multi-server ordering authorities, which
  is where the freezes came from.
- Not in this design: moving a group to another server. If the group's server
  disappears for good, members start a new group, and the client offers "New
  group with the same people". A later note can add a move.

**What the server sees (a deviation: no zkgroup at first).**
- Signal's server stores each member as a deterministic `UuidCiphertext` and
  authorises requests with zero-knowledge presentations (`AuthCredentialWithPni`,
  `CertificateController.java:96-141`; `server_params.rs:173-189`). Its server
  never learns who is in a group.
- We don't copy that now, for two reasons:
  1. **Federation.** A member's credential would be issued by *their* server,
     and the group's server would verify presentations against every member
     server's zkgroup parameters. Nobody has built that, and Signal's own groups
     server, the reference for it, isn't public.
  2. **What the servers already see.** Federation already shows them the
     accounts that exchange messages, so the gain is smaller than on Signal's
     single server.
- So the group's server keeps the member list in plain form: the AccountRefs and
  their roles. It checks access as an ordinary authenticated ACL. Everything
  else is encrypted, as in Signal: the title, description, avatar, timer, link
  password and delivery secret.
- The server sees:
  - the number of members and who they are;
  - roles and access rules;
  - the timing of changes;
  - the encrypted sizes.
- zkgroup stays possible later. The state format keeps member entries in one
  field, so a later version can encrypt them.

**What the server cannot do (copying Signal's property in our terms).**
- Signal's server cannot add a ghost member, because it lacks the master key
  needed to encrypt a member entry. Our server sees members in plain form, so we
  get the same property by **signing changes**, the research report's
  invariants 2–3.
  - Each change carries the acting device's signature (its identity key, checked
    against the actor's verified manifest, the same rule as inbound
    envelopes today).
  - It carries a MAC with the state key, which only members hold.
  - It carries the hash of the previous change, so the log is a hash chain.
- The server orders and stores the changes; Signal's server likewise
  notary-signs them (`server_params.rs:142`).
- A client applies a change only if:
  - the signature and MAC verify;
  - the chain links;
  - the actor held the needed role at the previous revision.
- A server that invents, edits or reorders a change is caught by every member.
- A server can still *withhold* changes, or show members different histories at
  the same revision. Two defences:
  - Every group message carries `{revision, chain hash}`. Members who see the
    same revision with a different hash fetch again and get a warning if it
    persists.
  - Each device keeps the highest revision it has seen (the `revisionGuard` idea
    of [`rollback-protection.md`](rollback-protection.md)) and refuses older
    state.
- The research report's deterministic merge rule for partitions (owners beat
  admins, mutual removals) is **not** needed. One server orders, as in Signal;
  the signatures only make that order checkable.

## 4. Membership

- **Create.** The creator is the first administrator. The group's server is the
  creator's server. Revision 0 is a signed genesis change; the group id comes
  from the master key.
- **Add.**
  - Who may add depends on `AccessControl.members`.
  - An added member joins at once with `joinedAtRevision`.
  - Signal's `membersPendingProfileKey` state isn't copied. It exists only
    because Signal's server needs a zkgroup profile-key credential before a full
    add. Kutup's profile keys travel in E2EE messages already.
  - An added member who isn't a contact sees the group as a message request
    (accept, block or leave) before anything is sent from their side, as in
    Signal.
- **Remove.** Only administrators may remove. The remover's change:
  - replaces `deliverySecret`;
  - is sent pairwise to the removed member, so they learn of it.

  Every remaining sender then replaces its sender key before its next send (§1).
  The group's server stops serving state to the removed account, so it never
  gets the new delivery secret.
- **Leave.**
  - A member leaves by a change of their own.
  - The last administrator must name another one first. Signal requires this
    too.
  - A leave counts as a removal for the key rule.
- **Roles.** Administrators promote and demote. `attributes` access decides who
  may change the title, avatar, description and timer.
- **Invite link.** Copied from `GroupInviteLink.contentsV1 {masterKey, inviteLinkPassword}`
  (`Groups.proto:102-111`; `groups.preload.ts:262-358`).
  - The link carries the master key and the 16-byte password, and our version
    adds the group's server. All of it sits in the URL fragment, so no web
    server log sees it.
  - `addFromInviteLink`: `ANY` joins at once, `ADMINISTRATOR` asks for approval,
    `UNSATISFIABLE` turns the link off.
  - Before joining, the person sees the encrypted title, description, avatar
    and member count (`GroupJoinInfo`).
  - Resetting the link replaces the password.
  - Banned accounts can't request again.
- **History.** New members see only what is sent after they join, as in Signal:
  - distribution goes only to devices current at send time;
  - each distribution starts at the current iteration;
  - the log is readable only from `joinedAtRevision`.
- **A removed member** keeps what they already received and cannot read
  anything after, provided the sender has seen the removal. A sender that hasn't
  catches up through the 404 on its next send (the old capability is gone),
  refetches and replaces its key. Signal has the same window.

## 5. My group list across my devices, and rollback

- Signal keeps each group's master key in the encrypted storage service, as
  `GroupV2Record`, so a new device knows its groups.
- We keep it in the account, in a new account-head scope, `chatGroups`, one
  entry per group:
  - the group id;
  - the master key, sealed under the account master key;
  - the group's server;
  - the joined revision.
- Writes go through `listedWrite`, so the server can neither drop a group from
  the list nor bring back a group the person left without the devices noticing
  ([`rollback-protection.md`](rollback-protection.md)). The native clients
  write the head when they arrive, as for pins.
- The chat backup ([`chat-backup.md`](../chat-backup.md)) is unchanged: display
  records stay keyed by conversation. A group conversation's key changes from
  today's `Group{groupId: uuid}` to the 32-byte derived id, encoded as
  `group:<base64url>`. No backup contains group records, because groups were
  never on.

## 6. Group calls

**Today.** The call runs on the starter's LiveKit SFU.
- The room id is the capability.
- The frame key is an MLS exporter secret (`chat-calls.md` "Group calls";
  `mls_engine.rs:487-508`).
- Both go with MLS.

**Signal (what is visible).**
- The SFU admits a device with a membership token from the groups server:
  `GET v2/groups/token` and `setMembershipProof` (`groups.preload.ts:1782-1806`;
  `calling.preload.ts:1476-1503`).
- Each participant's media key goes to the others as opaque calling messages
  over the normal one-to-one sessions (`calling.preload.ts:3325-3405`;
  `resendGroupCallMediaKeys`, `:2348-2353`).
- How RingRTC rotates those keys isn't in the references.

**What we copy.**
- **The SFU.** The call runs on **the group's server's SFU**. That server issues
  the LiveKit token only to current members, the same ACL as the state, and
  replaces the "room id is the capability" rule.
  - Members on other servers get their token through their own server over
    federation, as today's `/api/fed/chat/group-calls/token` does. It moves under
    `/api/fed/chat/groups/:id/call-token`.
  - A group whose server has no SFU configured offers no group calls; the
    button says why.
- **Keys.** Each participant draws a random 32-byte frame key and sends it to
  the other participants' devices pairwise, in a hidden ephemeral kind like
  `call`.
  - LiveKit's end-to-end encryption takes per-participant keys (its key provider
    with shared keys off), so each device decrypts each sender with that
    sender's key. This is Signal's shape: per-sender media keys over pairwise
    sessions.
- **When keys change.**
  - When a participant leaves, everyone draws a new key and sends it only to
    those still in the call.
  - A participant who joins gets the current keys.
  - This is our rule, stated because RingRTC's isn't visible: leaving must cut
    off, and joining doesn't need to, since a joiner never received earlier
    media.
- **Ringing and the call line.**
  - A start rings the members if the group has at most 16 of them. Signal's
    `global.calling.maxGroupCallRingSize` defaults to 16
    (`isConversationTooBigToRing.dom.ts:9`), and Kutup's limit is already 16.
  - The call line in the thread is a `groupCall` message sent with the sender
    key (Signal's `GroupCallUpdate {eraId}`).
- **Meeting links** don't change. Their keys come from the link, not from the
  group.

## 7. Limits

- **Members.** At most 256 accounts per group, the same number as MLS today.
  - Signal's limit is remote configuration (`global.groupsv2.groupSizeHardLimit`,
    `limits.dom.ts:27-33`). Its value isn't in the references; it is publicly
    1000.
  - Our reason for less: with 10 devices per account, a key replacement in a
    256-member group is up to 2560 pairwise distributions from one browser.
  - The limit is a server setting (`CHAT_GROUP_MAX_MEMBERS`, at most 256 until
    measured), so it can be raised after measurement.
- **Devices.** The device cap (10 per account, `MAX_ACCOUNT_MANIFEST_DEVICES`)
  bounds the fan-out. Signal allows 6 (`DeviceController.java:91`).
- **One send.** At most 2560 device headers per send, within Signal's
  `MAX_RECIPIENT_COUNT = 5000` and 256 KiB
  (`MultiRecipientMessageProvider.java:34-35`). The 1 MiB-per-request and
  32-envelope sealed limits of direct chats don't apply to the multi-recipient
  route, which gets its own limits from the second session.
- **Rates.** Group changes are 30 a minute per account at the group's server.
  Multi-recipient sends reuse the sealed limits per capability.
- **Sealed sender.** Group sends are sealed only (§1); there's no identified
  fallback, as for direct chats. Distribution messages and resends travel over
  the pairwise sealed path.

## 8. Formats (all by AccountRef)

- **The member identity.** It's the libsignal `ProtocolAddress` name
  `aci:<uuid>@<server>` with the device id, as for direct chats.
- **Never an address.** No group record, table, state field, change, capability
  or call token holds an address. Names come from profiles and pins, as
  everywhere since [`account-ids.md`](account-ids.md).
- **New content kinds:**
  - `senderKeyDistribution` (pairwise, hidden);
  - `groupUpdate`, reused: revision, chain hash and an optional embedded change;
  - `groupCallKey` (pairwise, ephemeral).
- **Group messages.** Every group message carries a `group` context
  `{groupId, revision, chainHash}`. Signal's context also carries the master
  key; ours doesn't, because members already have it from the state or the
  link.
- **Dropped.** `GROUP_CONTROL` [RSV] and the MLS manifest field
  (`MlsManifestDeviceV1`) go away. Manifests lose their MLS key packages.

## 9. Removing MLS

There's no migration: MLS groups were never enabled in the beta, so no data
exists. Once pairwise groups pass their gates, one change removes MLS:
- **chat-core:** `mls_engine.rs` and `mls_engine/` (about 19.6k lines),
  `mls_policy.rs`, `invite_link.rs`, the MLS functions in `engine.rs`, about 98
  WASM exports, and the OpenMLS dependencies in `Cargo.toml` (`openmls*`,
  `tls_codec`, `hpke-rs-rust-crypto`). `hpke-rs` stays for `kutup-crypto`. The
  `libcrux` advisory noted in the roadmap goes with them.
- **chat-proto:** `mls.rs` and `mls/` (about 7k lines), `invite_link.rs`, and the
  MLS manifest field and capability.
- **Server:**
  - `chat_mls.rs` and the MLS files of `chat_mls/`;
  - `/api/chat/mls/*`, `/api/fed/chat/mls/*` and the MLS ordering policy feature;
  - `CHAT_MLS_ORDERING_POLICY` and `CHAT_MLS_CONTROL_SIGNING_KEY`;
  - the `rotate_mls_ordering_policy` command;
  - the fuzz target `mls_control_parsers`.
  - The meeting-link files in `chat_mls/` (`call_links*`) move out first.
  - One migration (the next free number at build time) drops the 30
    `chat_mls_*` tables, including `chat_mls_pending_requests`, plus
    `chat_invite_links` and `chat_invite_requests`.
- **Web:** `mls-service.ts` (and its tests), `invite-links.ts`,
  `group-readiness.ts`, `MlsGroupSecurityDetails.tsx` and the MLS branches of
  `service.ts` and `types.ts`. The group UI (`NewGroupDialog`, `GroupDetails`,
  `groupLink/`, `GroupCallScreen`) is kept and rewired.
- **Specs and docs:**
  - Specs 36, 38 and the group parts of 32, 34 and 42 are rewritten for pairwise
    groups.
  - `docs/chat-mls.md` and `docs/chat-invite-links.md` are deleted.
  - These docs are updated: `chat-protocol.md` §2 and §8, `chat-calls.md`
    "Group calls", the threat model, `self-hosting.md`, `api.md` and the
    roadmap.
- **Broadcasts.** The broadcast threat model
  ([`broadcast-security-threat-model.md`](../broadcast-security-threat-model.md))
  assumes an MLS control group for channel owners. Broadcasts aren't built. Its
  owner group becomes a pairwise group when broadcasts are designed, and is out
  of scope here.

`CHAT_GROUPS` stays the switch. It is turned on only when the user decides,
after the gates.

## 10. Slices, split and estimate

| Slice | Third session (chat-core, client) | Second session (server, storage, federation) |
| --- | --- | --- |
| 1. State | `kutup-crypto` derivations; group state, change and signature formats in `kutup-chat-proto` (reviewed by the second session); the client state engine: verify, apply, catch up, revision guard; the `chatGroups` head scope | Tables and routes for state, changes (`current + 1`, `409`) and logs; federation proxying of member requests; the ACL |
| 2. Messages | Sender keys, the book, multi-recipient sealed send, the fallback, `409`/`410`, key replacement, retry and resend for groups | The multi-recipient sealed route and federated split; group delivery capabilities; limits |
| 3. App | Rewire the group UI: create, details, roles, access, link, requests, message requests; en and tr strings; e2e specs, two servers included | Invite-link join info and requests; live tests |
| 4. Calls | Per-participant frame keys, rotation on leave, the call UI | SFU token from the group's server, its federation route |
| 5. MLS out | Client and core removal | Server removal and the migration |

**Estimate (honest, working days of one session):**
- **Third session:** about 30–40 days in all.
  - Formats and crypto: 3–4.
  - State engine: 5–7.
  - Sender keys and sending: 5–7.
  - Healing: 3–4.
  - WASM/TS service: 3–4.
  - UI: 5–7.
  - Calls: 2–3.
  - Specs: 3–5.
- **Second session:** about 20–27 days in all.
  - State and logs: 5–7.
  - Federation and ACL: 4–6.
  - Multi-recipient route and capabilities: 5–7.
  - MLS removal and migration: 2–3.
  - Live tests: 3–4.
- **Calendar:** about 6–8 weeks with both in parallel, including review and the
  two-server gate. Slice 1 blocks the rest. The account-id slices ran about
  1.5× their estimate, and this is larger, so plan for the upper end.

## Questions for review

1. **The group's server = the creator's server**, with no move between servers
   in this design. Accept?
2. **No zkgroup at first.** The group's server sees the member list in plain
   form; changes are signed by the actor and hash-chained so the server can't
   forge them. Accept, with zkgroup left as a later option?
3. **Group delivery capabilities** in place of Signal's group send endorsements.
   Accept?
4. **Key replacement when a device leaves a member's manifest.** Signal doesn't
   do this. Keep it?
5. **256 members** until fan-out is measured (Signal: 1000). Accept?
6. **Resend from stored history, receivers asking for a week** (today's
   direct-chat rule; Desktop keeps a send log of 14 days at most). Keep?
