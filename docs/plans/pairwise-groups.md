# Chat groups on one-to-one sessions (replacing MLS)

Status: draft, revised after the main session's review and the second
session's server review (2026-10-17). No code before both accept it and the user
answers the questions at the end.
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
(`ts/model-types.d.ts:60-70`): `{createdAt, distributionId, memberDevices[{account, deviceId, registrationId}]}`.
- Before every send, the device diffs that list with the current member devices
  (`_analyzeSenderKeyDevices`, `sendToGroup.preload.ts:1367-1409`).
- The members come from this device's verified group state, and their devices
  from each member's *verified* manifest (§3, "Membership is the client's").
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
- **Parsing.** The server parses the format with libsignal's own
  `SealedSenderMultiRecipientMessage::parse`, as Signal-Server does.
  `kutup-server` already depends on libsignal-protocol 0.97.2 for the
  sealed-sender certificates.
  - Recipients in that format are 16-byte service ids. Per destination, each is
    the account id, and the destination server is implied.
  - The destination refuses a recipient that isn't one of its local accounts.
  - The origin refuses a message whose recipients don't all route to one
    destination.
- **Storage (as Signal-Server).**
  - The destination stores the shared payload once, with a small per-device view
    (Signal-Server's `MessagesCache` stores a shared multi-recipient payload plus
    views).
  - It assembles each device's message when the device drains its mailbox.
  - It drops the payload when the last view is acknowledged or expires. The
    payload is kept at least as long as mailbox retention.
  - Storing a copy per device would be up to 2560 × 256 KiB for one send.
- Device mismatch is handled as in Signal:
  - `409` lists missing and extra devices;
  - `410` lists stale ones (a changed registration id);
  - the client refetches the *manifests* of those accounts, never a member list
    from the server, rearranges its book and retries
    (`sendToGroup.preload.ts:1059-1168`).
- Today's direct-send recovery (`MAX_SEND_ATTEMPTS = 5`) already has that shape.

**Who may send sealed to a member.** There are two routes, as in Signal.
- **One-to-one: members' profile keys in the group state (copied from Signal).**
  - Signal's `Member` holds the member's profile key, encrypted with the group
    key (`Groups.proto:23-38`), so every member can reach every other one sealed
    and show their name.
  - We copy it. Each member's entry carries their profile key, and a member
    updates their own entry when their profile key changes (Signal's
    `ModifyMemberProfileKeyAction`).
  - The existing sealed route (`chat-protocol.md` §7) then works between group
    members who aren't contacts: the capability is derived from the profile key,
    as today.
  - Hidden pairwise kinds (distribution messages, resends, capabilities, call
    keys) travel this way, and so do slice 1's group messages (§10).
  - This is a change to the direct-chat rule, which until now gave the sealed
    route to contacts only. A group member can now send me a sealed direct
    message. It arrives as a message request, as in Signal.
- **Multi-recipient: a delivery capability per member (a deviation).**
  - Signal proves the sender is in a group with exactly these recipients using
    zero-knowledge *group send endorsements* that its groups server issues
    (`MessageController.java:694-706`; `group_send_endorsement.rs`). They depend
    on one central zkgroup issuer, which a federation of servers does not have.
  - Instead, each member draws a random 16-byte capability per group:
    - it publishes `SHA-256(capability)` to its own server, stored per account
      with no group id as today, so the server can't sort capabilities by group;
    - it sends the capability pairwise to the other members' devices, in a
      hidden `groupDelivery` kind;
    - it keeps it in its `chatGroups` entry (§5), so its own devices have it.
  - Nothing is derived from the master key, so neither an invite-link holder nor
    a removed member can compute it.
  - **Sending.** A sender attaches each recipient's capability. Each recipient
    capability costs one sealed-send unit, so a large group can't stretch one
    budget.
  - **What a server learns.** A server learns that its user accepts sealed mail
    under one more capability. It also sees which of its users share one
    multi-recipient send, as Signal's server does. It learns nothing about the
    sender.
  - **When a member is added.** The new member publishes and sends its
    capability once it processes the add. The members send theirs to it with
    their next distribution message.
  - **When a member is removed or leaves.** Every remaining member that applies
    the change replaces its capability, in one step:
    - it publishes the new hash;
    - it unpublishes the old one at the same moment;
    - it sends the new capability to the remaining members.

    This is atomic with applying the change, as profile capabilities are today.
    A removed member loses delivery to that member at once.
- **A group `404` is never the direct-chat silent drop.** For a direct chat, a
  blocked sender's `404` means "sent, never delivered" (`chat-protocol.md` §7).
  In a group, a recipient that is a member at the sender's current revision and
  answers `404` is usually behind or ahead on a removal. The sender:
  1. sends that recipient's copy over the one-to-one sealed route with the
     recipient's profile-key capability, so nothing waits;
  2. refreshes the group state;
  3. uses the multi-recipient route for that member again once its new
     capability arrives.

  If the one-to-one send fails as well, the copy is retried with back-off within
  the usual limits, and the message shows "not delivered yet" for that member.
  It is dropped only for a recipient who is no longer a member.

**When the sender key is replaced.** Signal replaces it:
- when a member is removed (`sendToGroup.preload.ts:442-453`);
- when a member's identity key changes (`ts/models/conversations.preload.ts:3468-3473`);
- by age, at most 90 days (`sendToGroup.preload.ts:346-354, 900-922`).

We copy all three. We add one trigger: **a device leaving a member's manifest**.
- Signal only drops that device from the book (`:507-525`), so it could still
  read.
- Our reason: a removed device is often a lost one. Kutup already treats
  manifest changes as security events, and the cost is one distribution per
  remaining device at the next send.
- Replacing is lazy, as in Signal: the device deletes its own state, and the
  next send distributes a new key.

**The removal window (as in Signal).** A sender that hasn't yet applied a
removal still encrypts to its old book, so the removed member can read that
sender's messages until the sender catches up. The sender catches up when:
- a remaining member's new capability arrives;
- a `404` makes it refresh;
- any message carries a newer revision.

The window is bounded by how quickly the change reaches each sender. Signal
has the same window between a removal and each sender's next group fetch.

**Fallback.** As in Desktop (`sendToGroup.preload.ts:191-261, 424-428`), a send
falls back to plain pairwise fan-out when sender key cannot apply:
- fewer than two recipient accounts;
- a recipient whose group capability this sender doesn't hold yet;
- a malformed answer.

The fallback is sealed, with the recipient's profile key from the group state.
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
with these additions:
1. **The trigger.** A group message that fails with `NoSenderKeyState`, an
   unknown chain id or a bad signature writes the same `undecryptable`
   placeholder in the group thread. The request goes to the *sending device*
   (named by the sealed certificate) and also names the group id and
   distribution id.
2. **The sender checks before answering.** It uses its own verified group state,
   never the server's word:
   - the requester must be a member of the group at the message's revision;
   - the requesting device must be in that member's verified manifest;
   - the requesting device must have been **one of the message's original
     recipients**. Each group message's history record keeps the recipient
     devices it was sent to, as Desktop's `sendLogRecipients` does
     (`ts/sql/migrations/index.node.ts:1363-1408`). A device added later can't
     pull older history this way.

   Otherwise the sender answers `unavailable`, an explicit refusal, as the
   report's invariant 9 requires.
3. **The answer.** A pairwise `resend` of the stored content, with the current
   distribution message attached. If the ratchet key in the request matches the
   current session, that session is archived first
   (`archiveSessionOnMatch`, `handleRetry.preload.ts:338-368`). A message no
   longer in the history gets just the distribution message, as Desktop's
   `sendDistributionMessageOrNullMessage` sends (`:370-440`).

The limits are today's direct-chat limits, and Desktop's `RETRY_LIMIT = 5` per
message has the same purpose:
- a session is reset at most once an hour per device;
- a message is resent at most once an hour per peer;
- placeholders are asked for again every 10 minutes, and given up after a week
  (`WAITING_GIVE_UP_MS`, `engine.rs:161`).

The sender answers from its own stored history, as for direct chats. There is
no separate send log, so anything still in the sender's history can be sent
again to its original recipients.
- Desktop keeps a send log of 14 days at most (`background.preload.ts:1166-1181`),
  and in practice about a day (`Server.node.ts:1681-1696`).
- We keep ours: it already exists for direct chats and reaches further back.
- A disappearing message that has expired on the sender's side is gone, and the
  answer is `lost`.

**A new device of mine.**
- It learns my groups, each group's master key and my capability from the
  account's group list (§5).
- It fetches each group's state.
- It gets each sender's key at that sender's next send. This is lazy, as in
  Signal, and the retry path covers anything that arrives first.
- No admin action, no other member's help and no group-wide operation is
  involved, so roles survive device replacement.
- It can't ask for messages sent before it existed, because it wasn't an
  original recipient. My older history comes from the chat backup, as for
  direct chats.

**A device that lost its group list.** Every group message carries the master
key, as Signal's does (§8). A device that gets a message for a group it doesn't
know:
1. verifies the group's state with that key;
2. checks that its account is a member;
3. writes the group back into the account's list.

**State lag.** Every group message carries the group's revision and chain hash,
as Signal's `GroupContextV2 {masterKey, revision, groupChange}` carries the
revision (`SignalService.proto:947-951`).
- A member that is behind fetches the change log from the group's server (§3).
- A change of at most 2 KiB rides inside the message itself
  (`SendMessage.preload.ts:111, 407-414`).
- **A revision this device can't fetch** (the group's server unreachable, or a
  change that doesn't verify yet). The message's fate depends on its sender:
  - **A member at this device's latest verified revision:** the message is shown
    as usual. The group shows "can't reach the group's server" and fetches again
    with back-off.
  - **Not a member at that revision** (for example a member just added): the
    message is held, not shown, and is processed once the fetch brings the
    change. A held message is dropped after a week, the same span as unreadable
    ones, and leaves a placeholder saying its sender couldn't be confirmed as a
    member.

**The group's server down.**
- Messages still flow: keys are pairwise, and delivery goes to each member's own
  server.
- Only membership and setting changes wait, and the person is told. This is the
  report's invariant 10 for messaging; changes need the group's server, as
  Signal's need its one groups server.

## 3. Group state: Groups v2, on the group's own server

**What we copy from `Groups.proto:23-124` and `groups.preload.ts`:**
- **Master key.** A random 32-byte group master key. From it, the group id and
  the state key are derived. Signal derives `GroupSecretParams` the same way
  (`zkgroup/src/api/groups/group_params.rs:67-86`). Our derivation is HKDF in
  `kutup-crypto`, as every Kutup format is.
- **The state.** It holds:
  - the members, each `{account, role, joinedAtRevision, profileKey}`, the
    profile key encrypted with the state key (`Member.profileKey`);
  - roles `ADMINISTRATOR` / `DEFAULT`;
  - `AccessControl {attributes, members, addFromInviteLink}` with
    `ANY / MEMBER / ADMINISTRATOR / UNSATISFIABLE`;
  - the title, description, avatar and disappearing timer;
  - `announcementsOnly`;
  - requesting members (`MemberPendingAdminApproval`) and banned members;
  - the invite-link password;
  - the revision.

  There is no delivery secret in the state. Capabilities are per member and
  travel pairwise (§1).
- **Encrypted attributes.** The title, description and timer are encrypted with
  the state key. The limits are Signal's: a title of at most 1024 encrypted
  bytes and a description of at most 8192 (`groups.preload.ts:255-256`).
  - The cipher is the `kutup-crypto` AEAD, XChaCha20-Poly1305, not Signal's
    AES-256-GCM-SIV: one AEAD suite per `cryptographic-dependencies.md`.
- **The avatar.** It is an encrypted blob under the state key, at most 512 KiB,
  stored by the group's server next to the state. The state holds only its id
  and hash.
  - This matches Signal, whose state holds `avatarUrl` while the CDN holds the
    bytes encrypted with the blob key.
  - It counts against the group's server's own allowance, not a member's
    storage pool: remote members have no pool there.
- **Changes.** A change is `Actions {revision = current + 1, ...}`: add, remove,
  modify-role, modify profile key, modify title/avatar/description/timer/access,
  invite-link password, request, approve, ban and unban. It has two parts:
  - a **plain part the server reads**:
    - the accounts added and removed, roles, access rules, requests, approvals,
      bans and the invite-link password;
    - **which** attributes the change modifies (title, description, timer,
      avatar), without their values;
    - the target account of a profile-key change;
    - the actor's manifest sequence, the previous hash and the revision.

    Signal's server reads the same things, through ciphertexts and proofs;
  - an **encrypted part** with the attributes (title, description, timer,
    avatar reference) and profile keys, sealed with the state key.

  The server takes exactly `current + 1`.
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
here lives on **the server where it was created, the group's server**.
- That is the creator's server, but the group belongs to the server, not to the
  creator's account. It outlives the creator leaving or deleting their account.
- A wipe or reset of that server loses the group.
- Members on other servers reach it through their own server, over
  authenticated federation (`/api/fed/chat/groups/...`). The member's server
  attests the account, as federated chat already does.
- **Reads.** State and logs go only to current members, and logs only from the
  member's `joinedAtRevision`. A removed account gets the same refusal as a
  stranger.
- **Tables (the second session's design).**
  - Groups: id, revision, chain head and the encrypted attributes.
  - Members: an AccountRef (`account_id` plus `server`, not a foreign key to
    `users`, since members can be remote), role and joined revision.
  - Requesting and banned accounts.
  - Changes: one row per group and revision, unique, holding the body and the
    previous hash.
  - `current + 1` is taken with the group's row locked, so concurrent changes
    get exactly one winner, and the others get `409`.
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
  else is encrypted, as in Signal: the title, description, avatar, timer and
  link password.
- The server sees:
  - the number of members and who they are;
  - roles and access rules;
  - the timing of changes;
  - the encrypted sizes.
- zkgroup stays possible later. The state format keeps member entries in one
  field, so a later version can encrypt them.

**Who accepts a change: the server, by the same rules as the clients.**
- In Signal, the groups server decides what it accepts (role and access checks
  through zk proofs) and notary-signs what it stores (`server_params.rs:142`).
  Clients take what it signed.
- We copy that, with one rule from the second session's review: **every check
  that decides whether a change is accepted is made by the group's server before
  it stores the change, and by every client again.** A change the server accepts
  is then never refused by an honest client, so the group can't freeze the way
  MLS did.
- The checks, all on the plain part:
  - exactly `current + 1`, and the previous hash matches the chain head;
  - the actor's signature, by a device in the actor's manifest at the sequence
    the change names. The server fetches and verifies that manifest as the
    directory already does, so server and clients judge the same manifest;
  - the actor's membership and role at the previous revision, under
    `AccessControl` and the rules of §4: `members` for adds, and `attributes`
    for each attribute the plain part names;
  - for a profile-key change, the actor is its target: only a member changes
    their own entry.
- The encrypted part isn't an acceptance check, because the server can't read
  it.
  - Its attributes are AEAD-sealed, so a bad one fails to decrypt on clients.
  - Clients show it as an unreadable change, and the revision still advances.
  - Encrypted content that the plain part doesn't declare (an attribute not
    named, a profile key for another account) is ignored as unreadable, never
    a reason to refuse the change.
  - So every acceptance check is one the server makes, and nothing only a
    client can judge decides acceptance.
- **What the server cannot do.** Signal's server can't add a ghost member,
  because it lacks the master key needed to encrypt a member entry. Ours can't
  either, because every change needs a member device's signature:
  - a change the server invents, edits or reorders fails a client's own check;
  - that client then shows the server-lied warning (below);
  - this is the only case where a client refuses a change.
- The chain is `hash(previous change)`, and each change also carries the hash
  of the resulting state.

**Membership is the client's.** These rules hold everywhere; the server's view
is never an input to them:
- The member list a device uses (for its book, for receiving and for answering
  requests) is the result of its own verified change chain.
- A `409` from the group's server means "refetch and verify again". It is never
  "take the server's list".
- Member devices come only from verified manifests (§1).
- A receiver drops a group message whose sender isn't a member at its latest
  verified revision. The one exception is the hold rule for a revision it can't
  fetch yet (§2).
- With `announcementsOnly` on, a receiver also drops messages from members who
  aren't administrators. Only clients can enforce this, because the server
  can't read sealed senders.

**Verifying changes made before now.** A change is checked when the device
first applies it, not again later. The cases:
- **Catching up after being away.** Each change names the actor's manifest
  sequence. A device that has since left the actor's manifest is checked
  against the actor's manifest history (`/api/chat/accounts/:id/manifest-history`),
  which is verified from the pinned account authority as today.
- **The actor's account authority was reset since** (a new incarnation). The old
  incarnation's manifests are no longer reachable from the pin, so that change
  can't be checked directly.
  - It is accepted only if a later change, by an actor this device *can* verify,
    chains over it, vouching for it through the hash chain.
  - Until such a change exists, the group shows that a recent change couldn't be
    confirmed, and the device applies nothing past it. Messaging isn't held up:
    the next verifiable change unblocks everything after it.
  - This needs both an authority reset and a device that was away across it,
    so it is rare.
- **Joining.** A new member doesn't verify history from before it joined.
  1. It verifies the change that added it. That change is by a current device
     of the adder, or of the approving administrator, and carries the hash of
     the resulting state.
  2. It takes the state snapshot at that revision only if the snapshot's hash
     matches.

  This is Signal's join, which also starts from the state at the joining
  revision (`groups.preload.ts:3977-4016`).

**Forks and withholding.** Two administrators can validly sign the same
`current + 1`, and a dishonest server could show each half of the group a
different branch, or hold changes back. The defences:
- Every group message carries `{revision, chainHash}`. A member that sees its
  own revision with a different hash fetches again. If the difference persists,
  it shows a warning that the group's server is showing members different
  histories.
- Each `chatGroups` entry (§5) keeps the last verified revision and chain hash,
  protected by the account head. A server that rolls a group back, or serves an
  older branch to another of this account's devices, is detected. The device
  refuses older state, as `revisionGuard` does in
  [`rollback-protection.md`](rollback-protection.md).
- The research report's deterministic merge rule for partitions (owners beat
  admins, mutual removals) is **not** needed. One server orders, as in Signal;
  the signatures and these checks make that order verifiable.

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
  - **How the added member learns the group**, whether on the same server or
    another:
    1. The adder sends the group-update message pairwise to the new member's
       devices. Its encrypted group context carries the master key and the
       group's server, as Signal's `GroupContextV2` carries the master key.
    2. The new member's client fetches the state from the group's server: a
       remote member through its own server over federation.
    3. It verifies its add (§3) and writes the group to its account's list.
  - An added member who isn't a contact sees the group as a message request
    (accept, block or leave) before anything is sent from their side, as in
    Signal. Processing the add does two things:
    - it writes the member's profile key into their own entry;
    - it publishes and sends their group capability (§1).

    That reveals only that a device got the add, which the delivery itself
    already shows the servers.
- **Remove.** Only administrators may remove. The remover's change is sent
  pairwise to the removed member, so they learn of it.
  - Each remaining sender replaces its sender key before its next send (§1).
  - Each remaining member replaces its group capability (§1).
  - The group's server stops serving state to the removed account, and removes
    it from a running group call (§6).
  - The removed member keeps the profile keys it already had, as in Signal, so
    it can still send one-to-one sealed messages. Those arrive as message
    requests, the same as from any non-contact.
- **Leave.**
  - A member leaves by a change of their own.
  - The last administrator must name another one first. Signal requires this
    too.
  - A leave counts as a removal for the key and capability rules.
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
  - Holding the master key from a link gives no group capability (§1). Before
    joining, it gives only the join info. The server serves state to members
    only.
- **History.** New members see only what is sent after they join, as in Signal:
  - distribution goes only to devices current at send time;
  - each distribution starts at the current iteration;
  - the log is readable only from `joinedAtRevision`;
  - a resend goes only to a message's original recipients (§2).
- **A removed member** keeps what they already received. They can't read
  anything a sender sends after that sender applied the removal; the window
  before then is described in §1.
- **Blocking a member** is client-side only, as in Signal: the server can't see
  sealed senders.
  - My devices drop that member's group messages.
  - My own messages still go to them while they're a member. Leaving them out
    would quietly break the group for them, and an administrator can remove
    them.
  - My devices still take their hidden pairwise kinds (distribution messages,
    capabilities, resends), checked against membership, so the group keeps
    working if I unblock them.
  - Blocking in a group doesn't rotate my direct-chat capability unless I also
    block them as a contact, which is today's rule for direct chats.
- **A member's identity change.** As in Signal:
  - each group they share with me shows a safety-number notice line;
  - my sender key for those groups is replaced (§1).

  Their membership is by AccountRef, so it survives an account authority reset.

## 5. My group list across my devices, and rollback

- Signal keeps each group's master key in the encrypted storage service, as
  `GroupV2Record`, so a new device knows its groups.
- We keep it in the account, in a new account-head scope, `chatGroups`, one
  entry per group. Each entry holds, sealed under the account master key:
  - the group id;
  - the master key;
  - the group's server;
  - the joined revision;
  - my current group capability;
  - the last verified revision and chain hash.
- Writes go through `listedWrite`, so the server can neither drop a group from
  the list nor bring back a group the person left without the devices noticing
  ([`rollback-protection.md`](rollback-protection.md)). The native clients
  write the head when they arrive, as for pins.
- The last-seen revision is written at most once a minute per group, and on
  every membership change, to keep head writes few.
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
  - The token is short-lived, and its identity is the AccountRef plus the
    device. Today's `group_calls.rs` moves out of `chat_mls/` with the meeting
    files.
  - A group whose server has no SFU configured offers no group calls; the
    button says why.
- **Keys.** Each participant draws a random 32-byte frame key and sends it
  pairwise, in a hidden ephemeral kind like `call`.
  - It goes only to the devices of members this device has verified (§3), never
    to whoever the SFU says is in the room. A participant the SFU lists without
    a verified membership gets no key, and the call view shows them as
    unverified.
  - Each device decrypts each sender with that sender's key. This is Signal's
    shape: per-sender media keys over pairwise sessions.
  - LiveKit's end-to-end encryption supports per-participant keys (its key
    provider with shared keys off), but setting a key per remote participant
    from our own messages needs **a key provider of our own**. Today's group
    calls use one shared MLS key. Building it is part of slice 3.
- **When keys change.**
  - When a participant leaves the call, everyone draws a new key and sends it
    only to those still in it.
  - When a member is **removed from the group** during a call, the same
    happens. The group's server also removes their participants through
    LiveKit's admin API, and clients treat the removal as that member leaving
    the call.
  - A participant who joins gets the current keys.
  - This is our rule, stated because RingRTC's isn't visible: leaving must cut
    off, and joining doesn't need to, since a joiner never received earlier
    media.
- **Ringing and the call line.**
  - A start rings the members if the group has **fewer than 16** of them, as in
    Signal: `global.calling.maxGroupCallRingSize` defaults to 16, and a group
    of 16 or more is too big to ring (`isConversationTooBigToRing.dom.ts:9`).
  - Kutup's current "up to 16" changes to match.
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
- **One send.** At most 2560 device headers per send and per destination, within
  Signal's `MAX_RECIPIENT_COUNT = 5000`.
  - The body is Signal's: 256 KiB + 32 for the payload, plus about 100 bytes
    per recipient (`MultiRecipientMessageProvider.java:34-35`).
  - The 1 MiB-per-request and 32-envelope limits of direct chats don't apply
    to the multi-recipient route.
- **Rates.**
  - Group changes: 30 a minute per account, and 60 a minute per group, so many
    accounts can't flood one log.
  - A multi-recipient send costs one sealed-send unit per recipient capability.
- **Sealed sender.** Group sends are always sealed: multi-recipient with group
  capabilities, or one-to-one with the profile keys from the group state (§1).

## 8. Formats and content (all by AccountRef)

- **The member identity.** It's the libsignal `ProtocolAddress` name
  `aci:<uuid>@<server>` with the device id, as for direct chats.
- **Never an address.** No group record, table, state field, change, capability,
  mention or call token holds an address. Names come from profiles and pins, as
  everywhere since [`account-ids.md`](account-ids.md).
- **The group context.** Every group message carries
  `group {masterKey, groupServer, revision, chainHash, change?}` inside the
  encrypted content.
  - This is Signal's `GroupContextV2 {masterKey, revision, groupChange}`, plus
    the group's server and the chain hash.
  - Carrying the master key in every message is how an added member learns the
    group (§4), and how a device that lost its list recovers (§2).
- **New content kinds (hidden, pairwise):**
  - `senderKeyDistribution`;
  - `groupDelivery` (a member's capability, §1);
  - `groupCallKey` (ephemeral).
- **`groupUpdate` is reused** for the group-update message after a change.
- **What groups have, as direct chats do:**
  - text, attachments, replies, quotes and link previews;
  - edits, deletes for everyone (by the sender only, as Signal began; admin
    deletes can come later), reactions, polls and stickers;
  - read and delivery receipts (pairwise, as Signal sends them);
  - typing (pairwise).
  - The disappearing timer is part of the group state (an `attributes` change),
    as in Signal, not a per-message setting.
- **Mentions** name members by AccountRef. A mention of someone who isn't a
  member is shown as plain text.
- **Not in groups at first:** live location, view-once media and the per-chat
  "note" features that direct chats have. Each can follow on its own.
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
  - the `MlsOrderingService` feature-policy type in
    `federation/feature_policy.rs` and its discovery advertisement;
  - the MLS retry job in `jobs.rs`;
  - the MLS admin status in `admin_routes.rs`;
  - the MLS telemetry;
  - `notify_mls_recipient_mailbox` and its hub events.
  - `CHAT_GROUPS`'s check-config entry stays.
  - Files that move out of `chat_mls/` first: the meeting-link files
    (`call_links.rs`, `call_link_history.rs`, `call_link_moderation.rs`,
    `call_link_waiting.rs`) and `group_calls.rs`.
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

**Slice 1 gives usable groups first.** In it, group messages are sender-key
ciphertexts sent as one sealed envelope per member device, over the existing
one-to-one sealed route with the profile keys from the state. This is Desktop's
own fallback path (§1).
- Slice 1 doesn't wait for the multi-recipient route and its shared-payload
  storage, the largest server piece.
- **A sealed batch request (the second session's review).** Today's anonymous
  route takes one recipient account per request, and allows 60 attempts a
  minute per IP (`RATE_LIMIT_CHAT_ANONYMOUS_IP_PER_MIN`). Federated sealed
  traffic allows 600 sends a minute per origin. One message to a 64-member
  group would pass the per-IP limit on its own. Slice 1 therefore adds a batch
  request:
  - one request per destination server, carrying several recipients;
  - each recipient with its own capability and its per-device envelopes;
  - still no shared payload and no sender.

  The per-IP limit counts requests. The per-capability counters stay the
  real limit, one unit per recipient (§7). The origin forwards one federated
  transaction per destination.
  - This is the multi-recipient route's outer shape without libsignal's
    format, so slice 2 replaces the body, not the plumbing.
  - Raising the per-IP default instead would weaken the outer wall for direct
    chats.
- Until slice 2 lands, groups are capped at 64 members, a server setting.

| Slice | Third session (chat-core, client) | Second session (server, storage, federation) |
| --- | --- | --- |
| 1. Usable groups | `kutup-crypto` derivations; state and change formats (plain and encrypted parts) in `kutup-chat-proto`, with the server's check list, reviewed by the second session; the state engine (verify, apply, catch up, joining, forks, the `chatGroups` scope) for create, add, remove, leave, admin roles, title, timer and profile keys; sender keys, the book, the per-device sealed send through the batch request, `409`/`410`, key replacement, retry and resend; a basic UI (create, list, thread, members, admin, title, leave, message request); en and tr; e2e specs on one and two servers | State, changes with the server-side checks (§3), logs and the ACL; federation proxying; the sealed batch request and its federated transaction; the sealed route for group members who aren't contacts; limits; live tests |
| 2. Sending once | Multi-recipient encryption, group capabilities and their rotation, the `404` handling; lifting the 64 cap | The multi-recipient route with shared-payload storage, capability publishing, the destination split |
| 3. Links and settings | Invite links, join requests and approval, access control, description and avatar, announcements-only, banning; their UI and specs | Join info, requests, avatar blobs, bans |
| 4. Calls | Per-participant frame keys with our LiveKit key provider, rotation on leaving and on removal, ringing below 16, the call UI | The SFU token from the group's server, its federation route, removal through LiveKit's admin API |
| 5. MLS out | Client and core removal | Server removal and the migration |

**Estimate (honest, working days of one session).** The second session's
figures are from its review.

| Slice | Third session | Second session | Calendar, in parallel |
| --- | --- | --- | --- |
| 1. Usable groups | 16–20 | 15–19 | about 4–5 weeks, with review and the two-server gate |
| 2. Sending once | 4–5 | 8–10 | about 2 weeks |
| 3. Links and settings | 6–8 | 3–4 | about 1.5–2 weeks |
| 4. Calls | 4–6 | 1–2 | about 1–1.5 weeks |
| 5. MLS out | 3 | 2–3 | about 1 week |

- In all, that's about 33–42 days for the third session and 29–38 for the
  second.
- Applying the account-id slices' 1.5× to the calendar gives **about 9–12
  weeks** for everything.
- Slice 1 alone carries the highest risk: the state engine and its server-side
  twin are new. If it runs over, it pushes the rest out rather than being cut.

## Questions for review

1. **The group's server = the creator's server**, with no move between servers
   in this design. Accept?
2. **No zkgroup at first.** The group's server sees the member list in plain
   form. It checks every change by the same rules as the clients (§3), and
   changes are signed by the actor and hash-chained, so the server can't forge
   them. Accept, with zkgroup left as a later option?
3. **Members' profile keys in the group state** (copied from Signal), so
   members who aren't contacts reach each other sealed one to one. Plus **a
   delivery capability per member for the multi-recipient route**, in place of
   Signal's group send endorsements, replaced at once on removal. Accept?
4. **Key replacement when a device leaves a member's manifest.** Signal doesn't
   do this. Keep it?
5. **256 members** until fan-out is measured (Signal: 1000). Accept?
6. **Resend from stored history, to original recipients only, with receivers
   asking for a week** (today's direct-chat rule; Desktop keeps a send log of 14
   days at most). Keep?
