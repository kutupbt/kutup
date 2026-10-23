# Chat groups on one-to-one sessions (replacing MLS)

Status: final draft (2026-10-17), with the user's decisions (end of the note)
and both sessions' reviews. Next is the main session's security review of the
pseudonym design. No code before the user's go.
- Replaces: `chat-mls.md` and `chat-invite-links.md` (both removed with MLS groups, §9). MLS groups were never enabled in the beta (`CHAT_GROUPS` is off).
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

**What the servers see of a batch.** One batch request names, to this
account's server and to the destination server, the member accounts on that
server that receive the message together. That is what per-recipient sends
from one IP at the same moment already show; the batch doesn't add to it.

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

The sender answers from its send log: each group message's outbox entry,
kept after delivery with the devices each leg went to (its ciphertexts
cleared).
- Desktop keeps a send log of 14 days at most (`background.preload.ts:1166-1181`),
  and in practice about a day (`Server.node.ts:1681-1696`).
- Ours keeps a delivered message a day, as Desktop does in practice
  (`GROUP_SEND_LOG_MS`); an undelivered one is tried for a week and then fails
  (`GROUP_UNDELIVERED_MS`). A message that disappeared, or that its sender
  edited or deleted (for everyone or for themselves), leaves the log, and so does a
  group's whole log when this account leaves it; the answer is then
  `unavailable`.
- A key and each named message, sent or not, are answered at most once an
  hour per requesting device and group, across reloads and tabs (the direct
  resend limits).

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

**A device that lost its group list.** A device whose list entry was never
written (the only device went within the write's random delay, §5) finds the
group again from the next member's send, built in `group_recover.rs`:
1. The member's next send reaches the new device pairwise: its sender key
   (the device isn't in the member's book), or the message itself when the
   member's device list was out of date. Its context carries the master key
   and home, as Signal's `GroupContextV2` does (§8), and on anything sent
   pairwise to one account it names that account's pseudonym in the group
   (`recipientPseudonym`). The member sends to it because bindings are the
   account's (§3), not a device's.
2. The context's key must be its group's at the home it names (the id binds
   the home), so nobody can name a home of their own. The named pseudonym
   must be one the account key gives (join epochs 0 to 63,
   `MAX_JOIN_EPOCHS`), found locally: a stranger who doesn't know it makes
   the device ask nothing. The attempt then counts against the limits below,
   before anything is asked of a server.
3. The list: the device reads it if it hasn't this run. A group it says the
   account left is never taken up this way; one it holds is taken up from
   the list (its home, epoch and verified revision). A list that can't be
   read stops it (it may say the account left). Only then does the device
   ask the home, once, for that pseudonym.
4. The state is kept only when it holds this account's own binding, verified
   under its own authority (no home can make one up), and the sender is a
   verified member of it. Nothing is kept on failure, and nothing is signed
   anew: the entry is the account's already. The list entry is written back
   with the usual delay.
- Once an hour per group, and at most ten groups an hour per device, across
  reloads.
- The home answers a pseudonym that isn't a member with the same status and
  empty body as an unknown group; only the time differs a little (a known
  group's state is read in full), and the device asks at most once per
  named pseudonym.
- **What is left:** if nobody in the group sends after the loss, the new
  device gets the group back only once someone does. A resend request for
  such groups is not built.
- A recovered group's lowest acceptable state is unknown (`min_revision` 0):
  the members' contexts show a home serving an older one (§3, forks).

**State lag.** Every group message carries the group's revision and chain hash,
as Signal's `GroupContextV2 {masterKey, revision, groupChange}` carries the
revision (`SignalService.proto:947-951`).
- A member that is behind fetches the change log from the group's server (§3).
- **As built (slice 1).** Group content is read, then decided about before
  anything of it is kept (`group_gate.rs`; one commit or none), whether it
  came under the sender key or pairwise (a sender key, a refresh, a resend, a
  fallback; each carries the group context, an invitation aside):
  - a context ahead of this device's verified state, or another head at the
    same revision, makes the device catch up and read the content again;
  - a sender who is a member at that state is taken;
  - a stranger is refused once this device reached the home's latest after
    their envelope arrived (as Signal drops what still doesn't fit after its
    group fetch; one catch-up settles every envelope that came before it),
    when their own context isn't ahead (a removed member, at once and without
    a catch-up), or when readable content of theirs carries no context;
  - what can't be decided now is **held**: a member whose manifest can't be
    fetched, or a stranger while no catch-up worked (an unreachable home). The
    envelope stays queued and is read again on later passes (the browser runs
    another pass 5 seconds after one that held something, doubling to 15
    minutes), given up after a week. At most 8 wait per stranger, 32 per
    member and 256 per group; a full group gives up the newest envelope of
    its biggest holder, strangers before members, so strangers can't use up
    members' room;
  - catch-ups are bounded per group: a context at most 64 revisions past this
    device's state and not asked for yet goes after a 2-second gap, anything
    else waits a back-off from 10 seconds, doubling on failure up to
    15 minutes; a catch-up that reaches the latest while the context is still
    ahead (a forged one) counts as a failure, and one that stops at its page
    limit isn't the latest yet;
  - members are looked up again when the state's head moves, a verified
    manifest's keys are kept for an hour, and a member whose manifest can't
    be fetched is looked up again after the same back-off;
  - another head, or a context still ahead after a catch-up that reached the
    home's latest, flags the group (`forkSuspected`, shown as "the group's
    server may be showing members different versions"); only the member who
    showed it clears it, by matching again;
  - nothing from a blocked account is taken, as in Signal.
  - Every change a member makes (title, invite, claim, leave, remove, role) is
    followed by a `groupChange` notice under the sender key: no body, only the
    context at the new revision, sent with Signal's implicit content hint, so
    it is never history and an unreadable one leaves no placeholder. The other
    members catch up when it arrives. A send whose last catch-up is more than
    five minutes old catches up first.
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

## 3. Group state: Groups v2 on the group's server, members as pseudonyms

**What we copy from `Groups.proto:23-124` and `groups.preload.ts`:**
- **Master key.** A random 32-byte group master key. From it, the group id and
  the state key are derived (the id binds the home; the state key's info
  carries the id, `kutup/chat-group/state-key/v2\0` ‖ group id, with a
  vector in `chat-group-state-key-v2.json`). Signal derives
  `GroupSecretParams` the same way
  (`zkgroup/src/api/groups/group_params.rs:67-86`). Our derivation is HKDF in
  `kutup-crypto`, as every Kutup format is.
  - **The id binds the home** (decided 2026-10-19, after the #268 review). A
    member who keeps the master key after removal (it isn't rotated, as in
    Signal) can't make the group live on a home of their own: there it is
    another group id, which no member's binding names, and every record
    checks that its key gives its id at its home.
    - The id is HKDF-SHA256 over the master key, salt `kutup/chat-group/v1`,
      info `kutup/chat-group/id/v2\0` ‖ the home digest (32 bytes).
    - The home digest is SHA-256 of `kutup/chat-group/home/v1\0` ‖ the server
      name (u16 big-endian length, then its bytes) ‖ the identity document
      hash as the pin writes it (u16 length, then its bytes) ‖ the identity
      sequence (u64 big-endian). A field that is empty or over 255 bytes is
      refused, never cut. Vectors: `chat-group-id-v2.json`.
    - The home is the pin made when the group was created (the genesis
      names it), kept for the group's life. The home's federation identity
      rotating later doesn't move the id: members follow the rotation from
      the pin.
    - The home is fixed (above), so a group never moves; a group on another
      home would be a new group, with a new id.
- **Roles: Signal's two, nothing more (the user, 2026-10-17).**
  `ADMINISTRATOR` and `DEFAULT`, with any number of administrators.
- **Access rules.** `AccessControl {attributes, members, addFromInviteLink}`
  with `ANY / MEMBER / ADMINISTRATOR / UNSATISFIABLE`, as in Signal.
- **Settings.** The title, description, avatar, disappearing timer,
  `announcementsOnly` and `terminated`.
- **Lists.** Pending slots (added, not yet claimed), requesting members
  (`MemberPendingAdminApproval`) and banned members.
- **The rest.** The invite-link password and the revision.

**Members are pseudonyms (the user, 2026-10-17: "the server must not be able
to see members").**
- **The plan.** It follows [`research/20-federated-group-credentials.md`](../research/20-federated-group-credentials.md).
- **Why not Signal's zkgroup.** Signal hides members from its groups server with
  zkgroup, but its credentials are keyed-verification MACs that only the
  issuer's secret can verify (`zkcredential/src/lib.rs:25-29`;
  `presentation.rs:640-642`). That needs one operator, and doesn't work across
  federated servers.
- **The pseudonym.** Each member holds, per group, a signing key pair. The
  group's server knows a member only by that public key.
  - It is derived from the account master key (decided 2026-10-19, after
    spec 38 found a lost-list window): its Ed25519 seed is HKDF-SHA256 over
    the master key, salt `kutup/chat-group-pseudonym/v1\0`, info the group id
    then the **join epoch** (u32 big-endian), in `kutup_crypto::chat_group::
    GroupPseudonymKey` with vectors in `chat-group-pseudonym-v1.json`.
  - The join epoch counts the account's joins of the group: 0 at the first,
    one more at each rejoin after leaving or removal (the device's record and
    the list entry carry it), so a rejoin is a new pseudonym.
  - **Which epoch a join takes:** one past an ended membership the device's
    own record or the account's group list names for the group; a current
    membership the list names is another device's, and its epoch is taken as
    it is (a claim there finds the account in). An unclaimed older
    invitation keeps its epoch. The list is read before an invitation's
    epoch is derived, and again before the claim, so another device's join
    or leave meanwhile counts.
  - **A pseudonym used before (`pseudonymUsed`).** An account that joined,
    left, and lost every record of it (the only device gone, and both list
    writes lost within their random delay) would rejoin at an epoch it used
    before, and the home would see a pseudonym it knew come back. So the
    home keeps a hash of every pseudonym that was ever a member of the group
    or asked to join it
    and refuses a newcomer's claim, link join or join request under one with
    `pseudonymUsed`, only once the change holds in every other way (its
    claim signature or link proof, and the acceptance checks): only that
    pseudonym's owner hears it, and it costs no relay or change budget (§3,
    "A pseudonym comes back only once"). The
    client then moves to the next epoch, saves it, signs the claim again for
    the new pseudonym and sends it at the same revision. No path takes an
    epoch past `MAX_JOIN_EPOCHS` − 1 (63): not an invitation, not the list,
    not this retry (a home that refuses every one stops it there), so
    recovery, which matches epochs 0 to 63, always covers the account's
    place. Joining by link and asking to join get the same retry when the
    client builds them (the home already answers them so).
  - Without the account key the pseudonyms of one account in different
    groups or epochs are unrelated, so they can't be linked across groups.
    This holds as long as the account key is safe; a leaked key exposes the
    group list anyway (§5), and with it every group and pseudonym.
  - So every device of the account finds its pseudonym again from the group
    id alone, even one whose list entry was never written (below, "A device
    that lost its group list").
  - Kutup's MLS code used the same device for owners (`owner_id`,
    `kutup-chat-proto/src/mls/conversation.rs:342-361`).
- **What the server reads, the plain part of the state:**
  - members as `{pseudonym, role, joinedAtRevision}`;
  - pending slots as `{slotId, role, adder's pseudonym, claim public key}`;
  - requesting and banned pseudonyms;
  - the access rules, the invite-link password and the revision.

  **No AccountRef is in it.**
- **What only members read, the part encrypted with the state key:**
  - for each pseudonym, the member's AccountRef, their profile key
    (`Member.profileKey` in Signal) and a **binding**: a signature by the
    account's **self-authority** over `(groupId, pseudonym, AccountRef)`
    (domain `kutup/chat-group/binding/v1\0`; decided 2026-10-19). Members
    check it against the authority key of that account's verified manifest.
    Every device derives the authority from the master key, so devices
    coming and going (a revoked or repaired one) never make a member
    unverified, and a new device needs to sign nothing;
  - **a binding is a transferable proof:** any member can show an outsider a
    signature by account X's long-lived authority saying X is in group G.
    Membership is hidden from the home, not from what members choose to
    show. Signal's zkgroup credentials avoid this; ours don't (it was as true
    with device-signed bindings);
  - for each pending slot, the invited AccountRef;
  - the title, description, timer and avatar reference.
  - The limits are Signal's: a title of at most 1024 encrypted bytes and a
    description of at most 8192 (`groups.preload.ts:255-256`).
  - The cipher is the `kutup-crypto` AEAD, XChaCha20-Poly1305, not Signal's
    AES-256-GCM-SIV: one AEAD suite per `cryptographic-dependencies.md`.
- **The avatar.** It is an encrypted blob under the state key, at most 40 KiB
  encrypted, so it fits one request to the home. That is enough for Signal's
  group avatars, which Desktop scales to a 512-pixel JPEG. It is stored by the
  group's server, and counted against that server's own allowance. Signal's state holds `avatarUrl`, while its CDN holds the bytes.
- **The member list a client uses** (for sending, receiving and answering
  resend requests) is the decrypted AccountRefs whose bindings verify. A member
  whose binding doesn't verify is shown as unverified and treated as a
  non-member (§2, §4). The rest of the group carries on.

**Where the state lives: the server where the group was created (the user,
2026-10-17).**
- The home is fixed, as in Signal (one groups server) and XMPP MUC. There is no
  handover, import or recovery. If that server is gone for good, the group is
  lost, and the client offers "New group with the same people".
- **Reaching it.** Every request goes through the anonymous route below, never a
  signed-in session, and is authorised by a pseudonym's signature.
- **Reads.** State and logs go only to a current member's pseudonym, and logs
  only from its `joinedAtRevision`. A removed pseudonym gets the same refusal as
  a stranger.
- **Tables (the second session's design).**
  - Groups: id, revision, chain head and the encrypted part.
  - Members: pseudonym public key, role and joined revision.
  - Pending slots, requesting and banned pseudonyms.
  - Changes: one row per group and revision, unique, holding the body and the
    previous hash.
  - **No table holds an account id**, local or remote.
  - `current + 1` is taken with the group's row locked, so concurrent changes
    get exactly one winner, and the others get `409`.

**The anonymous route (Oblivious HTTP, RFC 9458).**
- If a member's own server proxied group requests as federation does today, it
  would learn the group id, and the home would learn the account. We copy
  Oblivious HTTP instead:
  1. The client encrypts each request to the home's HPKE key.
  2. The member's own server relays the opaque blob. It learns only the
     destination server.
  3. The home answers through the same relay.
- **The keys.** The encapsulation is RFC 9458's, built with `kutup-crypto`'s
  HPKE (`hpke-rs`), so Rust owns the format.
- **Post-quantum from the start** (decided 2026-10-18). The one suite is X-Wing
  (X25519 + ML-KEM-768, draft-connolly-cfrg-xwing-kem-06, HPKE KEM 0x647a),
  HKDF-SHA256 and ChaCha20-Poly1305, so a request recorded today can't be
  opened later by a quantum computer. There is no X25519-only suite, no
  fallback and no negotiation: the key config names 0x647a and carries the
  1216-byte X-Wing public key, the notary names that config, and a client
  refuses a config or request with any other KEM. The gateway's private key is
  the 32-byte X-Wing seed (derived weekly from the federation identity, as
  before). A request's encapsulated key grows to 1120 bytes. Checked against the
  draft's own vectors; X-Wing runs on RustCrypto's `x-wing` and `ml-kem`
  (`docs/roadmap.md`, dependency advisories, says why not libcrux yet).
- **The home's key is authenticated end to end.** The client fetches the key
  config through its own server, which is also the relay. A dishonest relay
  could hand over its own key, read every request and pass it on. So:
  - the key config, with its key id, is signed by the home's federation
    identity key (v2);
  - the group state's plain part carries that identity public key, pinned at
    genesis by the creator, and every invitation and invite link carries it too;
  - clients verify every key config and every rotation against the pinned
    identity. A change of the identity itself is followed through the existing
    signed identity history, checked from the pin;
  - the gateway accepts the previous key for 24 hours after a rotation.
- **The relay is not an open proxy.**
  - It forwards only to federation peers, resolved through the existing
    DNS- and SSRF-safe transport, only to the gateway path, with a body cap.
  - It adds the server-signed federation envelope, so the home can admit and
    rate-limit per relay server. It adds nothing that identifies the user.
  - The home accepts relay traffic only from authenticated federation servers.
- **One user can exhaust a relay's quota at the home.** The relay's own per-user
  limit is the first defence. The home's per-relay limit is sized for a large
  server's members together.
  - Privacy Pass ([RFC 9576](https://www.rfc-editor.org/rfc/rfc9576.html),
    [9578](https://datatracker.ietf.org/doc/html/rfc9578)) could let the home
    limit per user without learning who: the relay issues tokens to its users,
    and the home redeems them.
  - Its rate-limiting form (ARC) is still an Internet-Draft
    ([draft-ietf-privacypass-arc-protocol](https://datatracker.ietf.org/wg/privacypass/documents/)),
    so v1 uses the per-relay limit and keeps this as the upgrade.
  - The response is bound to the request's encapsulation, so a relay can't swap
    answers.
- **Sizes are padded.** Requests and responses are padded to fixed sizes (1, 4,
  16 and 64 KiB), and log pages are sized to fit. Otherwise the relay could tell
  a claim from a log page or a state fetch by size.
- **Members on the home server itself** use the same route, through their own
  server's relay, never their session.
- **Inside the encrypted request:** the group id, the operation, a timestamp, a
  random nonce, and a signature by the member's pseudonym over all of them.
  - The home refuses a timestamp more than 5 minutes off, and a nonce seen
    within that window. A refusal for the timestamp carries the home's time, so
    a client with a skewed clock corrects and retries. It keeps seen nonces for 10 minutes (twice the skew).
    Changes are protected by `current + 1` as well; for reads, the nonce stops
    replay for amplification.
- **Requests from non-members** (a link's join info, a join request) carry a
  proof of the link password instead of a member signature. They are limited
  per group and per relay server, so a link holder can't flood the group.
- **A pseudonym comes back only once.** The home keeps a hash of every
  pseudonym the group has seen, as a member or a requester (the log is
  pruned and the state forgets who left, so neither can answer it). A claim, a join from the
  link or a request to join whose pseudonym is among them is refused with
  `pseudonymUsed` (`group_route::PSEUDONYM_USED`), so the members never see a
  pseudonym they knew come back after a device lost its join epoch.
  - The home answers it only once the claim's or the link's proof holds and
    the change passes every other check; the request is signed by that
    pseudonym, so only its own holder hears it, and it is no membership oracle.
  - The client derives the next join epoch's pseudonym and tries again, up to
    64 epochs (recovery searches as many). The refusal spends neither the
    relay's failure budget nor the group's change budget.
- **Abuse limits without identity:**
  - **The relay** knows its signed-in user and limits how many requests each
    user may relay per minute, without seeing their contents.
  - **The home** limits per pseudonym, per group and per relay server.
  - A request without a valid member signature is refused before any work, with
    the same answer and in the same time as an unknown group (one decapsulation
    and one lookup either way).

**What the anonymous route can't hide: members on the home server itself.** A
member whose account is on the group's own server uses a relay and a gateway
run by the same operator, often the same process.
- An operator who logs requests, or patches its code, can match "user U relayed
  a blob" with "pseudonym P made request R". That reveals which of its own
  accounts are in its groups.
- That always includes the creator, whose server is the home.
- Hidden membership therefore holds:
  - for **remote members**, against the home;
  - for **local members**, only against an operator that doesn't correlate.
- What reduces the leak, for an honest but curious operator:
  - the relay keeps no log per request and passes blobs on a separate path;
  - the client delays and batches local requests.
- Neither fully removes it, and no design studied does
  ([research 20](../research/20-federated-group-credentials.md), §4).
- **Accepted by the user (2026-10-17)**, stated honestly in the user-facing
  documentation (§9).

**What a member's own server can infer (also stated to users).** A member's own
server, even when it isn't the home, can **infer that two of its users share a
group**:
- group messages reach both at the same moments, often in one multi-recipient
  send;
- both relay requests to the same home at the same times.

This is a statistical inference, and it is stronger for small, busy groups. The
server doesn't learn the group's id, its other members or anyone's role. The
mitigations reduce it but don't remove it:
- timing jitter (below);
- padded sizes;
- relaying through one path with no per-request log.

**Changes.** A change is `Actions {revision = current + 1, ...}`: add (a pending
slot), claim, remove, leave, modify-role, modify profile key,
modify title/avatar/description/timer, modify access, invite-link password,
request, approve, ban, unban and terminate. It has two parts:
- **The plain part, which the server reads:**
  - the pseudonyms and slots added, claimed and removed;
  - roles, access rules, requests, approvals, bans and the invite-link
    password;
  - **which** attributes the change modifies (title, description, timer,
    avatar), without their values;
  - the target pseudonym of a profile-key change;
  - the actor's pseudonym, the previous hash and the revision.
- **The encrypted part:** the AccountRefs, bindings, profile keys and attribute
  values, sealed with the state key.
  - Each sealed field is bound to the group, the field (title, member entry,
    ...) and its subject (the pseudonym or slot), so it can't be moved to
    another place.
  - It is **not** bound to the revision. A field is carried unchanged through
    later revisions; binding the revision would mean sealing every field again
    at every change. Replaying an older value in the same place needs the
    state key, which only members hold, and a member could seal that value
    anyway.
- **A newcomer's change names no resulting state.** A claim, a link join, a
  request or its cancellation is made by someone who never fetched the state:
  its sealed entries would open with a link's master key, and Signal shows a
  requester only the join info. So:
  - the newcomer builds the change from the join info's revision and head;
  - the home computes the result, and its notary signature names the state
    hash;
  - every client recomputes the state with the same check and compares it with
    the notary's hash.

  Every other change names its resulting state.

The server takes exactly `current + 1`. On `409` the client refetches and tries
again, up to 5 times within a minute (`modifyGroupV2`, `groups.preload.ts:1507-1716`).

**Who accepts a change: the server, by the same rules as the clients.**
- In Signal, the groups server decides what it accepts and notary-signs what it
  stores (`server_params.rs:142`). We copy that, with one rule: **every check
  that decides whether a change is accepted is made by the group's server before
  it stores the change, and by every client again.** A change the server
  accepts is then never refused by an honest client, so the group can't freeze
  the way MLS did.
- **The checks, all on the plain part:**
  - exactly `current + 1`, and the previous hash matches the chain head;
  - the actor's pseudonym signature over the change;
  - the actor's role at the previous revision, by Signal's rules (§4):
    `members` for adds, `attributes` for each attribute named, administrators
    for roles, removals, bans, approvals, the link and `terminate`;
  - a profile-key change targets the actor's own pseudonym;
  - a claim is signed by the slot's one-time claim key over the new pseudonym;
  - the last-administrator rule (§4).
- **What the server can't check.** The encrypted part isn't an acceptance check,
  because the server can't read it.
  - Attributes are AEAD-sealed. A bad one fails to decrypt on clients, which
    show an unreadable change while the revision still advances.
  - Encrypted content that the plain part doesn't declare is ignored as
    unreadable, never a reason to refuse.
  - A binding that doesn't verify makes that member unverified (above). It is
    never a reason to refuse the change.
- **Changes by unverified pseudonyms are applied.** Clients apply every change
  the home signed and accepted, so the chain can't freeze. When the actor is an
  unverified member, the change shows with a warning naming them as
  unverified.
  - Sender keys, resends, call keys and group capabilities still go only to
    verified members.
- **What the server can't do.** Signal's server can't add a ghost member,
  because it lacks the master key. Ours can't invent or alter a change either,
  because every change needs a member pseudonym's signature. A pseudonym enters
  only through:
  - a claim of a slot an administrator (or, under `members = MEMBER`, a member)
    signed;
  - a link join that the link's rules allow;
  - the genesis.
- **The chain.** It is `hash(previous change)`, and each change also carries the
  hash of the resulting state.
- **The home signs what it accepts, as Signal's groups server does.** Signal's
  server notary-signs every change it stores (`server_params.rs:142`). Ours signs
  each accepted change with its federation identity, the one pinned at genesis,
  over `(groupId, revision, change hash, resulting state hash)`. After a
  rotation, clients verify it against the identity history.
  - Logs, states and the changes that ride in group messages carry that
    signature.
  - **Clients apply only home-signed changes.** A member can't circulate a
    signed `r + 1` that the home never stored, and two administrators' rival
    changes can't split the receivers.
- **The state hash is one a server can compute.** It covers the canonical
  serialization of the plain part plus the encrypted parts as ciphertext bytes,
  never their decrypted values.
- **Catching up.** In order:
  1. apply a change that rides in a group message, if it is exactly one
     revision on and carries the home's signature;
  2. otherwise fetch `logs/<from>` in pages;
  3. otherwise fetch the whole state (`getGroupUpdates`, `:3585-3792`).

  A member reads the log only from its `joinedAtRevision`
  (`WebAPI.preload.ts:4978-4996`).
- **Announcing.** After a change, the actor sends a group-update message to all
  members, and to a removed member pairwise. Each receiver shows a timeline
  line per change (`'group-v2-change'`).

**Linking a member across groups by timing.** A member's pseudonyms differ per
group, but acting in several groups at once would link them.
- A profile-key change, a binding re-signed after an identity reset, and a new
  device catching up are spread over each group with a random delay of minutes.
- A claim waits a random few seconds to a minute after the invitation arrives,
  rather than following the adder's message at once.
- Sizes are padded (above).

**Verifying changes made before now.**
- **Pseudonym signatures** verify for ever: a member's pseudonym key doesn't
  change while they are a member. So catching up after a long absence needs no
  manifest history for them.
- **A binding** is checked against the self-authority of the account's
  verified manifest, which doesn't change with its devices, so no manifest
  history is needed for it either.
- **After the bound account's authority was reset**, its member re-signs the
  binding from the new manifest, as a profile-key-style change of their own.
  Until then, members see a safety-number notice for them, as for direct chats.
- **Joining.** A new member doesn't verify history from before it joined.
  1. It verifies the claim or join that added it.
  2. It takes the state snapshot whose hash that change carries. This is
     Signal's join, which starts from the state at the joining revision
     (`groups.preload.ts:3977-4016`).

**Membership is the client's.**
- The member list a device uses is the result of its own verified change chain
  and verified bindings. The server's view is never an input.
- A `409` means "refetch and verify again".
- Member devices come only from verified manifests (§1).
- A receiver drops a group message whose sender isn't a verified member at its
  latest verified revision. The one exception is the hold rule for a revision it
  can't fetch yet (§2).
- With `announcementsOnly` on, a receiver also drops messages from members who
  aren't administrators. Only clients can enforce this, because no server can
  read sealed senders.

**Forks and withholding.** A dishonest server could show halves of the group
different branches, or hold changes back. The defences:
- Every group message carries `{revision, chainHash}`. A member that sees its
  own revision with a different hash fetches again. If the difference persists,
  it shows a warning that the group's server is showing members different
  histories.
- Each `chatGroups` entry (§5) keeps the revision and chain hash verified at
  joining, protected by the account head, so another of this account's
  devices refuses a history that doesn't extend it. Each device keeps its own
  last verified revision and refuses older state, as `revisionGuard` does in
  [`rollback-protection.md`](rollback-protection.md). The list is not written
  for every new revision (§5): what one device saw later is not a floor for
  the others.
- One server orders, as in Signal; the signatures and these checks make that
  order verifiable.

## 4. Membership: Signal's rules, checked on pseudonyms

The rules are Signal's, as the Desktop client applies them. The server checks
them on pseudonyms (§3).
- **Create.** The creator is the first administrator. Revision 0 is a signed
  genesis change; the group id comes from the master key at its home.
- **Who may do what** (Signal-Desktop):
  - edit the title, description, avatar and timer: administrators, or every
    member when `attributes` is `MEMBER` (`canEditGroupInfo.preload.ts:9-30`;
    `canChangeTimer.preload.ts`);
  - add members: administrators, or every member when `members` is `MEMBER`
    (`canAddNewMembers.preload.ts:9-27`);
  - the invite link and its setting: administrators (`GroupLinkManagement.dom.tsx:126`);
  - promote and demote, remove, ban, approve requests, change access rules and
    `announcementsOnly`: administrators;
  - end the group for everyone (`terminated`): administrators
    (`ConversationDetails.dom.tsx:255-256`).
- **The last administrator.** An administrator can't leave while the group has
  other members and none of them is an administrator: they choose a new one
  first (`getCannotLeaveBecauseYouAreLastAdmin`, `ConversationDetails.dom.tsx:158-170`).
  - The server enforces it on pseudonyms: a leave or a **self-demotion** by the
    only administrator pseudonym is refused while other member pseudonyms
    remain.
- **An administrator's account ending.** Signal-Desktop has no rule for it, and
  Signal's groups server isn't public, so its behaviour can't be confirmed.
  - With pseudonyms our server can't know that an account ended either.
  - The group keeps working: messages flow, members can leave.
  - Changes that need an administrator wait until an administrator acts. If none
    is left, they never happen. Members can start a new group with the same
    people.
  - So the dead administrator's pseudonym stays for ever. No server can tell its
    account ended.
  - **Decided by the user (2026-10-17): Signal's behaviour, nothing more.** A
    group whose last administrator vanished can't make administrator-only
    changes. The leave and self-demotion rule (choose a successor first) stays.
  - Clients show a member whose account has ended (their manifest is gone) as
    such.
- **Add.** Who may add depends on `AccessControl.members`. Signal's "pending"
  member is made explicit:
  1. The adder writes a **pending slot**. The plain part holds the role, the
     adder's pseudonym and a **one-time claim public key** (Ed25519) that the
     adder generates for this slot. The invited AccountRef is encrypted.
     - Pending slots count toward the member limit (members plus pending ≤
       `CHAT_GROUP_MAX_MEMBERS`), as Signal counts pending members.
  2. The adder sends the group-update message pairwise to the invitee's devices.
     - **As built (slice 1):** a hidden `groupInvite` content, sealed to the
       invitee's devices only, and never kept: no history, no outbox, no copy
       for the adder's other devices, which learn of the slot from the log.
       Only contacts can be invited (their profile key gives the sealed
       capability), as Signal adds only people whose profile key it holds. A
       slot whose invitation couldn't be delivered is revoked at once. The
       invitation also carries the group's name, so it can be shown before the
       invitee joins and reads the state.
     Its encrypted group context carries the master key, the group's server and
     the home's pinned identity, as Signal's `GroupContextV2` carries the master
     key.
     - **Only the invitee's copy** also carries the claim private key, never the
       copy sent to the other members.
  3. The invitee's client fetches the join info (revision and head) through the
     anonymous route. It then **claims** the slot with a change carrying:
     - its new pseudonym;
     - a signature by the claim key over
       `("kutup/chat-group/claim/v1", groupId, slotId, the slot's revision, new pseudonym)`.
       The slot's revision means a claim can't be replayed into a later slot
       with the same id;
     - the pseudonym's own signature over the change;
     - its encrypted binding and profile key.
  4. The server verifies the claim signature with the slot's public key, and
     takes the claim once, under the group's row lock.
     - Nothing the home sees lets it claim the slot itself. With a revealed
       secret, a dishonest home could have dropped the invitee's request and
       claimed an administrator slot with its own pseudonym. Members check that the binding's account is the slot's. The new
     member's `joinedAtRevision` is the claim's.
  5. An invitee who isn't a contact sees the group as a message request (accept,
     block or leave) before anything is sent from their side, as in Signal.
     An invitation from a blocked account is dropped. A group this account
     left or declined takes a new invitation (a new slot) made after the state
     it holds.
     Claiming publishes and sends their group capability (§1). That reveals only
     that a device got the invitation.
  - An unclaimed slot can be revoked by an administrator or by its adder, as
    Signal's pending members can. The server checks "administrator, or the
    adder's pseudonym".
- **Remove.** Administrators remove a pseudonym. The change is sent pairwise to
  the removed member, so they learn of it.
  - Each remaining sender replaces its sender key before its next send (§1).
  - Each remaining member replaces its group capability (§1).
  - The server refuses the removed pseudonym from then on, and removes it from a
    running group call (§6).
  - The removed member keeps the profile keys it already had, as in Signal.
- **Leave.** A member leaves by a change signed by their own pseudonym, subject
  to the last-administrator rule. A leave counts as a removal for the key and
  capability rules.
- **Invite link.** Copied from `GroupInviteLink.contentsV1 {masterKey, inviteLinkPassword}`
  (`Groups.proto:102-111`; `groups.preload.ts:262-358`).
  - The link carries the master key, the 16-byte password and the group's
    server, all in the URL fragment, so no web server log sees them.
  - `addFromInviteLink`: `ANY` joins at once, `ADMINISTRATOR` asks for approval,
    `UNSATISFIABLE` turns the link off.
  - A join or a request is a change carrying the joiner's new pseudonym, the
    password and the encrypted binding. The server checks the password and the
    access rule.
  - Before joining, the person sees the encrypted title, description, avatar
    and member count (`GroupJoinInfo`), fetched through the anonymous route with
    the password.
  - Resetting the link replaces the password. A banned pseudonym can't request
    again.
  - **Bans by account, in the encrypted part.** With pseudonyms the server can't
    recognise a banned person who returns through the link under a new
    pseudonym. So the encrypted part keeps a ban list by AccountRef:
    - a joiner whose binding names a banned account is shown unverified;
    - administrators are prompted to remove them.

    There is no refusal, so the server checks still hold.
  - **Banning someone who joined through the link also resets the link password
    by default**, in the same change, as an option the administrator can untick.
    - Without it, a banned person who still has the link could rejoin under a
      new pseudonym and, as a member, read the member list until an
      administrator removed them. Signal's server prevents that rejoin itself.
    - The server already checks the password, so nothing new is needed there.
  - **Link-join floods.** Pseudonyms cost nothing, so one link holder could fill
    the group's 256 places in minutes. Two defences:
    - the home limits link joins per relay server and per group;
    - administrators get one tap to "remove all unverified".
- **History.** New members see only what is sent after they join, as in Signal:
  - distribution goes only to devices current at send time;
  - each distribution starts at the current iteration;
  - the log is readable only from `joinedAtRevision`;
  - a resend goes only to a message's original recipients (§2).
- **A removed member** keeps what they already received. They can't read
  anything a sender sends after that sender applied the removal; the window
  before then is described in §1.
- **Blocking a member** is client-side only, as in Signal.
  - My devices drop that member's group messages.
  - My own messages still go to them while they're a member.
  - Their hidden pairwise kinds are still taken, checked against membership.
  - It rotates my direct-chat capability only if I also block them as a
    contact.
- **A member's identity change.** As in Signal:
  - each group they share with me shows a safety-number notice line;
  - my sender key for those groups is replaced (§1).

## 5. My group list across my devices, and rollback

- Signal keeps each group's master key in the encrypted storage service, as
  `GroupV2Record`, so a new device knows its groups.
- We keep it in the account, in a new account-head scope, `chatGroups`, one
  entry per group. Each entry holds, sealed under the account master key:
  - the group id;
  - the master key;
  - the group's server;
  - the joined revision;
  - the join epoch my pseudonym is derived at (§3; the entry carries no key
    of its own);
  - my current group capability;
  - the revision and chain hash it verified when it joined.
- Writes go through `listedWrite`, so the server can neither drop a group from
  the list nor bring back a group the person left without the devices noticing
  ([`rollback-protection.md`](rollback-protection.md)). The native clients
  write the head when they arrive, as for pins.
- The entry format (`kutup_crypto::chat_group_list`, vectors in
  `chat-group-list-v1.json`), so that the account's server learns as little
  as possible:
  - Two keys from the account master key: HKDF-SHA256 with salt
    `kutup/chat-group-list/v1\0`, infos `kutup/chat-group-list/id-key/v1\0`
    and `kutup/chat-group-list/seal-key/v1\0`.
  - The entry id is `HMAC-SHA256(id key, "kutup/chat-group-list/id/v1\0" ‖
    group id)`, base64url without padding (43 characters). The server never
    sees a group id, and two accounts in one group have unrelated ids.
  - A sealed entry is `"KUTPGL1\0" ‖ suite u16 (1, XChaCha20-Poly1305) ‖
    revision u64 ‖ nonce (24) ‖ ciphertext and tag`. The AAD is the header
    (magic, suite, revision), the account's key binding (u16 length, then the
    binding) and the 32-byte entry id, so an entry opens only under its own
    id and revision, for this incarnation of the account.
  - The plaintext is `u16 length ‖ GroupListEntryV1 JSON ‖ zeros`, so every
    sealed entry is exactly 4032 bytes. The server reads the revision from
    the header (`inspect`), orders writes by it, and refuses any other size.
- Writes are rare and spread out, so the server can't line up co-members by
  when they write:
  - a device writes an entry only when the account joins a group and when it
    leaves it (or the group ends, or it is removed), never for other changes;
  - each write waits a random 0–10 minutes, and writes that are due together
    go out together; a pending write is kept in the local store, so it
    survives a reload;
  - a device flushes its pending writes before it signs out or unlinks
    itself. A device removed from elsewhere loses them; the account's other
    devices learn of the group through their own sync and write any group
    missing from the list.
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
  the LiveKit token only to a current member's pseudonym, through the anonymous
  route like every group request (§3), and replaces the "room id is the
  capability" rule.
  - The token is short-lived. Its identity is the pseudonym plus a random
    per-call device tag, so the SFU never sees an account.
  - **Members connect to the home's SFU directly**, signalling and media, as
    Signal's clients do (the user, 2026-10-21): the home sees each
    participant's network address and device details next to that call's
    opaque identity, and so next to the pseudonym. Identities and rooms are
    per call, so this ties one participant to one pseudonym in one call. The
    slice 4 server design (§11) states it in full.
  - Participants learn which member is which from the frame-key messages, which
    are pairwise and from verified members.
  - Today's `group_calls.rs` and its federation route are replaced. The meeting
    files move out of `chat_mls/` first.
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
    calls use one shared MLS key. Building it is part of slice 4.
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
  - Group changes: 30 a minute per pseudonym, and 60 a minute per group, so many
    accounts can't flood one log.
  - A multi-recipient send costs one sealed-send unit per recipient capability.
- **Sealed sender.** Group sends are always sealed: multi-recipient with group
  capabilities, or one-to-one with the profile keys from the group state (§1).

## 8. Formats and content (all by AccountRef)

- **The member identity.** It's the libsignal `ProtocolAddress` name
  `aci:<uuid>@<server>` with the device id, as for direct chats.
- **Never an address.** No group record, table, state field, change, capability,
  mention or call token holds an address.
- **Never an account on the group's server.** AccountRefs appear only in the
  encrypted part of the state and in E2EE messages. The server knows members by
  pseudonym (§3). Names come from profiles and pins, as
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
- **`groupChange`** is the group-update message after a change: a hidden
  kind with only the group context (§2). It isn't `groupUpdate`, which stays
  MLS's same-account control until slice 5 removes MLS.
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
  - **The user-facing privacy text** (the Chat help and the threat model) states
    the limits plainly:
    - hidden membership fully holds for members on other servers;
    - for members on the group's own server, it holds only against an operator
      who doesn't correlate its relay with its gateway;
    - a member's own server can statistically infer that two of its users share
      a group, more easily in small, busy groups;
    - the mitigations we have.
- **Broadcasts.** The broadcast threat model
  ([`broadcast-security-threat-model.md`](../broadcast-security-threat-model.md))
  assumes an MLS control group for channel owners. Broadcasts aren't built. Its
  owner group becomes a pairwise group when broadcasts are designed, and is out
  of scope here.

`CHAT_GROUPS` stays the switch. It is turned on once all five slices of §10
are done, when the user decides.

## 10. Slices, split and estimate

**Rollout: all at once (the user, 2026-10-17).** The work is built and merged
in the slices below, but groups stay **off in production** (`CHAT_GROUPS`) until
every slice is done: links and requests, calls, and the MLS removal. Then they
are switched on together.
- The e2e stacks run with groups on from slice 1.
- No interim limit is ever user-visible.

**Slice 1's basic UI (as built).** Shown when the server offers pairwise
groups (`chat.pairwiseGroups`):
- *New group* asks for a name and the contacts to invite.
- The list shows groups this account is in or invited to; an invitation from
  a stranger reads as a message request.
- The thread of an invitation offers Join, Decline and, from a stranger,
  Block.
- A member's thread sends text and replies only; reactions, edits, deletes for
  everyone, media, polls, places, timers, typing and receipts stay hidden
  there until their slice.
- Above the thread, the group says when its server can't be reached, when this
  account may have been removed, and when the server may be showing members
  different keys or versions (never hidden).
- Its details list the members (administrators marked, unverified ones said
  so); administrators promote, demote and remove; anyone may rename it or
  invite contacts as the group's access allows; leaving as the last
  administrator names another first.
- Pairwise groups get links in slice 3; until then they have none (the old
  MLS groups keep theirs until slice 5 removes them).

**Slice 1 builds usable groups first.** In it, group messages are sender-key
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
  - **As built.** A group message's legs and a new sender key's
    distributions each go as one batch per destination server
    (`POST /api/chat/anonymous/messages/batch`), cut at 64 recipients and
    4 MiB. Per leg:
    - `delivered` (stored at the recipient's server) finishes it;
    - `unavailable` and `peerUnsupported` end it as a refused direct send
      does;
    - `refused` (for good, or over 1 MiB) ends it as failed;
    - `deviceMismatch` amends it from the recipient's **verified** device
      list (envelopes to devices still listed are kept, a listed device
      without one gets the message pairwise) and sends it again, up to five
      rounds a pass; a leg that mismatches 20 times in all fails;
    - `pending` (queued at this account's server for the recipient's, which
      may still answer that the devices changed), `conflict` (this
      device's own earlier copy is still queued under the send id, and goes
      out), `rateLimited`, and a batch that didn't go all leave the leg
      waiting. It goes again under the same send id (the server answers
      from its row) after a wait that doubles each pass, from 10 seconds to
      15 minutes.

    A leg not taken within the send log's week fails. A sender key only
    `pending` is not entered in the book: it is noted as queued, not handed
    out again for an hour (a server that is down isn't sent a new copy with
    every message), and handed out again after that. Once a later message
    to the same devices is stored at the recipient's server, the queued key
    (ahead of it in the same queue) is entered in the book; a device
    mismatch drops that account's queued keys, so a fresh one goes to the
    current devices. A `deviceMismatch` after `pending` makes the leg
    *sending* again, since the amended copy isn't held yet. An error on one leg
    (its devices can't be read, its envelopes can't be sealed) leaves that
    leg waiting; one message that can't go never holds up the others; a
    pass that changed nothing writes nothing.

    What the message shows, as Signal does: **sending to N members** while
    this account's server hasn't taken it for some (a limit, no answer);
    **sent** once it has it for every member, even while a member's own
    server is slow or down; and how many member accounts it **never
    reached** (`refused`, `unavailable`, `peerUnsupported`, or the week
    gone), shown as soon as it is known, while the rest may still wait. A
    group message is never shown as "not sent"; a pass that fails as a
    whole is logged to the console and tried again next pass.
  - This is the multi-recipient route's outer shape without libsignal's
    format, so slice 2 replaces the body, not the plumbing.
  - Raising the per-IP default instead would weaken the outer wall for direct
    chats.
- Until slice 2 lands, test stacks cap groups at 64 members, a server
  setting. It is never seen in production, where groups are still off.

| Slice | Third session (chat-core, client) | Second session (server, storage, federation) |
| --- | --- | --- |
| 1. Usable groups | `kutup-crypto` derivations; state and change formats (plain and encrypted parts) in `kutup-chat-proto`, with the server's check list, reviewed by the second session; pseudonyms, bindings, slots and claims; the anonymous route's client side (HPKE encapsulation, signed requests); the state engine (verify, apply, catch up, joining, forks, the `chatGroups` scope) for create, add, claim, remove, leave, admin roles, title, timer and profile keys; sender keys, the book, the per-device sealed send through the batch request, `409`/`410`, key replacement, retry and resend; a basic UI (create, list, thread, members, admin, title, leave, message request); en and tr; e2e specs on one and two servers | State, changes with the server-side checks on pseudonyms (§3), logs and the pseudonym ACL; the anonymous route (the HPKE gateway on the home, the relay on every server, replay and rate limits); the sealed batch request and its federated transaction; the sealed route for group members who aren't contacts; limits; live tests |
| 2. Sending once | Multi-recipient encryption, group capabilities and their rotation, the `404` handling; lifting the 64 cap | The multi-recipient route with shared-payload storage, capability publishing, the destination split |
| 3. Links and settings | Invite links, link joins and requests by pseudonym, approval, access control, description and avatar, announcements-only, banning, ending a group; their UI and specs | Join info through the anonymous route, link checks, requests, avatar blobs, bans |
| 4. Calls | Per-participant frame keys with our LiveKit key provider, rotation on leaving and on removal, ringing below 16, the call UI | The SFU token for pseudonyms through the anonymous route, removal through LiveKit's admin API and its webhook |
| 5. MLS out | Client and core removal | Server removal and the migration |

**Estimate (honest, working days of one session).** The second session's
figures are from its review.

| Slice | Third session | Second session | Calendar, in parallel |
| --- | --- | --- | --- |
| 1. Usable groups (off in production) | 21–28 | 22–28 | about 5–6 weeks, with review and the two-server gate |
| 2. Sending once | 4–5 | 8–10 | about 2 weeks |
| 3. Links and settings | 6–8 | 3–4 | about 1.5–2 weeks |
| 4. Calls | 4–6 | 2–3 | about 1–1.5 weeks |
| 5. MLS out | 3 | 2–3 | about 1 week |

- In all, that's about 38–50 days for the third session and 37–48 for the
  second. The security review's claim keys, home-signed changes and timing
  jitter add about 1–2 and 1.
  - The fixed home removed the ownership moves.
  - Pseudonymous members and the anonymous route add about 4–6 days to each
    session ([research 20](../research/20-federated-group-credentials.md)).
- Applying the account-id slices' 1.5× to the calendar gives **about 10–13
  weeks** for everything, and groups switch on at the end.
- Slice 1 alone carries the highest risk: the state engine and its server-side
  twin are new. If it runs over, it pushes the rest out rather than being cut.

`CHAT_GROUPS` turns on only after slice 5 and its gates, when the user decides.

## 11. Build notes: slice 3, then slice 2 (2026-10-20)

Order (the main session, 2026-10-20): slice 3 (links, requests, settings), then
slice 2 (sending once), then calls, then MLS out. Groups stay off until all of
them are done (the user, 2026-10-20: no early or partial launch).

### Slice 3: what exists, and the formats

**Already in place.** The shared checks (`kutup_chat_proto::group::check`)
apply every slice-3 action: `JoinFromLink`, `RequestToJoin`, `CancelRequest`,
`ApproveRequest`, `DenyRequest`, `ModifyAttribute`, `ModifyAccess`,
`ModifyAnnouncementsOnly`, `ModifyInviteLink`, `Ban`, `Unban`,
`ModifyBanList` and `Terminate`, with the link password compared in constant
time. The home's gateway gates link join info by the link proof, and records
requesters as seen pseudonyms (`pseudonymUsed`). The client handles all of
them when it applies a change, but authors only slice 1's actions and the
title.

**The invite link.**
- `https://chat.<server>/join#<base64url>`. The fragment is
  `GroupInviteLinkV1` in a fixed binary layout, base64url without padding:
  `version (1) ‖ master key (32) ‖ password (16) ‖ identity sequence (u64
  BE) ‖ identity document hash (32) ‖ server (UTF-8, the rest)`. As built
  binary rather than JSON: a link stays under 160 characters with any server
  name. Only its one canonical spelling reads. The fragment never reaches a
  server: not in the path or query, so not in logs or `Referer`. Someone on
  another server opens the same fragment in their own server's Chat.
- The joiner derives the group id from the key and the pin and checks it as
  any invitation is checked (`master_at`). Kept short for QR codes: the pin's
  hash is the 64-character hex form, and the whole link stays under 300
  characters.

**Join info, joining and asking.**
- Join info comes through the anonymous route under the link proof
  (`GroupRequestV1::with_link_password`, a `RequestSigner` for the link). Its
  sealed title, description and avatar open with the link's master key; the
  member count and whether approval is needed are in the clear.
- Joining (`ANY`) and asking (`ADMINISTRATOR`) are changes signed by a new
  pseudonym, at the join epoch a claim would take, with the same
  `pseudonymUsed` retry and the same 64-epoch bound. The change carries a
  member entry sealed as `MemberEntry` (an approval moves it as it is).
- A joiner then takes the whole state and announces, as after a claim. An
  asker is saved as `Requesting`.

**Requests are quiet: admins see them at their next sync** (the main session,
2026-10-20, as proposed).
- Every client syncs each pairwise group when the app opens and about every
  ten minutes: one log read from its revision per group, jittered, paused while
  the tab stays hidden past the usual hidden interval.
- So administrators see a new request at their next sync. A push to them would
  tell the home who the administrators are. The plan and the UI say this as it
  is.
- An approving administrator sends the usual `groupChange` pairwise to the
  newcomer, whose binding now says who they are.
- The requester asks about its own request with `GetRequestStatus` (the home,
  signed by the requesting pseudonym, about that pseudonym only): `pending`
  with the revision and head a cancel needs (so a cancel works after a link
  reset too), `denied`, `member` or `unknown`.
- Denying also bans the pseudonym from the link, as Signal does.

**Bans, and what they can't do.**
- The state keeps banned pseudonyms in the clear, which the home enforces, and
  a ban list by account in the sealed part (`banList`, as built: one sealed
  list of AccountRefs, up to 24 KiB, about 180 accounts), replaced in the same
  change as the ban (`Ban` plus `ModifyBanList`).
- The home sees only pseudonyms, so **it can't enforce a ban on an account**.
  What holds:
  - an administrator's client refuses to approve a request whose binding names
    a banned account;
  - the banned pseudonym itself is refused by the home;
  - a banned account asking again at a new epoch is caught at approval by its
    binding;
  - with approval off (`ANY`), a banned account holding the link can join under
    a new pseudonym. Every member's client then shows it as banned, and
    administrators are asked to remove it. Banning resets the link password by
    default, so the link it held stops working.

**Attributes.**
- Description: sealed text, up to its cap (as the title).
- Timer: sealed `u32` seconds (Signal's `DisappearingMessagesTimer`); 0 is off.
  Every sender applies it to group messages, as in direct chats.
- **Avatar**: the attribute is `{hash, sealed}`.
  - `hash` is the SHA-256 of the sealed blob, in the clear, so the home can
    serve and clean up blobs.
  - `sealed` (`Avatar`, up to 512 bytes) holds the blob's key and its content
    type.
  - The client pads the image to a size bucket (8, 16, 32 or 40 KiB) and seals
    it under a fresh random key, so the same picture in two groups gives
    unrelated hashes: a version byte, a 24-byte nonce, the padded image and a
    16-byte tag (XChaCha20-Poly1305), so exactly 8,233, 16,425, 32,809 or
    41,001 bytes. The home refuses any other length as malformed. The client
    uploads it with `PutAvatar`, then makes the change.
  - `PutAvatar` is authorised as the avatar change is: the signer is a member
    and passes `access.attributes`, checked against the state as it arrives.
  - A change naming an avatar hash must find its blob: the home refuses a
    `ModifyAttribute` for the avatar whose hash is neither the pending nor the
    current blob (`avatarMissing`). Once the change is accepted, the pending
    blob becomes the current one and the old one goes at once.
  - The home keeps the current blob and at most one pending upload per group
    (the pending one goes after 24 hours), counts them against its own limits
    for groups it hosts (not any account's pool, since the home doesn't know
    who uploaded), and answers `GetAvatar` padded to one size, to members and
    under the link proof for the current hash only.
- Announcements-only: only administrators send; other members' messages are
  refused on receipt, as in Signal.

- **Limits are site settings**, admin-editable as every Kutup limit (the
  user's standing rule), never constants: the largest avatar, the avatar
  storage per group, and the link-join and request budget per relay server.

**Server parts** (the second session, agreed 2026-10-20):
- the avatar operations and their storage (above), at most two blobs of
  40 KiB per hosted group, so the existing setting for how many groups a home
  hosts bounds the total (built: `PutAvatar` and `GetAvatar` bodies padded to
  one size, 41,005 bytes, by `pad_group_avatar`, so the sealed sizes don't
  show the relay the bucket; the largest blob and the storage per group are
  site settings, first 41,001 and 82,002; a genesis can't name an avatar);
- `GetAvatar` under the link proof;
- a per-relay-server budget for link joins and requests (about 120 a minute,
  admin-settable), charged before the change is checked;
- `GetRequestStatus` (built: operation tag 9, answer `GroupRequestStatusV1`):
  `unknown` (never `NotFound`) for a pseudonym the group never saw or an
  unknown group, `denied` for a banned one or one the group saw that is now
  neither requesting nor a member (the home's record of seen pseudonyms
  holds members and requesters alike, so a removed member asking gets
  `denied` too); it spends the per-pseudonym budget like any signed request,
  and is no oracle (the asker proves the pseudonym);
- the link-join budgets (built, after review: per relay server and group,
  and per relay server, the site settings
  `chat_group_link_joins_per_relay_group_per_min` and
  `chat_group_link_joins_per_relay_per_min` under Administration → Server
  settings, first 120 and 1200 from `RATE_LIMIT_CHAT_GROUP_LINK_JOINS_*`) are
  charged on `JoinFromLink` and `RequestToJoin` only, once the link's
  password holds and before the rest of the change is checked, so junk
  without the link spends nothing and one link's holders crowd only that
  group; join info keeps its per-group limit;
- `GetRequestStatus` takes the same reads for every answer (no timing
  oracle for a group's existence), and `unknown` spends the relay's failure
  budget.

**Client parts** (the third session):
- the link format, its parser and the link request signer;
- join, ask and cancel with the epoch retry;
- approve, deny, access, link reset, announcements-only, ban and unban, end
  the group, and "remove all unverified";
- the description, timer and avatar formats;
- the receiving rules (announcements-only, banned shown as such);
- the periodic group sync;
- per-change timeline lines;
- the web: wasm and service, the link, request and settings screens moved off
  their MLS versions, en and tr, specs on one and two servers.

### Slice 3: as built (client, 2026-10-20)

- **Link settings.** `set_group_link(off | join | approve)` changes
  `addFromInviteLink`, setting a password the first time; off keeps the
  password, so turning the link on again gives the same link (Signal).
  `reset_group_link` sets a new one. A member previewing their own group's
  link sees "already a member", and no record is made.
- **Requests.** `approve_group_request` refuses a request whose verified
  binding names a banned account (the home can't know accounts).
  `deny_group_request` is `DenyRequest` + `Ban` of the pseudonym, and the
  account goes on the ban list when its binding verified. A rejoiner through
  the link (asking, then approved) takes a whole state over the one it kept,
  as an invited rejoiner does.
- **The ban list.** `GroupBanListV1 {version, banned: [{account,
  pseudonyms}]}`, sorted by account, each account's pseudonyms sorted (at
  most 64, one per join epoch), so lifting an account's ban unbans its
  pseudonyms in the same change. About 150 accounts fit the 24 KiB sealed cap
  (not 180: the pseudonyms are kept with each account).
  - When the list has no room, `groupDetails.banListFull` says so beforehand
    (counted for the longest possible account), the UI says it in the bans
    section and in the ban dialog, and a ban or denial then holds for the
    pseudonym only: the home enforces that; nothing fails.
  - `ban_group_member(resetLink)`: `Ban` (which removes) + the list + a new
    password when the link is on (the default in the UI).
  - "Remove unverified or banned": every non-administrator member whose
    binding didn't verify or whose account is banned, 64 removals per
    change; refused while some member's manifest can't be fetched.
- **Attributes.** Description: trimmed, at most 480 characters
  (`MAX_GROUP_DESCRIPTION_CHARS`, Signal-Desktop's), no control characters
  but newlines. Title: 32 characters in the UI (`MAX_GROUP_TITLE_CHARS`).
  Timer: the sealed `u32` seconds, big-endian; absent is off. Every group
  send of a visible kind carries the group's timer as its own
  `expiresAfterSeconds`.
- **Receiving and sending rules.** Once the group ended, or while it is
  announcements-only for a non-administrator: nothing is sent (the engine
  refuses, the composer is replaced by the read-only line), and what
  arrives is dropped on both receive paths, change notices excepted.
- **A removed member is told** (§4, "Remove"): a removal or a ban sends the
  removed verified account a hidden `groupRemoval` content pairwise,
  carrying the log entry (change and notary). Their device takes it when it
  is the next change of the chain it holds (the notary and the chain head
  prove it; the sender needn't be trusted, so it bypasses the sender gate,
  as an invitation does) and the group is `gone` at once. A device further
  behind learns as before, when the home stops answering it (Signal's server
  doesn't serve a removed member's log either).
- **Timeline lines.** Every change a device verifies (from the log, or its
  own) writes a local `groupUpdate` row with the MLS groups' kinds plus
  `timerChanged`, `addersChanged`, `membersInvited`, `invitationsRevoked`,
  `joinedByInvitation`, `joinedFromLink`, `joinRequested`,
  `joinRequestCanceled`, `joinRequestApproved`, `joinRequestDenied`,
  `memberBanned` and `memberUnbanned`. Its id is `grp:<groupId>:<revision>`,
  so reading a change twice writes one line. Only verified accounts are
  named: a change by or about an unverified pseudonym has no line about it.
  A line whose accounts can't be checked when the change is read is left
  out, never the change.
- **Periodic sync (web).** Each member group is caught up 15 s after the app
  opens, then about every 10 minutes (30 in a hidden tab), ±20%, one group
  at a time.
- **A request's outcome** (`GetRequestStatus`, #285). The asker's device
  asks when the group opens and at each periodic sync: approved takes the
  whole state (a member now), denied or unknown ends the group as `gone`
  here. Content arriving for a group still `requesting` settles the request
  first, so the first messages after an approval aren't dropped (only
  members send to it). Withdrawing is a `CancelRequest` at the revision and
  head the status names, so it works after a link reset too; it is asked
  again once if the log moved meanwhile.
- **The avatar** (#288). The image is scaled down on the device (256×256,
  WebP, under 16 KiB, so the second bucket every home takes), padded to its
  bucket and sealed under a fresh key (`kutup_crypto::chat_group::
  seal_group_avatar`, vector `chat-group-avatar-v1.json`); uploaded with
  `PutAvatar` in the route's padded body; then `ModifyAttribute` names the
  blob's SHA-256 in the clear and `GroupAvatarV1 {version, key,
  contentType}` in the sealed attribute. Members read it back with
  `GetAvatar` and check the hash the state names (a home serving another
  blob is caught); a link's preview reads it under the link proof and opens
  it with the key (the join info names no hash; the AEAD holds). The web
  caches pictures by hash. The home's refusals (`avatarTooLarge`,
  `avatarStorageFull`, `avatarMissing`) are said as such, as every refused
  group change now is.

### Slice 2: client notes (for the server design)

The design is §1 ("Sending once" and "Multi-recipient: a delivery capability
per member"). What the client side settles:
- **Encrypting.** libsignal's `sealed_sender_multi_recipient_encrypt` over
  one destination server's member devices, with recipients as 16-byte service
  ids (the account ids) and the content in `UnidentifiedSenderMessageContent`
  with the group id. One request per destination server, through this
  account's own server as today's sealed route.
- **Capabilities.**
  - Each member draws a random 16-byte capability per group and publishes its
    `SHA-256` to its own server with today's capability publishing (per
    account, no group id).
  - It sends the capability to the other members in a hidden `groupDelivery`
    content kind and keeps it in its group list entry, so its own devices hold
    it.
  - It replaces it in one step when a member is removed or leaves: publish the
    new, unpublish the old, send the new.
- **Sending.** One capability per recipient account in the request; a
  recipient whose capability this sender doesn't hold yet goes by the
  pairwise fallback (slice 1's path, which stays).
- **Answers.**
  - `409` and `410` per account: refetch that account's manifest, never a member
    list from the server, rearrange the book, retry (as direct sends);
  - `404` for a member at the sender's revision: that copy goes pairwise at
    once, the group is refreshed, and the member is retried on the
    multi-recipient route once its new capability arrives.
- **Lifting the 64-member cap** on test stacks once this route carries group
  messages.

Questions for the server design (second session):
- the request shape on the origin and the federated route;
- how capabilities ride with the multi-recipient body;
- shared-payload storage and per-device views (Signal-Server's
  `MessagesCache`);
- the sealed-send units per recipient;
- the destination split;
- the `409`/`410`/`404` answers per account inside one request.

### Slice 2: the server design (second session, 2026-10-20)

Copied from Signal-Server (`MessageController` `PUT /v1/messages/multi_recipient`,
`MessagesCache`'s shared payload, libsignal's `SealedSenderV2SentMessage`),
with the deviations federation forces: capabilities instead of group send
endorsements, one request per destination server, and remote delivery that
is synchronous with the pairwise path as its durable fallback. Reviewed by
the third session (client side) and the main session.

**1. The request.** `POST /api/chat/anonymous/messages/multi?server=<destination>`,
anonymous (no bearer, no cookie), as today's sealed routes. Recipients on the
sender's own server are the same request with `server=<own>`, delivered
locally. Body `SealedMultiSubmissionV1`, canonical JSON:
- `sendId`: dedup and the client's retry key. It counts as seen per
  recipient device only once something was stored for it: a retry after a
  `409`/`410` with the same `sendId` is deduplicated per device, never
  refused as a whole.
- `payload`: base64 of libsignal's sent multi-recipient message (version
  `0x23`, 17-byte service ids = ACI of the account ids), parsed with the Rust
  `SealedSenderV2SentMessage::parse`; each recipient's message is assembled
  with `received_message_parts_for_recipient` (key material
  `range_for_recipient_key_material`). `C_i ‖ AT_i` is per account, not per
  device. No excluded recipients.
- `capabilities`: `{ "<accountId>": "<16-byte capability, base64>" }`, exactly
  the payload's recipient accounts.
- `urgent` (default true): `false` skips web push and only nudges connected
  devices, as Signal's flag (receipts-like traffic never wakes a phone).

Limits, each an admin-editable site setting with Signal's values as defaults:
- the request at most `256 KiB + (32 + 100) × recipients` (about 282 KiB at
  256), base64 aside; the real ceiling is each recipient's assembled message,
  at most 96 KiB (Signal's per-recipient cap);
- at most 256 accounts per request (the group size);
- too large is `413`; a malformed payload, a device listed twice, a
  recipient missing from `capabilities` or the other way round is `400`.

**2. Capabilities.** A new table, because today's `chat_delivery_capabilities`
holds one profile-derived capability per account: `chat_group_capabilities
(user_id, capability_hash bytea(32), created_at)`, no group id.
- `PUT /api/chat/group-capabilities { "add": [hash], "remove": [hash] }`
  (bearer, the owner) adds and removes in one transaction, so a removal's swap
  is atomic; `POST …/set { "hashes": [...] }` sets exactly these (a device
  restoring from its group list).
- At most 1024 per account (a site setting): a call that would pass it is
  refused whole (`409 capabilityLimit`), never trimmed.
- The raw capability is never stored; a recipient's is checked as today's
  (`SHA-256`, constant time).

**3. The order of checks** (Signal's: access before recipients).
1. Parse and size (`400`/`413`).
2. **Capabilities first**, per recipient account. A recipient that isn't a
   local active account or whose capability doesn't hold is `refused`: one
   outcome for all three, so the answer is no account-existence oracle.
3. Budgets (§4), per request, then per recipient: a recipient over its
   budget is `rateLimited`.
4. Devices, only for the recipients that passed 2 and 3: any with missing or
   extra devices → `409 [{accountId, missingDevices, extraDevices}]`; else any
   with a changed registration id → `410 [{accountId, staleDevices}]`. Nothing
   is stored on either, and the answer carries `refused` and `rateLimited` as
   well, so the client handles them in the same retry.
5. Store (§6) and answer `200 { "refused": [...], "rateLimited": [...] }`.
   §1's `404` handling applies to `refused` per member: pairwise at once,
   refresh the group, multi-recipient again once the new capability arrives;
   `rateLimited` members go pairwise later, with back-off.

Recipients are processed in account-id order, so concurrent requests lock
mailboxes in one order.

**4. Budgets: per request or per recipient, said for each.**
- Per request: the anonymous route's per-IP budget, charged once per request
  plus a bytes-per-minute budget per IP, so one message to 256 members costs
  one request (today's batch route charges every recipient after the first,
  which can't carry a 256-member group or CGNAT neighbours; it changes the
  same way, and so do the pairwise SKDMs and the fallback over it).
- Per recipient: a budget per group capability (keyed by its hash), not the
  recipient's shared sealed budget, so one abusive member can only drain one
  group's capability of each member, never their direct sealed route.
- Per origin server and destination: per request and bytes, not per stored
  recipient (today's per-recipient counting gives about two 256-member
  messages a minute).
- The 64-member cap is lifted only with these.

**5. Remote destinations: synchronous, the pairwise path durable.** The
durable sealed federation path doesn't fit a multi-recipient body (its 1 MiB
transaction cap, one sequence per destination that a stuck row would block,
per-recipient settlement). So:
- the origin forwards the request at once to the destination's
  `POST /api/fed/chat/sealed/multi` (signed federation, its own endpoint and
  size cap from §1), waits up to the usual timeout, and relays the answer as
  it is (`200` with `refused`/`rateLimited`, `409`, `410`);
- a slow or unreachable destination is `503 peerUnavailable`: nothing is
  queued, and the client sends those members' copies over the pairwise
  path, which is durable. No late `409`/`410` can be lost, and no row waits
  in a sequence;
- the origin keeps nothing of the body once answered.

**6. Storage once (Signal-Server's shared payload).**
- `chat_shared_payloads (id uuid, payload bytea, created_at)`: `e_pub ‖
  ciphertext`, once per request and destination, inserted only if at least
  one recipient device is newly stored, in the same transaction as the rows.
- Each recipient device gets its ordinary `chat_mailbox` row, its account's
  48 bytes of key material as `content`, and `shared_payload_id` (a foreign
  key, `ON DELETE RESTRICT`). The partial index on `shared_payload_id`
  (`WHERE shared_payload_id IS NOT NULL`) is `CREATE INDEX CONCURRENTLY`, alone
  in its own no-transaction migration.
- A drain assembles `[0x22] ‖ C_i ‖ AT_i ‖ e_pub ‖ ciphertext`, the device's
  ordinary sealed envelope; drain pages are capped by bytes as well as
  count.
- **Collection by reference**, not by a fixed expiry: the mailbox sweep
  (retention, device deletion's cascade, acks) removes rows; then payloads no
  row references are deleted (`NOT EXISTS`, using the index), every sweep and
  best-effort after an ack. Concurrent acks, raised retention and deleted
  devices then never leave or lose a payload.
- Pushes and WebSocket nudges carry no payload: a connected device drains,
  so nothing assembles 256 × 96 KiB in memory at once.

**What a server learns.**
- As Signal's: which of its users share one multi-recipient send.
- The origin sees the raw capabilities for a remote destination, so a
  malicious origin could sealed-send to those members within their group
  budget: parity with today's profile capability on the direct route. A
  member who fears it replaces its capability.
- The destination sees capability hashes used together, so it can link a
  group's members' capabilities, and an add/remove pair links a rotation to
  the one before. It can't tell which group, nor who sends.
- An account's number of capabilities is its number of groups (the client
  may publish padding capabilities; open).
- A request's size reveals its recipient count through the per-recipient
  headers. The client pads the content (libsignal's plaintext padding, to a
  bucket), which hides its length, not the count, as in Signal.

**Questions answered.**
- Dedup after a capability rotation: the server's dedup is per device and
  `sendId`; a copy that arrives twice (multi, then pairwise after a refusal)
  is dropped by the receiver's sender-key duplicate check.
- Retry after `202`: there is no `202` now (§5); a retry after `503` uses the
  pairwise path.
- `urgent=false`: no web push (above).

**Tests.** Unit: validation (`400`/`413`), the order (refused before devices,
`409` before `410`, `refused`/`rateLimited` carried in each), assembly equal to
libsignal's, collection by reference under concurrent acks. Live, one server:
a 3-member send stored once and drained by each device; a stale device; a
refused capability; the payload gone after the last ack and after a device
is deleted. Two servers: the federated send, a remote `409` relayed, `503`
when the peer is down, the destination refusing a foreign account.

**Lifting the 64 cap.** `CHAT_GROUP_MAX_MEMBERS` (a site setting) defaults to
256 (decision 5) once §4's budgets are in; test stacks first.

Estimate as §10 (8–10 days), the budgets and the storage change being most of it.

**Built (second session, 2026-10-21):** group capabilities
(`/api/chat/group-capabilities`), the multi-recipient route on the origin and
the destination (`/api/fed/chat/sealed/multi`, synchronous, `503
peerUnavailable` otherwise), shared-payload storage collected by reference,
drain assembly with pages capped by bytes, and the budgets of §4 (the sealed
batch route counts the address once per request and by bytes too). Every
limit is an administrators' setting (Server settings) with Signal's values
first; requests to the federated route that don't authenticate are limited
per address (`RATE_LIMIT_FED_MULTI_FAILURES_PER_MIN`, 60, charged before the
body is read and given back once a request authenticates), an env rate limit
as the other pre-authentication limits. The server never had the 64 cap: `CHAT_GROUP_MAX_MEMBERS` is 256 and
`GroupLimits` takes at most that; the client lifts its own once this is in.

### Slice 4: group calls, the server design (second session, 2026-10-21)

Agreed with the third session and revised after the main session's review
(LiveKit's server and livekit-client 2.22.3 read for the facts below; ringrtc
isn't in the references, so its points are unverified). Built on §6.

**What the home's server does, and nothing more:** it admits current full
members to a call room on its SFU under opaque identities, tells members who
is in the call and under which era, and puts out whoever the group removed.
Frame keys, ringing and the call line are the clients', end to end.

**1. The call room and its era.**
- A call gets a room of its own on the home's SFU, named `g` + 26 random
  base32 characters when the call starts. The home keeps the group's current
  room (`chat_group_calls`: group, room, era, created at), so the members
  meet in it; a name per call means no room name ties calls of one group
  together over time.
- The **era** (Signal's `eraId`) is HMAC(the home's call key, room name), 16
  bytes: one per room, so every member and every message agrees on it. The
  call key is drawn once and kept for the server's life.
- A new room (and so a new era) is made only when the group has none, or
  LiveKit says its room is gone; under the group's row lock (`SELECT … FOR
  UPDATE`, `INSERT … ON CONFLICT`), so token requests at the same moment share
  one room rather than split the call. An empty room that still exists keeps
  its era: members who rejoin within its timeouts continue the same call.
- LiveKit creates rooms on first join (`room.auto_create`, on by default,
  which meetings use), so **every token carries the room's configuration**
  (`roomConfig` in its grant: maximum participants, the empty timeout before
  anyone joins and the departure timeout after the last leaves; all
  administrators' settings, 75, 300 s and 60 s at first). A room recreated
  from an old token then has the same limits; being a past call's name, it
  holds nobody else and no current member is sent to it.

**2. Opaque identities.** A participant's LiveKit identity is
HMAC(the call key, pseudonym ‖ era ‖ device tag), base64url: stable for one
device in one call, unlinkable across calls and groups, and meaningless to
anyone but the home. The home keeps identity → pseudonym for its rooms'
lifetimes (to put removed members out); members learn whose identity is whose
from the frame-key messages (pairwise, from verified members) and from the
peek (sealed to the asking member).

**3. Signalling goes to the home's SFU directly (the user, 2026-10-21).**
livekit-client opens the SFU's WebSocket with the token in the URL, and the
browser's details (sdk, version, operating system, browser, device model,
network; in newer protocol versions inside the `join_request`'s
`ClientInfo`). The member's browser opens it **directly**, as Signal's
clients reach Signal's SFU, so:
- **the home learns each participant's network address and device details
  next to that call's opaque identity**, and through the identity map, next
  to the member's pseudonym. It still never learns the account. The user
  accepted this limit (2026-10-21); it is told plainly here, in 10, and in
  docs/chat-calls.md "What servers learn".
- What keeps it small: identities and rooms are per call (1, 2), so an
  address ties one participant to one pseudonym in one call, not calls
  together through the SFU's records.
- The client sends as little as the SDK allows: no device model or network
  type it can leave out of `ClientInfo`, and no name or metadata.
- The token travels in the URL's query (`access_token`); the home, its SFU
  and its proxy never log query strings on the `/rtc` path (nginx's log
  format for that location drops `$args`; LiveKit logs no query).
- The relay through the member's own server, which would have hidden the
  address and device details, was considered and not chosen: it costs a
  relayed WebSocket per participant on every member server for a limit the
  user accepts.

**4. Media to the home's SFU, as Signal's.** With the address already
known to the home from signalling, forcing media through the member's own
TURN would hide nothing from it and cost relay bandwidth on every member
server. So the client uses ordinary ICE to the SFU (its own server's TURN as
a fallback, as for direct calls), and the person's "Always relay calls"
setting still forces relay through their own TURN for those who want it. The
SFU's UDP range (50000–60000 by default) must be reachable from browsers and
from other servers' TURN; self-hosting.md says so. TURN quotas (per user,
total, bandwidth per allocation) become administrators' settings applied to
coturn.

**5. `CallToken` (operation 6).** Member-signed through the anonymous route;
its body is `{ "deviceTag" }` (16 random bytes, fresh per call and device).
- Only a **full member** of a group that hasn't ended gets one (a requester
  or a pending slot gets `NotFound`, as a stranger does); a home without an
  SFU answers `Unavailable` and the client says this group's server has no
  calls.
- The answer is `GroupCallTokenV1 { url, token, identity, room, eraId,
  expiresAt, maxParticipants }`.
- The token grants exactly: joining that one room; publishing the camera,
  microphone, screen share and its audio; subscribing; no data publishing
  (the keys go pairwise), no updating its own metadata or name; nothing of
  admin, create, list, record, hidden or agent; an empty name and metadata.
- It lives `chatGroupCallTokenSeconds` (600 s at first). LiveKit refreshes a
  connected participant's token itself (every 5 minutes, at least 10 minutes
  valid), so **removal is not revocation**; see 7.

**6. `GetCallState` (operation 10).** Member-signed, no body.
`GroupCallStateV1 { eraId?, participants: [{ identity, pseudonym }],
maxParticipants, full }`. A room with nobody in it is "no call": no era and
no participants, never an error. The client asks when the conversation opens
and when a `groupCall` line arrives (Signal's peek cadence), not on a timer.

**7. Removal, and the SFU's view of who may be there.**
- Media safety rests on the clients: on a removal every sender switches at
  once to a fresh key sent only to those who remain, so a removed member
  that reconnects sees frames it can't decrypt.
- The home also keeps the room to its members: LiveKit's `participant_joined`
  webhook (signed with the API key) is checked against the group's current
  members, and anyone else is removed at once; every token and peek request
  reconciles the room the same way; after a change that drops members the
  home removes theirs; when the group ends it deletes the room.
- A live test: a removed member reconnecting with its refreshed token is
  put out.

**8. Budgets.** Tokens and peeks per group a minute (120 and 240 at first),
and per pseudonym strictly smaller shares (12 and 24), so one member can't
spend the group's; a server-wide cap on concurrent group-call rooms and
participants. All administrators' settings.

**9. Ringing.** Below 16 members a start rings, as Signal's
`maxGroupCallRingSize`; the starter's own server's setting decides
(`chat.groupCallRingMax` in `/api/auth/settings`).

**10. What each server learns.**
- The home and its SFU: per participant an opaque identity it maps to a
  pseudonym, **the participant's network address and device details** (3,
  accepted by the user); join and leave times; how many are in the call, how
  long it lasts and who is speaking when (LiveKit's audio levels). Never an
  account or media. An address seen in calls of several groups can link the
  pseudonyms behind it across those groups, as an address can on any server
  a person connects to.
- A member's own server: the anonymous-route requests it relays (token and
  peek: that its user is in some group's call on that home, and when), and
  TURN traffic when the person relays. Never which group, never the
  pseudonym.
- docs/chat-calls.md and the threat model say so.

**Client parts** (the third session):
- the frame-key message `{ eraId, identity, generation, ratchetCount, key }`,
  pairwise to verified members only;
- **on a join**, each sender ratchets its key once (LiveKit `ratchetKey`, an
  HKDF step) and sends the joiner only the ratcheted key, so a joiner can't
  open earlier media; the others ratchet within the key provider's window;
- on a leave or a removal, a fresh key, switched to at once;
- its own key provider, the ICE settings of 4, `ClientInfo` kept to what the
  SDK requires (3), no data channel, the peek cadence of 6, and the call UI
  off MLS.

**Operating it.** `CHAT_SFU_URL`, `CHAT_SFU_API_KEY` and
`CHAT_SFU_API_SECRET` only in the home's environment; LiveKit's webhook to the
home; the SFU's UDP range reachable from other servers' TURN. Meeting room ids
are validated so they never begin with `g`. The LiveKit code (tokens, the room
service, webhooks) moves out of `chat_mls/` first; today's `group_calls.rs`
and its federation route go with the MLS removal (slice 5).

**Proto and storage.** `GetCallState` (tag 10); `CallToken` takes a body;
`GroupCallTokenV1` and `GroupCallStateV1` in `group_route.rs`. A migration
for `chat_group_calls` (one row per group) and the identity map.

**Settings** (administrators', Server settings): the room's maximum
participants (75), empty and departure timeouts (300 s, 60 s), the token's
lifetime (600 s), tokens and peeks per group and per pseudonym a minute (120,
240; 12, 24), concurrent call rooms and participants on the server, TURN
quotas and bandwidth, and the ring limit (16).

**Tests.** Unit: identities, the room's configuration and the grants in the
token, the era from the room name. Live, one server with the test stack's
LiveKit: a token and a peek, a non-member's and a requester's `NotFound`, one
room shared by concurrent token requests, a removed member put out on
reconnecting, the room deleted on `Terminate`, the budgets. Two servers: a
member on B gets a token through B's relay and joins A's room, and A's
access log for `/rtc` holds no token.

## Decisions (the user, 2026-10-17)

1. **Home.** The group lives on the server where it was created and never moves.
   If that server is gone, the group is lost. There is no recovery.
2. **Roles.** Signal's two: administrator and member, with any number of
   administrators and Signal's last-administrator rule. There is no owner.
3. **Hidden membership.** No server may see who is in a group. Members are
   per-group pseudonyms, and requests go through the anonymous route
   ([research 20](../research/20-federated-group-credentials.md)). zkgroup is
   not used, because it doesn't federate.
4. **Rollout.** All at once: groups stay off in production until all five
   slices are done.
5. **Size.** At most 256 members.
6. **The limits of hidden membership** are accepted as stated in §3: members on
   the group's own server, and what a member's own server can infer. They are
   told to users plainly.
7. **A vanished last administrator.** Signal's behaviour: the group can't make
   administrator-only changes. The choose-a-successor rule for leaving and
   self-demotion stays.

Still open for the reviewers:
- **Key replacement when a device leaves a member's manifest.** Signal doesn't
  do this. Keep it?
- **Resend from stored history, to original recipients only, with receivers
  asking for a week.** This is today's direct-chat rule; Desktop keeps a send
  log of 14 days at most. Keep it?
