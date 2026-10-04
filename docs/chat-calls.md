# Kutup Chat calls

Voice and video calls, as Signal has them:

- **One-to-one calls:** media goes directly between the two browsers
  (WebRTC). Everything that sets a call up travels end-to-end encrypted
  through the existing Direct (libsignal) session.
- **Group calls:** media goes through the SFU of the server that started the
  call, with frames end-to-end encrypted under a key only the group's MLS
  members can derive. See "Group calls" below.

## Signaling

A call is a short exchange of `call` messages (`CallSignalV1`), a content
kind that is ephemeral like typing:

- the engine never stores it as history;
- it is never copied to the sender's other devices;
- a copy that is still undelivered after 60 s is dropped instead of being
  sent late.

| Signal | From | Carries |
| --- | --- | --- |
| `offer` | caller | `media` (`audio`/`video`), the SDP offer |
| `answer` | a callee device | the SDP answer |
| `ice` | either | 1–32 ICE candidates (sent in batches every 250 ms; each send fetches the peer's keys, which is rate-limited) |
| `hangup` | either | `reason`: `normal`, `declined`, `answeredElsewhere`, `declinedElsewhere`, `unanswered`, `failed` |
| `busy` | a callee device | the callee is already in a call |

Every signal carries `callId`, `callerDeviceId` and, once a callee device
has answered, `calleeDeviceId`. Signals go to every device of the other
account. Devices ignore those not meant for them, so the exchange stays
between the caller's device and the device that answered:

- An offer rings every device of the callee.
- The first answer wins. The caller then sends `answeredElsewhere` naming
  that device, and the callee's other devices stop ringing.
- A decline on one callee device becomes `declinedElsewhere` for the others.
- The caller keeps its ICE candidates until it knows which device answered.

Several tabs of one browser share a device:

- Incoming calls ring in one tab per account, the holder of a "call desk"
  Web Lock.
- Signals reach every tab over a BroadcastChannel.
- A Web Lock held during any call makes the desk answer `busy` to other
  callers.

**Who can call:**
- A call from someone who isn't an accepted contact doesn't ring. The
  engine suppresses it like typing, as Signal does.
- Calls are refused in Note to Self and as MLS group content.
- An offer older than 45 s doesn't ring. It is recorded as a missed call,
  for example when Chat opens after the call is over.

**Media:**
- Encrypted with DTLS-SRTP.
- The DTLS fingerprints sit in the SDP, which arrives end-to-end encrypted
  and authenticated. The media keys are therefore bound to the two
  accounts, without a server that could swap them.
- Both sides always negotiate a video line in both directions. Turning the
  camera on during a voice call is then a track swap, not a new offer.

**Screen sharing:**
- Either side can send its screen (a window, a tab) in place of its camera.
  It rides the video line that is already negotiated, so starting and
  stopping are track swaps too, and it is encrypted like the camera.
- Stopping brings the camera back if it was on before. The browser's own
  "Stop sharing" control stops it the same way.
- The control shows only where the browser can capture a screen; most phone
  browsers cannot, and they still see a screen shared with them.

**Timeouts:**
- A call rings for 60 s.
- A dropped connection gets 10 s to recover before the call counts as
  failed.

## Call history

When a call ends, the device that took part writes a `callLog` record
(`CallLogBody`: `callId`, `incoming`, `media`, `outcome`, `startedAtMs`, and
`durationSeconds` when answered) into that conversation. The outcome is one
of `answered`, `missed`, `declined`, `unanswered`, `busy` or `failed`.

- **Local only:** like group notices, the record never travels and is
  refused on every receive path. Its id is the call id, so a record is
  written once.
- **Other devices:** a device that didn't take part (because another one
  answered or declined) writes nothing.
- **Display:** records show as centered notices ("Missed voice call",
  "Outgoing video call · 3:07") with "Call back", and in the chat list
  preview.
- **Backup:** the continuous backup keeps them.

## Group calls

A group call runs on the LiveKit SFU of the server of whoever starts it (its
host; `CHAT_SFU_URL`, `CHAT_SFU_API_KEY`, `CHAT_SFU_API_SECRET`). Accounts of
a server without an SFU can join calls others host but not start one (the
capability `chat.groupCalls`).

**Starting and ending:** starting a call sends one `groupCall` message
(`GroupCallBody`) to the group over MLS. It carries:
- `callId`;
- `event` (`started` / `ended`);
- `host`;
- `media`;
- a `roomId` of 128 random bits;
- a 32-byte `secret`.

The start shows in the timeline ("Alice started a group call") with Join,
and the header offers Join while the call is on. The last participant to
leave sends `ended`. A start nobody ended (a crash) stops showing after 12
hours. `groupCall` is refused as Direct content.

**Joining:**
- A member asks its own server for an SFU token
  (`POST /api/chat/group-calls/token` with host, room and participant tag).
- If the host is another server, the request goes over signed federation
  (`POST /api/fed/chat/group-calls/token`).
- The host mints a 6-hour LiveKit token for that one room (join, publish,
  subscribe; never room admin).
- The room id is the capability: only the group's members know it.

**Frame encryption:**
- Browsers encrypt media frames before they leave (insertable streams,
  livekit-client's E2EE worker). The SFU forwards frames it cannot read.
- The key is an MLS exporter secret of the group's current epoch, labelled
  `kutup group call frame key v1` with the call id as context. Only the
  current members can derive it.
- A membership change advances the epoch and changes the key. Each epoch's
  key sits at key index `epoch mod 16`, so frames from a member one step
  behind still decrypt while the Commit reaches everyone.
- Participants check for a new epoch every 3 s, and at once when a frame
  fails to decrypt.

**Who is who:**
- The SFU sees each participant only as a tag: the first 12 bytes of
  `HMAC-SHA256(secret, address)` in hex, plus 4 random bytes per join.
- Members compute the tags of the group's roster to name the tiles. The SFU
  cannot, without the secret.

**Screen sharing:** a participant can publish its screen beside its
camera. It is one more track through the SFU, with its frames encrypted
under the same key as the others. While someone shares, the screen takes the
stage and the participants move to a strip beside it.

**Ringing:** in groups of up to 16 members, a start less than 45 s old rings
the other members, with Join, Join with video and Decline, a ringtone, and
a notification when the tab is hidden. One tab per account rings (the call
desk). Larger groups only show the notice, as in Signal.

**Members added during a call:** they never received the start. When a
participant's key refresh finds new members in the roster, the participant
with the lowest SFU identity (exactly one) re-sends the same `started`
message. The timeline shows each call's start once.

**Group calls in the timeline:** the start notice, and the list preview
("Group call started" / "Group call ended").

## Meetings

A meeting is a call anyone holding its link can join, with or without a
Kutup account, as in a Zoom or Google Meet link or Signal's call links. It
is separate from the calls of a conversation on purpose:

- A one-to-one or group call is keyed from its conversation's own
  encryption. Only the conversation's members can derive the key, so nobody
  can be let in by a link without weakening it.
- A meeting belongs to no conversation. The link is the invitation, and
  everything about the meeting derives from the link.

An account makes meetings in Chat: "New meeting" in the sidebar (one to
join right away), "Schedule" on the Meetings page (a title, and optionally a
day, time and length), or "Start a meeting" in a conversation's menu, which
makes one and sends its link there as a message. It needs the server's SFU
(the capability `chat.callLinks`).

**The link:** `https://<chat app>/call#<fragment>`, where the fragment is
base64url (no padding) of `0x01 || secret (32 bytes)`. Browsers never send
the fragment to a server. The page at `/call` sits outside the app's
sign-in: it shows the meeting's title and time, asks for a name and joins.

**Keys:** from the secret, HKDF-SHA256 (salt `kutup/chat/call-link/v1`)
derives:

| Label | Value | Used for |
| --- | --- | --- |
| `room id` | 16 bytes, as 32 hex characters | the SFU room, and what the host files the meeting under |
| `access token` | 32 bytes | presented to the host for the details and an SFU token; the host stores only its SHA-256 |
| `frame key` | 32 bytes | media frames are encrypted under it in the browser (key index 0) |
| `name key` | 32 bytes | each participant's chosen name |
| `info key` | 32 bytes | the meeting's title and time |
| `chat key` | 32 bytes | messages written during the meeting |

A sealed value is `nonce (24) || XChaCha20-Poly1305(length (u32 BE) || body
|| zeros)`, with the associated data
`kutup/chat/call-link/v1/<name|info|message> 0x00 roomId`, so a value sealed
for one purpose or meeting does not open as another:

| Value | Body | Padded plaintext | Sealed |
| --- | --- | --- | --- |
| name | 1 to 124 bytes of UTF-8, no control characters | 128 bytes | 168 bytes |
| info | JSON `{ title, startsAtMs?, durationMinutes? }` | 512 bytes | 552 bytes |
| message | JSON `{ id, text, sentAtMs }`, text up to 4000 bytes | a multiple of 256 bytes | up to 4648 bytes |

A title is 1 to 200 bytes; a length is 1 minute to 24 hours and needs a
start. The Rust engine (`kutup-chat-core` `call_link.rs`) owns these
formats, with a fixed test vector for the derivation; the browser reaches it
through WASM.

**The owner's meetings:** the owner's secret for a meeting is itself
derived: HKDF-SHA256 over the account master key with the same salt and the
info `owner secret 0x00 nonce`, where `nonce` is 16 random bytes the host
stores with the meeting. Any of the owner's devices lists its meetings and
derives each link again; the host never holds a secret. An account keeps at
most 50.

**The host stores**, per meeting: the room id, the nonce, the SHA-256 of
the access token and of the owner's host token, the sealed info, whether it
has a waiting room, the owner and the time it was made; and, for a meeting
with a waiting room, the people waiting (below). It
offers:

- to the owner: create, list, replace the info and delete
  (`/api/chat/call-links`);
- to anyone presenting the access token, with no account:
  - `POST /api/chat/call-links/info`: the sealed info;
  - `POST /api/chat/call-links/token`: a 6-hour LiveKit token for that one
    room (join, publish, subscribe; never room admin), carrying the joiner's
    sealed name as the participant's metadata.

  A wrong token and an unknown room are answered alike. These routes are
  limited to 60 a minute per address (`RATE_LIMIT_CALL_LINK_PER_MIN`), the
  waiting room's repeated questions to 600
  (`RATE_LIMIT_CALL_LINK_POLL_PER_MIN`), and the SFU is never open to rooms
  nobody registered.

**In the meeting:** media goes through the host's SFU, each frame encrypted
under the frame key, so the SFU forwards what it cannot read. The SFU sees
each participant as a random identity and an opaque label; the others open
the label with the name key. Screen sharing and the People panel work as in
a group call.

**Meeting chat:** the Chat panel of a meeting is the meeting's own, not a
conversation. Each message is sealed under the chat key and sent to the
room as an SFU data message; who wrote it is the participant it came from.
It is stored nowhere: a browser shows what arrived while it was in the
meeting, someone who joins later does not see earlier messages, and it is
gone on leaving. The panel says so.

**Scheduling:** a meeting's time is information for the people invited, not
a lock. The host cannot read it, so the link works before and after it. A
scheduled meeting offers a calendar file (`.ics`, one `VEVENT` in UTC with
the title and the link), on the Meetings page and on the join page; Kutup
keeps no calendar and sends no invitations or reminders.

**History:** the Meetings page lists the account's meetings (those whose
planned end is still ahead first) and, separately, the meetings the account
joined, with when and for how long. That second list belongs to the
account, so it is the same on all of its devices:

- Each stay is a record of the link's fragment (so it can be joined again),
  the title, when it was joined and for how long, sealed in the browser:
  `nonce (24) || XChaCha20-Poly1305(length || JSON || zeros)`, padded to
  1024 bytes, under HKDF-SHA256 of the account master key (the meetings'
  salt, info `joined key`), with the AAD `kutup/chat/call-link/v1/joined`.
- The server stores the records (`/api/chat/joined-meetings`, the newest
  100 per account) and hands them back. It cannot open them, so it still
  has no readable record of who joined what; it does learn that the account
  recorded a stay and when, which someone watching the server could set
  beside the token requests of that moment.
- The meeting page sits outside the sign-in, so it cannot write to the
  account itself. When a stay ends it leaves it in the browser's storage
  (`kutup-meeting-history`, at most 30), tagged with the account signed in
  to Chat in that browser at the time, if any. Chat, whenever it is open
  there, moves those stays into the account and removes them from the
  browser. A stay joined while nobody was signed in goes to the account
  that next opens Chat in that browser; one tagged with another account is
  left for that account.
- Someone without an account keeps their stays in their browser only.
- Stays can be taken off the list one by one, or the list cleared.

**The waiting room:** optional, per meeting ("Waiting room" when making or
changing one). With it on, holding the link is not enough to join.

- The host is the meeting's owner. Their proof is the **host token**:
  HKDF-SHA256 over the account master key with the meetings' salt and the
  info `host token 0x00 nonce`. Unlike everything derived from the link's
  secret, nobody the link is shared with can compute it. The server stores
  its SHA-256.
- This server enforces it, because it mints the SFU tokens:
  `POST /api/chat/call-links/token` answers `403` for a meeting with a
  waiting room unless the host token is presented. Whether a meeting has a
  waiting room is therefore kept in the clear on the server, and told to
  whoever asks for the meeting's details.
- A joiner **knocks** (`…/knock`: access token, a random identity, their
  sealed name) and receives a ticket only they hold. Their page shows
  "Waiting for the host to let you in" and asks how the knock went every
  2.5 s (`…/knock/status`); asking also tells the server they are still
  there.
- The host, in the meeting, sees who is waiting by the names they chose
  (`…/knocks`, asked every 3 s, the sealed names opened in the browser) and
  lets each one in or turns them away (`…/knocks/decide`). An admitted
  knocker's next question returns the SFU token, for the identity and name
  they knocked with; one turned away is told so.
- A knocker who stops asking for 20 s is no longer listed, and knocks are
  forgotten ten minutes after their knocker last asked. At most 50 people
  wait at one meeting. Leaving and coming back means knocking again.
- Turning the waiting room off lets in everyone still waiting.
- The meeting page sits outside the sign-in, so it has no session to derive
  the host token from. The signed-in app, which lists the account's
  meetings, leaves each meeting's host token in the browser's storage for
  that page (`kutup-meeting-hosts`). The owner is therefore the host in a
  browser where they are signed in to Chat; in any other browser they are a
  guest like everyone else, and wait. Someone has to be the host in the
  meeting for anyone to be let in.
- A co-host (below) lets people in and turns them away too.

**Hosts:** the meeting's **owner**, and the **co-hosts** the owner names
while it is running. Until here this server only minted tokens to enter the
SFU's room; removing someone and ending a meeting act on the SFU itself, as
the room's administrator, through LiveKit's room service
(`CHAT_SFU_API_URL`, by default the SFU's URL with `ws` read as `http`).

- **Who is who.** The owner proves it with the host token. When they ask
  for an SFU token with it, the server records the identity they joined
  under as the owner's. A co-host is a participant's SFU identity the owner
  named (`…/co-hosts`); they prove who they are with their own SFU token,
  which this server minted and so can check (signature, room, identity).
  Anyone holding the link can ask who the hosts are (`…/roles`): the People
  list marks them "Host" and "Co-host". These roles are the server's word,
  not something a participant can claim. A browser learns of a change by a
  contentless hint sent through the SFU (topic `kutup-roles`), and then asks
  the server; the hint itself proves nothing.
- **A co-host lasts one stay.** The role belongs to the identity they
  joined with; leaving and joining again is a new identity without it.
- **What each may do.** The owner: everything. A co-host: let people in,
  turn them away, and remove participants who are not hosts. Nobody removes
  the owner; only the owner names co-hosts or ends the meeting.
- **Removing someone** (`…/participants/remove`, from their row in the
  People list): the server turns the waiting room on, marks the knock they
  came in by as turned away, and disconnects them at the SFU. Their page
  says a host removed them. They still hold the link, which is why the
  waiting room goes on: to come back they have to ask, and a host decides.
  It stays on until the owner turns it off.
- **Ending the meeting for everyone** (`…/end`, from the owner's leave
  button, which then offers "Leave meeting" and "End meeting for
  everyone"): the server turns away everyone waiting, forgets the co-hosts,
  and deletes the SFU room, which disconnects everybody; their pages say
  the host ended it. The link keeps working: the meeting can be held again.
  When the owner merely leaves, the meeting goes on without a host.
- **What removal is not.** It is not a change of keys: a removed person
  still holds the link, and so the keys the media, names and chat are
  sealed under. It keeps them out of the room, which is where those travel.
  A meeting that must exclude someone for good needs a new link.
- **A removed person's SFU token.** The SFU cannot take back the token they
  were given, which lasts up to six hours; a modified client could connect
  with it again. So the server remembers each removed identity (for a day
  after it was last removed) and removes it again when it is back: whenever
  a browser in the meeting asks who the hosts are, which each does when the
  people in the room change, and whenever a host looks at who is waiting,
  the server asks the SFU who is in the room and disconnects a removed
  identity it finds there. No host has to be present. Someone who gets
  back in this way is in the room for the moment it takes the others to
  notice them.

**What a meeting is, and is not:**
- Without a waiting room the link is the whole capability: whoever has it
  can join. With one, they can still read the title and time and ask to
  join, and the host decides. Either way, someone in the meeting sees,
  hears and reads its chat, and can hand the link on.
- Names are what people typed. Nothing ties a name to an account, including
  for people who have one; the join page says so.
- Deleting a meeting stops new joins. People already in it stay until they
  leave or the owner ends it for everyone first (their SFU token lasts up
  to six hours).
- A meeting is one room: everyone who opens the link while others are there
  is in the same call.

## The call view

Both kinds of call open the same view over the app: the Kutup Chat mark, the
call's title and status, the video, and the controls (microphone, camera,
screen, People, Chat, leave).

- **People** lists who is in the call, with each one's camera, microphone
  and screen-sharing state. In a one-to-one call the other side's microphone
  state is not shown: it is not signalled.
- **Chat** opens the call's own conversation beside the video (over it on a
  phone), so messages and attachments can be read and sent without leaving
  the call. It is the conversation itself, not a separate call chat: what is
  written there stays in the history like any other message. Polls, places
  and stickers stay in the conversation proper.
  In a meeting, which has no conversation, it is the meeting's own
  temporary chat instead (see "Meetings").

## ICE servers

`GET /api/chat/call-servers` returns what `RTCPeerConnection` needs:

- **STUN:** the servers in `CHAT_STUN_URLS`.
- **TURN:** with `CHAT_TURN_URLS` and `CHAT_TURN_SECRET` set, a relay entry
  with a 12-hour credential in coturn's shared-secret scheme:
  - the username is `<expiry>:<pseudonym>`, where the pseudonym is a hash of
    the account, so relay logs don't name it;
  - the password is `base64(HMAC-SHA1(secret, username))`.
- **Relay needs no account list:** the relay only checks the HMAC.
- **Coturn:** `docker compose --profile turn up` starts coturn with the same
  secret, refusing relays to private and loopback addresses.

Without a relay, calls connect only where a direct path exists (same network,
or NATs that allow it).

"Always relay calls" (Privacy) sends media only through the relay, so the
other person never learns this browser's IP address. It is shown only when a
relay is available.

## What servers learn

For group calls, the host's SFU sees:
- the room id;
- how many participants there are, their network addresses and tags;
- when each joins and leaves;
- the sizes and timing of the encrypted frames.

It never sees who the participants are, the group, or the media. Other
servers see only the federated token request (room id and tag) from their
accounts.

For meetings, the host additionally learns that a meeting exists, which
account made it and when, when its sealed details change, whether it has a
waiting room, how many people knock and when each is let in or turned away,
that an account recorded a joined meeting and when (not which), which SFU
identities are its hosts, which identity is removed and when the
meeting is ended, and the network address of each joiner when it asks for the details or a
token. It never
learns the link, the title or time, the names people chose, the chat, or
the media. Someone who gets the link learns all of them.


- **Kutup servers:** they carry the signals as ordinary encrypted Direct
  traffic, so they see only message timing and sizes.
- **Call-servers endpoint:** it is asked for credentials when a call
  starts.
- **TURN relay:** when used, it sees the two network addresses, when, and
  how much, never the media.
- **Without the relay:** each browser sees the other's IP address, as in any
  direct WebRTC call. "Always relay calls" prevents that.
