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


- **Kutup servers:** they carry the signals as ordinary encrypted Direct
  traffic, so they see only message timing and sizes.
- **Call-servers endpoint:** it is asked for credentials when a call
  starts.
- **TURN relay:** when used, it sees the two network addresses, when, and
  how much, never the media.
- **Without the relay:** each browser sees the other's IP address, as in any
  direct WebRTC call. "Always relay calls" prevents that.
