# Kutup Chat calls

One-to-one voice and video calls, as Signal has them. Media goes directly
between the two browsers (WebRTC). Everything that sets a call up travels
end-to-end encrypted through the existing Direct (libsignal) session. Group
calls are separate work (see the parity plan).

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

- **Kutup servers:** they carry the signals as ordinary encrypted Direct
  traffic, so they see only message timing and sizes.
- **Call-servers endpoint:** it is asked for credentials when a call
  starts.
- **TURN relay:** when used, it sees the two network addresses, when, and
  how much, never the media.
- **Without the relay:** each browser sees the other's IP address, as in any
  direct WebRTC call. "Always relay calls" prevents that.
