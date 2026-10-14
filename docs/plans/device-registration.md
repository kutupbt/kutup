# Collaboration devices signed by the account

Status: built on `slate/cli-yjs-sync` for the clean-slate release (wire and
table changes, folded into the baseline before the wipe).

A collaboration device is the Ed25519 key a browser tab or the CLI signs
collaboration frames with. Before this change any holder of a session token
could register one (the `authSig` was empty), and frames from another server
were taken on that server's word. Neither could forge an edit (clients check
every frame by AEAD under the file key), but both could fill a document's log
with frames attributed to the account.

## Part 1: local devices

**Who signs.** The account authority key. It derives from the master key, so
every client that can read the account's files holds it, and the server and
every client already resolve it (the incarnation id is its hash).

**The statement** (`kutup-crypto::device_registration`, vectors in
`crypto.json` → `deviceRegistration`):

```
DeviceRegistrationV1 = sign_authority(
  "kutup/device-registration/v1\0"
  ‖ incarnation id (32)
  ‖ server domain (u16 length ‖ bytes)
  ‖ user id (16)              the server's id for the account
  ‖ device public key (32)
  ‖ purpose (u8)              1 = collaboration frames
  ‖ challenge (32)            from this server
  ‖ issued_at (i64, ms))
```

**Registration.**

- `POST /api/devices/challenge` returns a 32-byte challenge. It is valid for
  5 minutes and single use, at most 5 stay open per account (the oldest is
  dropped), and requests are limited by `RATE_LIMIT_DEVICE_CHALLENGES_PER_MIN`
  (default 20).
- `POST /api/devices` with `{ publicSigning, label, challenge, issuedAtMs,
  signature }`. The server checks:
  - the signature, under the account's authority key and its current
    incarnation;
  - this server's domain and the caller's user id;
  - the challenge (open, the caller's, then used up whatever the outcome);
  - `issuedAtMs` within ±24 hours of the server clock;
  - a key never registered before (on any account, revoked or not: `409`);
  - at most 20 devices in use per account (`tooManyDevices`; see *In use*).
- Any failed check answers `403 deviceNotAuthorized`. The client registers
  again; this is not a sign-out.
- The device row stores the statement and its incarnation.

**Trust.** A device is trusted while three things hold:

- it is not revoked;
- its incarnation is the account's current one, so an account reset ends
  every device of the old incarnation at once;
- the sign-in session that registered it (or last renewed it) is live.

The socket and the HTTP frame routes check all three. A sign-out anywhere, a
session's expiry or a password change that ends sessions retires the device
without a signature. That is not a revocation: a renewal under a live
sign-in, which needs the account's statement again, takes it up. The CLI's
device is bound to the CLI's session the same way.

**In use.** The cap counts devices in use: trusted, with a statement within
the 30-day lease. Devices of ended sign-ins, and devices left unused for 30
days, drop out of the count by themselves. When the cap is reached anyway,
the client tells the user (in English and Turkish) to remove one under
Account → Devices. The user chooses; nothing is revoked for them.

**The lease.** A statement older than 30 days is no longer trusted by other
servers (part 2). Clients renew after 15 days: they sign a fresh statement
over a new challenge and send it to `POST /api/devices/:id/renew`.

**On the web.** One device per sign-in per app origin, shared by its tabs.
Its key, id and statement time are sealed with the session's keys
(`EncodedKeys` v3), so a reload or a new tab reuses it, and it goes with the
sign-in. A fork to another origin never carries it: each origin registers
its own. Signing out revokes this origin's device with a signed revocation,
best effort, on top of the server retiring it.

**Revocation.** `DELETE /api/devices/:id` takes `DeviceRevocationV1`:

```
sign_authority("kutup/device-revocation/v1\0" ‖ incarnation
               ‖ server (u16 length ‖ bytes) ‖ device key (32) ‖ revoked_at (i64, ms))
```

A session alone cannot revoke a device. A revoked key never registers again.
Open sockets close at the next recheck (15 seconds).

## Part 2: devices on other servers

A bridge (the remote editor's server) posts frames to home (the file's server)
under a share's capability. Those frames can only come from that share's
recipient, and home knows the recipient's incarnation from the share itself:
the named share envelope (folders), or the file share's
`recipient_incarnation_id` (files).

**The announce.** `POST /api/fed/drive/collab/devices` is signed and
capability-authorized, and limited by
`RATE_LIMIT_COLLAB_DEVICE_ANNOUNCES_PER_MIN` (default 60) per (domain,
capability). It carries at most 50 entries in total, as `devices` (statements)
and `revocations`.

Home stores a device in `remote_collab_devices`, keyed by (domain, device id).
It refuses an entry, with a per-entry code, when:

- its statement does not verify, or names another server than the bridge
  (`doesNotVerify`);
- its authority's incarnation is not the share recipient's (`notRecipient`);
- the statement is older than the 30-day lease or dated more than a day ahead
  (`expired`);
- its key was revoked (`revoked`) or belongs to another device (`keyInUse`);
- the account already has 20 devices in use on that domain: not revoked,
  with a statement within the lease (`tooManyDevices`). Devices of ended
  sign-ins stop renewing and drop out of the count; home sweeps them a week
  past their lease. The bridge logs what home refuses.

A renewal is the same announce with a newer statement.

**Frames.** For each frame from a bridge, home also requires:

- the sender device is announced for this domain;
- the device belongs to the share recipient's current incarnation;
- its lease has not run out;
- the frame verifies under the device's key.

The frames response lists `unknownDevices` and `expiredDevices`, and those
frames are not kept. On `unknownDevices` the bridge announces the devices and
sends the frames again once. On `expiredDevices` it asks its clients to renew
(`{"type":"renewDevice","deviceIds":[…]}` on the socket).

**Revocations.** Each local revocation gets this server's next revocation
sequence number. The signed time is data only, and a local revoke's time must
be within a day of the server clock.
- **Order:** the bridge forwards its account's signed revocations in sequence
  order, after the mark home last answered (`revocationsThrough`, kept in
  `collab_revocation_marks` as home gave it).
- **Home's mark:** home records, per (domain, incarnation), the highest
  sequence it processed (`remote_revocation_marks`) and answers that.
- **Why not times:** a client's clock, fast or slow, can neither skip a
  revocation nor stall the paging, and many revocations in one millisecond
  page normally.
- **Paging:** more than 50 page over several announces, none skipped. A
  bridge stops when home's mark does not advance.
- **Storage:** home deactivates the device and keeps the key in
  `remote_revoked_device_keys`, per (server, key), so that server can never
  announce it again. Another server's account cannot block it.
The uploads sweeper deletes the devices of incarnations that no share names
any more. Revoked keys stay.

**One bridge per local account.** A bridge's room is keyed by file and local
user, so it announces only that account's devices.

The other direction (home pushing frames to a bridge) needs no such check:
home decides what its own log holds anyway.

## Limits

See `docs/drive-security-threat-model.md` → *Collaboration devices*: a
withheld revocation lasts at most until the lease ends, and an attacker who
holds the authority key has the account.

## Tests

- **Crypto vectors:** a registration and a revocation, plus refusal cases.
- **`tests/devices_live.rs`:** unsigned, foreign, replayed and made-up
  challenges; challenge eviction; key reuse; signed revocation; and a revoked
  device refused on the frames route.
- **`tests/collab_frames_live.rs`:** `deviceNotAuthorized` on the frame routes.
- **`remote_devices::tests`** (live database):
  - an unannounced device;
  - a foreign authority, another server and the wrong incarnation;
  - the lease, both expired and future-dated, and renewal;
  - revocation for good, and that another account cannot revoke;
  - the 20-device cap and the 50-entry limit;
  - 65 revocations paged.
- **The two-server gate:** written, not run here; the release run decides.
