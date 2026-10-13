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
  - at most 20 active devices per account (`tooManyDevices`).
- Any failed check answers `403 deviceNotAuthorized`. The client registers
  again; this is not a sign-out.
- The device row stores the statement and its incarnation.

**Trust.** A device counts only while it is active and its incarnation is the
account's current one. The socket and the HTTP frame routes check both, so an
account reset ends every device of the old incarnation at once.

**The lease.** A statement older than 30 days is no longer trusted by other
servers (part 2). Clients renew after 15 days: they sign a fresh statement
over a new challenge and send it to `POST /api/devices/:id/renew`.

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
- the account already has 20 active devices on that domain
  (`tooManyDevices`).

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

**Revocations.** The bridge forwards its account's signed revocations in its
announces, oldest first, from the mark home last confirmed
(`revocationsThrough`, kept in `collab_revocation_marks`). More than 50 page
over several announces, none skipped. Home deactivates the device and keeps
the key in `remote_revoked_device_keys`, so it can never be announced again.
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
