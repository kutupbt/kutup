# API Reference

Base URL: `https://localhost:38443` for the bundled local Compose edge, or your
configured public `SERVER_URL`. Port `38080` redirects to HTTPS.

All authenticated endpoints require `Authorization: Bearer <accessToken>`.

> **Note:** File content and metadata are end-to-end encrypted by the client. Account secrets use one canonical, suite-bearing envelope per value; the server validates only its public framing and never sees the plaintext or key.

**Request bodies** are capped at 4 MiB unless a route says otherwise; the
upload routes raise it (a whole-file upload up to `driveUploadMaxBytes`, a
multipart version up to `driveVersionMaxBytes`, both site settings, 10 GiB
and 2 GiB at first; a tus chunk 64 MiB, a whiteboard asset one envelope, a
federated Drive upload the upload limit plus 16 MiB, streamed to disk). A
larger body gets `413`.

## Errors

A failed request answers JSON `{"error": "<English text>", "code": "<code>"}`,
plus fields a code names. **Apps act on `code`, never on the text**, which
is for logs and people reading the API. A `5xx` answers only
`{"error": "internal server error"}`, except the few coded ones about the
request rather than the server (listed with their `5xx` status below,
today `checkTimedOut`), which carry their `code` and `error` as client
errors do.

Without a specific code, a client error carries its status's default:

| Status | Code |
|---|---|
| 400, 422 | `invalid` |
| 401 | `unauthorized` |
| 403 | `forbidden` |
| 404 | `notFound` |
| 409 | `conflict` |
| 413 | `tooLarge` |
| 429 | `tooManyRequests` |
| any other 4xx | `error` |

Specific codes, where an app does something particular (a test in
`kutup-server` fails when the source uses a code this list lacks):

| Code | Status | Meaning |
|---|---|---|
| `deviceCredential` | 401 | A Chat call made as a device without that device's `X-Kutup-Device` credential, with a wrong one, or for a removed or expired device (one answer for all) |
| `noManifest` | 404 | `GET /api/chat/accounts/{accountId}/manifest` (and its federation route): the account has no Chat manifest, since no Chat device ever registered. Clients take only this 404 for "re-register as the account's first device"; any other 404 is an error |
| `badSignature` | 400 | A Chat prekey (signed EC, last-resort or one-time Kyber), or a manifest's `identityBinding`, not signed by the account's identity key |
| `keysDiffer` | 409 | `POST /api/chat/keys/check`: the server holds other keys for this device; it uploads them again |
| `linkTokenLimit` | 409 | `POST /api/chat/link-tokens`: as many unused link tokens as the administrators allow (`chatLinkTokensPerAccount`) |
| `manifestConflict` | 409 | A re-registration (`POST /api/chat/device` with `registration.type = reregistration`) or an identity distribution lost a race with another manifest change for the account: read the manifest again and retry (a replay of the current head answers 200) |
| `linkToken` | 403 | `POST /api/chat/device` linking: the link token is used, expired, unknown or another account's |
| `noAccountIdentity` | 409 | `POST /api/chat/device` linking: the account has no Chat identity yet; its first device re-registers |
| `deviceLimit` | 409 | A device registration, or a manifest listing more devices than the account may have: the site setting `devicesPerAccount` (default 32) over every kind of device |
| `devicesMismatch` | 409 | A manifest whose entries the server can't back: a listed device that isn't a live row of the account with the entry's kind, sign-in (`session`), frame key and Chat keys; or a re-registration that changes the account's non-Chat entries |
| `identityMismatch` | 409 | A Chat registration or manifest naming another identity than the account's (it changes only by a distribution or a re-registration) |
| `invalidCredentials` | 401 | A sign-in that does not finish: a wrong password, a name that is no account, a used or expired login id, a password changed since the sign-in started (not an expired session). At `login/2fa`: a wrong code, the token still good |
| `preAuthInvalid` | 401 | `login/2fa`: the second step's token is expired, not one, or from a password the account no longer has: back to the password step |
| `setupTokenInvalid` | 401 | `complete-setup` (and `register/start` under it): the setup token is expired, not one, already used, or from a temporary password since replaced: sign in again |
| `wrongPin`, `signedOut`, `noPin` | 403/404 | Kutup Pass's PIN: wrong (with `attemptsLeft`), the last try ended the sign-in, none set |
| `accountLocked` | 429 | The sign-in lockout or ceiling (a while) |
| `accountIdInvalid` | 400 | `register`: no account id given back, or one this server did not mint for the sign-up's key binding (start the sign-up again) |
| `revisionTaken` | 409 | A Drive upload or version naming a `revisionId` the file, another file or an open upload already has (a revision names one content: choose a new one) |
| `securityKeysOff` | 503 | This server can't offer security keys (its account app isn't on https) |
| `securityKeyLimit` | 409 | `POST /api/auth/security-keys/register/*`: the account has `limit` keys already |
| `securityKeyExists` | 409 | That security key is already added |
| `securityKeyRefused` | 400 | The key's answer was not accepted (another origin or RP, user verification missing when required, a bad attestation) |
| `securityKeyCeremony` | 400 | The security key prompt expired, or was answered already: start again |
| `securityKeyCompromised` | 401 | The key's counter did not move on, with no other use of it in flight: it may have been copied, and is no longer used (remove it; add it again if it is yours) |
| `securityKeyRetry` | 409 | The key's counter is behind because it was used elsewhere (another tab) since this sign-in started: start again |
| `secondFactorRequired` | 403 | Adding a factor (a security key, the authenticator app beside keys) or turning "Require PIN" off while two-step sign-in is on: prove a factor the account has (`code`, `recoveryCode` or `securityKey`) |
| `noSecurityKeys` | 409 | A security key step for an account without a usable key |
| `accountIdTaken` | 409 | `register`: the account id is some account's, or was a deleted account's (ids are never reused): start again |
| `keyListInvalid` | 400 | A shared mailbox's next key list the chain refuses: not signed by its signer in force, an old signer after its handover, a gap, or other keys than the group's |
| `handoverNeeded` | 403 | A shared mailbox's new signer without a handover from the one in force: only an administrator starts a group's key lists over |
| `newSignerNeeded` | 400 | Someone who held a shared mailbox's signing key no longer may (removed, no longer an owner or manager, or their account deleted or deactivated): the change needs a new signer |
| `idTaken` | 409 | Creating a group: the id the browser drew is some group's: draw another |
| `noAccountKey` | 400 | A shared mailbox's key share for an account not set up yet (no account keys to seal it to) |
| `grantInvalid` | 403 | A one-time grant that does not fit: unknown, used, expired, for another purpose, account or session (one answer for all): prove the password again |
| `opaqueKeyStale` | 409 | An OPAQUE record made against a setup that is no longer the server's current one: register again |
| `opaqueKeyMissing` | 500 | The account's record names an OPAQUE setup whose key is not in `OPAQUE_SETUP_KEYS`: the operator restores the key (the account can recover with its phrase meanwhile) |
| `keyBindingTaken` | 409 | The key binding drawn for a new record is another account's: draw another |
| `rateLimited` | 429 | This address asked too often (a minute); nginx's own 429 too |
| `peerUnsupported` | 503 | The recipient's server lacks this Chat wire; the message waits |
| `peerRefused` | 502 | The recipient's server refused this message for good |
| `deviceListMismatch` | 409 | Federation: the recipient's device list changed; the body lists missing, stale and extra devices |
| `sequenceGap` | 409 | Federation: a transaction arrived out of order; `expectedSequence` names the next one |
| `sealedVersionUnsupported` | 400 | Federation: a sealed transaction of another wire version, refused for good |
| `version_conflict` | 409 | A newer version exists (Drive, collab) |
| `revision_conflict` | 409 | A newer revision exists |
| `head_conflict` | 409 | The account head moved (another device wrote first; `sequence` the current one, or a folder delete whose `removes` is not what it removes): read the head and index again, redo the edit |
| `head_required` | 409 | The account keeps a head, and this listed write carried none |
| `contactListFull` | 400 | `PUT /api/chat/contact-list/{id}`: a new entry past the 10,000 the list keeps; the client keeps the write due (a block is never dropped) and tells its person |
| `malformed` | 400 | `POST /api/chat/anonymous/messages/multi`: the payload doesn't parse, names nobody, lists a device twice, or the token isn't canonical base64 of at most 256 bytes ([chat-protocol.md](chat-protocol.md) §7); also a group route's refusal code |
| `groupSendTokenInvalid` | 401 | `POST /api/chat/anonymous/messages/multi`: the group send token doesn't hold for the payload's accounts (expired, an account added or missing, another server's key), checked before any account is looked up; another server's answer is relayed as it is. Send those copies one by one and fetch the endorsements anew ([plans/group-send-endorsements.md](plans/group-send-endorsements.md) §3.5) |
| `endorsementExpiration` | — | A group route's `putEndorsement` refusal: the expiration isn't day-aligned, is past, or is more than 3 days ahead |
| `endorsementSize` | — | A group route's `putEndorsement` refusal: the sealed blob isn't the one length |
| `peerUnavailable` | 503 | `POST /api/chat/anonymous/messages/multi` for another server's accounts: that server didn't take the send (slow, unreachable or unwilling); send their copies one by one |
| `calendarExists` | 409 | `POST /api/calendar/calendars`: the id (or the calendar key) is in use; draw another |
| `calendarLimit` | 409 | `POST /api/calendar/calendars`: the account owns as many calendars as the administrators allow (`calendarsPerAccount`) |
| `eventLimit` | 409 | An events sync: the calendar holds as many events as the administrators allow (`calendarEventsPerCalendar`); that change only |
| `sequenceBehind` | 409 | An events sync: the changed event's `SEQUENCE` is lower than the stored one's, or a changed occurrence's is lower than its series'; that change only |
| `uidTaken` | 409 | An events sync: an event with this UID is in the calendar already; that change only |
| `eventIdTaken` | 409 | An events sync: a create's id holds another event (in any calendar); that change only |
| `recurrenceIdChanged` | 400 | An events sync: an update would turn a series into a changed occurrence, a change into a series, or move a change to another `RECURRENCE-ID`; that change only |
| `invalidReminders` | 400 | A calendar event's or default reminders out of bounds or too many; that change only |
| `unknownZone` | 400 | `PUT /api/calendar/settings`: a time zone the server's database doesn't know |
| `countTooLarge` | 400 | An events sync: the rule's `COUNT` is above `calendarMaxCount`; that change only |
| `exdateNotAnOccurrence` | 400 | An events sync: a calendar-part `EXDATE` isn't an occurrence of the series; that change only |
| `parentMissing` | 400 | An events sync: a changed occurrence's series isn't in the calendar; that change only |
| `notAnOccurrence` | 400 | An events sync: a `RECURRENCE-ID` isn't an occurrence of its series; that change only |
| `setupRequired` | 409 | The account has no keys yet (an admin-made account before its first sign-in): a listed write or a rename waits for setup |
| `renamed` | 409 | A lookup of a name an account no longer goes by (held, or named in a rename chain): `renames` carries `{ "version": 1, "chains": [...] }`, never keys |
| `nameReserved` | 409 | The name is the server's (postmaster, abuse, …, the break-glass account), in any spelling |
| `renameInvalid` | 400 | A rename statement or its re-signed Drive key binding does not check out |
| `renameConflict` | 409 | The rename chain moved (`sequence`), or the statement starts from an address the account has since left (another device renamed meanwhile): read `/user/me` and sign anew |
| `tooManyHeldNames` | 409 | Five of the account's old names still receive: drop one first (a dropped name stays held until freed, but no longer counts) |
| `renameTooSoon` | 429 | One rename per 30 days (`retryAt`); going back to the name just left within 7 days is free, once |
| `dropTooSoon` | 429 | One dropped name per 30 days (`retryAt`) |
| `addressReceiveOnly` | 403 | An account's old address receives only; mail is sent from its current one |
| `notHeld` | 409 | Not a name the account (or, for an admin, anyone) holds |
| `breakGlassAccount` | 403 | The break-glass account keeps its name |
| `forwardingMaterialMismatch` | 400 | `POST /api/mail/forwardings`: the proxy factors aren't for the address's current key, or don't name the forwardee key's subkeys |
| `endToEndRequired` | 400 | `POST /api/mail/forwardings` to a Kutup address without `endToEnd` material |
| `forwardingExists` | 409 | The address already forwards there |
| `forwardingLimit` | 409 | 10 forwardings per address or 25 per account |
| `customDomainsOff` | 403 | Custom mail domains are off here (`POST /api/mail/domains`) |
| `addressDisabled` | 403/404/422 | The address is disabled: a send from it (403), a key lookup for it (404), a send to it (422); clients never send to it another way |
| `addressEnabled` | 409 | `PUT /api/mail/addresses/{id}/delete` or `/enable`: the address isn't disabled |
| `addressSetChanged` | 409 | `PUT /api/mail/addresses/order`: the ids aren't exactly the account's current addresses |
| `defaultAddress` | 409 | Disabling the default address: make another address default first |
| `disabledDefault` | 400 | `PUT /api/mail/addresses/order`: a disabled address cannot be default |
| `ownAddress` | 409 | Disabling or deleting the account's own address (on the server's domain) |
| `domainNotVerified` | 409 | The address's custom domain doesn't take mail now (sending from it, a new address or a catch-all on it) |
| `notYourAddress` | 404 | `fromAddress` names no active address of the caller's |
| `mimeMismatch` | 400 | `POST /api/mail/send`: the readable `mime` isn't the same message (another From than the sender's address, another Message-ID, or a Bcc header) |
| `checkTimedOut` | 503 | `GET /api/mail/domains/{id}?refresh=1`: the domain's whole DNS check ran past its time (`mail_domains.check_timeout_seconds`); nothing changed |
| `domainBlocked` | 409 | `POST /api/mail/domains`: an administrator deactivated this name; nobody may add it until they lift the block |
| `forwardingUnavailable` | 409 | This server has no `MAIL_FORWARDING_KEYS`: no forwarding can be set up |
| `forwardingState` | 409 | A forwarding action from the wrong state (pause an active one, accept a pending one, …) |
| `keyListRequired` | 400 | The first outside forwarding of an address brings its next key list, with EMAIL_NO_ENCRYPT on every key |
| `keyListMismatch` | 400 | That key list changes more than adding EMAIL_NO_ENCRYPT |
| `forwardingKeepsNoEncrypt` | 409 | A key list clearing EMAIL_NO_ENCRYPT while the address forwards outside Kutup |
| `internationalAddressUnsupported` | 400 | `POST /api/mail/forwardings` to an address with non-ASCII characters: not supported yet (an IDN domain works in its punycode `xn--` form) |
| `codeWrong` | 400 | `POST /api/mail/forwardings/:id/verify`: not the code; `attemptsLeft` says how many more tries the code takes |
| `codeVoid` | 409 | `POST /api/mail/forwardings/:id/verify`: the code took its last wrong try (`forwarding_code_attempts`); send a new one |
| `codeExpired` | 409 | `POST /api/mail/forwardings/:id/verify`: no live code (past `forwarding_code_minutes`, or none sent); send a new one |
| `forwardingVerified` | 409 | `POST /api/mail/forwardings/:id/code`: the forwarding is verified already |
| `tooOld` | 410 | `GET /api/account/heads`: the anchor is past the kept window (1,000 heads): re-anchor with a notice |
| `name_taken`, `nameTaken` | 409 | The name is in use (with what holds it) |
| `nameNeeded` | 400/409 | A write without its `nameHash` (400), or a folder restored at the top level that needs a name there (409) |
| `versionUploading` | 409 | A new version of this file is already being uploaded (`idleSeconds`; `uploadId` and `yours` for its uploader or the folder's owner) |
| `frameRefused` | 409 | A collaboration frame sent over HTTP was not kept (stale key or document key, not this device's, a replay): read the log again |
| `deviceNotAuthorized` | 403 | A collaboration device the account has not vouched for (an unanswered, used or expired challenge, a statement that does not verify, a revoked device or one of an earlier incarnation): register one again, do not sign out |
| `tooManyDevices` | 409 | The account has 20 collaboration devices in use (trusted, renewed within 30 days): the user removes one under Account → Devices; nothing is removed for them |
| `link_removed` | 404/410 | The shared link was removed |
| `keyChanged` | 409 | A recipient's key changed since it was checked |
| `keysPendingUpgrade` | 409 | The person's Drive key is still X25519 (identity suite 1): share with them once they have signed in again (docs/plans/pq-shares.md) |
| `identitySuiteCurrent` | 409 | The account's identity suite is current: nothing to upgrade |
| `setupPending` | 409 | `POST /api/account/identity-suite` for an account still in its first-login setup, which registers suite-2 keys itself: finish the setup (not a 401, which would end the session) |
| `peerOutdated` | 502 | The other server runs an older version without post-quantum Drive keys and must upgrade before sharing |
| `registrationClosed` | 403 | Registration is off: nobody may sign up, with or without a referral code |
| `registrationCodeRequired` | 403 | Registration needs a referral code and none was given |
| `registrationCodeInvalid` | 403 | The referral code admits no one: one answer whether it is unknown, expired, revoked or used up |
| `newKeyNeeded` | 409 | A new key must be made first |
| `noAddressKey` | 409 | The address has no key yet |
| `sharesNeeded` | 409 | Shares must be updated first |
| `groupChanged`, `group` | 409 | The group changed; read it again |
| `notAllowed`, `notAllowedToSendAs` | 403 | Not permitted for this account or address |
| `invalidAddress`, `unknownRecipient` | 400/404 | An address that is not one, or no such recipient |
| `sending`, `sendingPaused`, `outsideSendingOff` | 409/403 | Mail sending is busy, paused, or off for outside |
| `sendLimit`, `scheduledLimit` | 429 | A sending or scheduling limit was reached |
| `spam`, `refused` | 403 | The message was refused |
| `expiringOutside` | 400 | Expiring messages cannot go outside Kutup |

Not covered: server-to-server federation answers (signed, their own shapes)
and the framework's own refusals of a request it cannot read (a body that is
not JSON, a missing path segment), which answer plain text without a code.

## Session version

Every authenticated answer carries `X-Kutup-Session-Version`: 16 hex
digits, an HMAC under a key only the server holds of the account's security
state (its password, 2FA, role, username and key binding), read in the same
query that checks the session. It reveals nothing about that state, only
whether it changed. It changes when
any of them changes, from any app or device. Each app (each on its own
origin) remembers the last one it saw; on a change it reads `/user/me`
again and, when the key binding is no longer the one its keys carry, ends
its session. The header is exposed to cross-origin callers.

---

## Authentication

Sign-ins are **server-side sessions** (`auth_sessions`). Every session has a
client type, sent by the client in the `X-Kutup-Client` header:

| Client type | Who | Signs in | Refresh token |
|---|---|---|---|
| `web-account` | the account web app (`account.<domain>`) | password (`/login/start` and `/login/finish`, `/login/2fa`, `/complete-setup`, `/register`) | HttpOnly cookie on that origin |
| `web-drive`, `web-chat` | the Drive and Chat web apps | **forked** from a `web-account` session (`/api/auth/forks`) | HttpOnly cookie on their own origin |
| `cli` | the `kutup` CLI | password | JSON body |

Access tokens are 15-minute JWTs carrying the session id (`sid`); every
authenticated request (and each collab / chat WebSocket upgrade) checks that
the session is still live, so revoking a session takes effect immediately.
Refresh tokens are opaque 32-byte secrets that **rotate on every refresh**;
see `/api/auth/refresh`. A new password ends the account's other sessions, a
recovery all of them; an admin disabling the account and an admin wipe end
every session of the account.

**Passwords are OPAQUE** (RFC 9807, docs/plans/opaque.md): the server keeps a
record per account that is useless without an online exchange, and never sees
the password or anything to test a guess against offline. Sign-in is
`login/start` then `login/finish`; a new password is `opaque/register/start`
then `opaque/register/finish` (or the request that creates the account). Every
binary value is canonical base64 of the `opaque-ke` messages; suite 1 is
ristretto255, Triple-DH and Argon2id (64 MiB, t = 3, p = 1).

**Grants** (`kg1_…`) prove a fresh password, or the recovery phrase, for one
action: `pass` (the Pass PIN), `passwordChange`, `totp` (turning two-step
sign-in on or off, with a current code), `adminReset`, `recovery`, `rotate`. Each is bound to one account and, except a recovery's, to
the session it was issued to; it is used once and expires in five minutes (a
`rotate` one in two). It is never a session. A grant that does not fit is
`403 grantInvalid`, whatever the reason.
Design: `docs/plans/multi-app-web-rewrite.md`.

### GET /api/auth/settings

Returns public server settings: who may register (`registrationMode`:
`on`, `code` with a referral code, or `off`), the Chat
capability advertisement, and where each web app lives (`apps`, from
`KUTUP_BASE_DOMAIN` / `KUTUP_{ACCOUNT,DRIVE,CHAT,OFFICE}_URL`).

**Auth:** None (a bearer token, if sent, makes per-account values the
caller's own)

**Response:**
```jsonc
{
  "registrationMode": "code",
  "chat": {
    "enabled": true,
    "protocolVersion": 1,
    "suites": [1],
    "maximumActiveDevices": 10,
    "manifests": true,
    "profiles": true,
    "federation": true,
    "sealedSender": true,
    "pairwiseGroups": false,
    "groupCalls": false
  },
  "apps": {
    "account": "https://account.example.org",
    "drive": "https://drive.example.org",
    "chat": "https://chat.example.org",
    "maps": "https://maps.example.org",
    "photos": "https://photos.example.org",
    "office": "https://office.example.org",
    "editor": "https://editor.example.org"
  },
  "nameHoldDays": 180,
  "oldAddressReceiveDays": 90,
  "passVaultMaxBytes": 67108864
}
```

`passVaultMaxBytes` is the largest `.kdbx` file Kutup Pass takes in an
upload (an existing vault brought in from KeePassXC or a backup), as
administrators set it (`PUT /api/admin/settings`; 64 MiB at first). The
browser opens a vault whole, so this bounds what an upload makes it hold;
a vault's own saves are never refused by it.

The chat block also advertises size/retention limits, the canonical federation
server name when enabled, and the authenticated sealed-sender service-policy
history. `maximumActiveDevices` is the setting `chatMaxActiveDevices`, from 1
through the V1 hard cap of 10: a signed-in caller's own where administrators
set one (that answer is `Cache-Control: private, no-store`), else the
site's. A capability is advertised only when its complete local and
federated path is enabled.

---

### POST /api/auth/register

Create a new account with an encrypted key bundle. Rate-limited (10/hr/IP, `RATE_LIMIT_REGISTER_PER_HOUR`).
Who may register is the registration mode (docs/plans/registration-codes.md),
checked before anything else: `off` refuses everyone (`registrationClosed`),
`code` needs `registrationCode` (`registrationCodeRequired` without one), `on`
admits anyone and records a code if one is given. A code that admits no one
gets `403 registrationCodeInvalid`, the same answer for every reason, and
counts against the address (20 an hour together with code checks,
`RATE_LIMIT_REGISTRATION_CODE_FAILURES_PER_HOUR`; then `429 rateLimited`). A
code is used up in the transaction that creates the account, so a code with N
uses admits exactly N accounts however many sign up at once.

**Auth:** None

**Request body:**
```json
{
  "username": "alice",
  "accountId": "<uuid register/start minted>",
  "accountIdProof": "<hex, from register/start>",
  "registrationCode": "7KQ2M-9XD4T-PAV3W-8HCNR",
  "keyBinding": "<lowercase UUID v4 drawn by the client>",
  "opaqueRecord": "<base64 OPAQUE RegistrationUpload>",
  "opaqueServerKeyId": 1,
  "masterKeyEnvelope": "<canonical base64 AccountEnvelopeV1>",
  "recoveryKeyEnvelope": "<canonical base64 AccountEnvelopeV1>",
  "drivePrivateKeyEnvelope": "<canonical base64 AccountEnvelopeV1>",
  "publicKey": "<base64>",
  "accountAuthorityPublicKey": "<base64 32 bytes>",
  "accountAuthorityKeyId": "<lowercase SHA-256 hex>",
  "accountIncarnationId": "<lowercase SHA-256 hex>",
  "driveSigningPublicKey": "<base64 32 bytes>",
  "recoveryProof": "<base64>",
  "driveKeyBinding": "<canonical base64, 64 bytes>"
}
```

All key material is encrypted client-side before being sent. The password is
registered first (`POST /api/auth/opaque/register/start` for the new key
binding, then the client's half), and its OPAQUE export key seals the master
key (`masterKeyEnvelope`). `opaqueServerKeyId` is the setup register/start
answered under; a record made against a setup that is no longer the current
one is refused (`409 opaqueKeyStale`: start again). The key binding is checked
unused in the transaction that creates the account (`409 keyBindingTaken`:
draw another). `recoveryProof` is a distinct HKDF output bound to the key binding;
the raw recovery entropy that opens `recoveryKeyEnvelope` is never sent. Each
envelope authenticates its suite, purpose, key binding, nonce and
exact ciphertext length as AEAD associated data. The three purposes cannot be
substituted for one another or relocated to another account.

The complete account identity is fixed at registration: the account authority,
incarnation, Drive X25519 key, and Drive Ed25519 share-signing key are persisted
as one binding. A later account manifest must match all of them exactly; a
self-signed first manifest cannot select a replacement authority.
The account's permanent id (`users.id`, docs/plans/account-ids.md) is the one
`register/start` minted for this sign-up's key binding: `accountId` and
`accountIdProof` come back unchanged (`400 accountIdInvalid` for anything
else; `409 accountIdTaken` for an id some account has, or had: a deleted
account's id is never given again). `driveKeyBinding` (required) is the
authority's signature over the account (this server's name and `accountId`)
and the Drive keys (`kutup_crypto::drive_key_binding`,
docs/plans/drive-identity-pins.md); `400` when missing or not matching. It
names no username, so a rename never signs it again.

**Header:** `X-Kutup-Client` as for sign-in.

**Response:** `200`, the session, as `POST /api/auth/login/finish` answers it:
the client made the keys and holds the export key, so there is no second
exchange.

**Errors:** `403` with `registrationClosed`, `registrationCodeRequired` or
`registrationCodeInvalid` (above), `409` if the username is already taken,
`409 keyBindingTaken`, `409 opaqueKeyStale`.

---

### POST /api/auth/registration-code/check

Whether a referral code can admit a sign-up now, so the sign-up page can say
so before it derives the account's keys. It uses nothing up; the account's
own registration takes the use.

**Auth:** None. Rate-limited per address (30 an hour,
`RATE_LIMIT_REGISTRATION_CODE_CHECK_PER_HOUR`), and a code that admits no one
counts with sign-ups' wrong codes (above).

**Request body:** `{ "code": "7kq2m 9xd4t pav3w 8hcnr" }`: case, spaces and
dashes do not matter, and I/L read as 1, O as 0.

**Response:** `204`; `403 registrationCodeInvalid` (the same answer for every
reason), `403 registrationClosed` when registration is off, `429 rateLimited`.

---

### POST /api/auth/login/start

The server's half of an OPAQUE sign-in's first message. Rate-limited (10/min/IP,
`RATE_LIMIT_LOGIN_PER_MIN`).

**Every start counts as a failed attempt, before any OPAQUE work.** A client
checks the password itself and needs no finish to learn a guess was wrong, so
the start is the attempt. A right finish gives it back.
- **Lockout:** 5 attempts in a row for one account from one client IP
  (`LOGIN_LOCKOUT_THRESHOLD`) lock that account for that IP: further starts
  return `429` for 15 minutes (`LOGIN_LOCKOUT_MINUTES`).
- **Ceiling:** attempts from clients the account does not know are also capped
  per account, all together (`LOGIN_ACCOUNT_CEILING`, 20 in the same window;
  `LOGIN_ACCOUNT_DAILY_CEILING`, 200 a day; an IPv6 client counts by its /64).
  A client that signed in to the account before carries the HttpOnly
  `kutup_known` cookie (set at a session's finish and by
  `POST /api/auth/forks/consume`, `Path=/api/auth`: no route outside sign-in
  sees it; the same answers clear one a browser may hold at `Path=/api`) and
  is not held by that cap.
- **Unknown names:** both apply to them too, keyed by the canonical name, so a
  `429` does not reveal whether the account exists.
- **Codes:** a `429` from the lockout or the ceiling carries `code:
  accountLocked` (a while); one from a per-address route limiter carries
  `code: rateLimited` (a minute).

**What an answer reveals:** a name that is no account (a held name after a
rename, another server's address, a name never taken) gets OPAQUE's fake
answer, of the same shape and size, the same each time for that name; it can
never be finished. A malformed request is a `400` before the name is looked
up. At most 5 sign-ins are under way per name and 20 per address; past
either, the oldest is dropped. A sign-in waits at most two minutes for its
finish.

**Auth:** None (`purpose: "reauth"`: Bearer JWT, and the name must be the
caller's account) · **Header:** `X-Kutup-Client: web-account` or `cli` for a
session (`400` otherwise)

**Request body:**
```json
{
  "name": "alice",
  "credentialRequest": "<base64 KE1>",
  "purpose": "session",
  "for": null
}
```

`purpose` is `session` (sign-in, the default) or `reauth`: a signed-in person
proving the password again for a grant, `for` one of `pass`, `passwordChange`,
`totp`, `adminReset`; or `for: "verify"`, the password checked and nothing
kept (`login/finish` answers `{"ok": true}` and stores no grant; Pass unlock
uses it). A reauth counts against the account's lockout and ceiling as a
sign-in does.

**Response:** `{ "loginId": "<uuid>", "credentialResponse": "<base64 KE2>", "suite": 1 }`.

---

### POST /api/auth/login/finish

Checks the client's KE3. Every miss is the same `401 invalidCredentials`: a
wrong password, a name that is no account, a used or expired login id. A
malformed finalization is a `400`.

**Auth:** None (a reauth: the Bearer JWT of the session that started it) ·
**Header:** `X-Kutup-Client` as for the start

**Request body:** `{ "loginId": "<uuid>", "credentialFinalization": "<base64 KE3>" }`

**Response (a session, no 2FA):**
```json
{
  "accessToken": "<jwt>",
  "sessionId": "<uuid>",
  "userId": "<uuid>",
  "username": "alice",
  "masterKeyEnvelope": "<canonical base64 AccountEnvelopeV1>",
  "drivePrivateKeyEnvelope": "<canonical base64 AccountEnvelopeV1>",
  "publicKey": "<base64>",
  "keyBinding": "<the account's key binding (a UUID v4)>",
  "isAdmin": false,
  "storageQuotaBytes": 5368709120,
  "storageUsedBytes": 104857600
}
```

The export key the client got from the exchange opens `masterKeyEnvelope`
(`kutup_crypto::opaque::ExportKey::open_master_key`). For `web-account` the refresh token is an HttpOnly, host-only cookie named `refresh_token` (`Path=/api/auth/refresh`, `SameSite=Lax`, 30-day sliding `Max-Age`, `Secure` outside development) and is **not** in the JSON body. For `cli` it is returned as `"refreshToken"` in the body and no cookie is set.

When the account's record is under a setup that is no longer the server's
current one (`OPAQUE_SETUP_KEYS` rotated), the session also carries
`"rotate": true` and a `grant` (purpose `rotate`, this session, two minutes):
the client registers the password it just used again
(`opaque/register/start` and `/finish` for the account's own key binding),
silently. Nobody's sign-in ends for that.

**Response (2FA enabled):** `200` with `{"requiresTotp": true, "preAuthToken": "<jwt>"}` — proceed to `/api/auth/login/2fa`.

**Response (first login, an account an administrator created, or the `ADMIN_ACCOUNT` one, not yet set up):** `200` with `{"requiresSetup": true, "setupToken": "<jwt>", "userId": "<uuid>", "username": "alice"}` — proceed to `/api/auth/complete-setup` (`userId` is the account id the new keys' `driveKeyBinding` names). Its temporary password was registered by the administrator's client; the server never had it.

**Response (a reauth):** `{ "grant": "kg1_…", "expiresAt": "<RFC 3339>" }`.

---

### POST /api/auth/login/2fa

Complete login when 2FA is enabled. Locked after 5 failed attempts.
`code` is the authenticator's six digits, or one of the account's recovery
codes (`POST /api/user/2fa/verify`), which works once: case, spaces and the
dash are ignored, and I/L read as 1, O as 0.

**Auth:** None (uses `preAuthToken` from the sign-in's answer) · **Header:** `X-Kutup-Client` as for `/api/auth/login/start`

**Request body:**
```json
{
  "preAuthToken": "<jwt>",
  "code": "123456"
}
```

**Response:** the same session as `/api/auth/login/finish` answers (with
`rotate` and `grant` when due). The client keeps the export key across this
step.

The sign-in's answer asks for this step (`requiresTotp: true`) whenever the
account has a second factor, and `secondFactors` lists the steps it may
take, a security key first: `securityKey`, `totp`, `recoveryCode`. Only an
authenticator app that is turned on counts here; a secret still being set
up never signs in.

### POST /api/auth/login/security-key/start, …/finish

The second step with a security key (docs/plans/security-keys.md).
- `start` `{ "preAuthToken" }` answers `PublicKeyCredentialRequestOptions` in
  its JSON form, naming the account's usable keys (only someone past the
  password step learns them); `409 noSecurityKeys` without one.
- `finish` `{ "preAuthToken", "credential" }`, `credential` being the
  browser's `PublicKeyCredential.toJSON()` from `get()`, answers the same
  session as `login/2fa`. The ceremony is single use, bound to the
  pre-auth token, and lasts `webauthnCeremonySeconds`. Failures share
  `login/2fa`'s attempt budget (`401 invalidCredentials`, then `429`). A key
  whose counter did not move on may have been cloned: it is marked
  compromised, logged, and refused (`401 securityKeyCompromised`); it is
  never offered again (Proton's flag: remove it, and add it again if it is
  yours). When the key was used after this sign-in started (another tab),
  a counter behind is that use, not a clone: refused only (`409
  securityKeyRetry`), as Signal restarts the ceremony.

**Auth:** None · **Header:** `X-Kutup-Client` (on `finish`)

---

### GET /api/auth/recover/preflight

Fetch the encrypted recovery key bundle so the client can decrypt the master key with the mnemonic-derived recovery key. Rate-limited (5/hr/IP). Returns deterministic fake data for names that are no account, to prevent user enumeration.

**Auth:** None
**Query:** `?name=alice` (the username, or the Kutup address `alice@<domain>`)

**Response:**
```json
{
  "recoveryKeyEnvelope": "<canonical base64 AccountEnvelopeV1>",
  "envelopeBinding": "<the account's key binding>"
}
```

---

### POST /api/auth/recover/grant

The recovery phrase's proof, for a `recovery` grant (no session): with it the
client registers a new password (`opaque/register/start` and `/finish` for the
account's key binding), which ends every session of the account. Rate-limited
(5/hr/IP).

**Auth:** None

**Request body:** `{ "name": "alice", "recoveryProof": "<base64>" }`

`recoveryProof` is the 32-byte HKDF-derived authorization proof. The server
bcrypt-compares it to the verifier stored at registration; it never receives
the recovery entropy used for decryption. An unknown name, an account without
a verifier and a wrong phrase are the same `401`, checked at full cost.
Registering the new password with the grant also turns every second factor
off and drops the recovery codes, as Proton's lost-2FA path does, and records
`twoFactorOff` in the security log: someone who lost the authenticator signs
in with the new password alone.

**Response:** `{ "grant": "kg1_…", "expiresAt": "<RFC 3339>" }`.

---

### POST /api/auth/opaque/register/start

The server's answer to a registration request for a key binding: stateless,
derived from the current setup and the key binding. Each answer is one query
of that key binding's OPRF key, so it is limited as a sign-in start is
(`RATE_LIMIT_LOGIN_PER_MIN`) and needs one of:
- `grant`: `passwordChange`, `recovery` or `rotate` for the account's own key
  binding (a new password), or an admin reset's grant (`adminReset` with a
  target, from `reset-grant`) for a new key binding of that account;
- Bearer the setup token, at first sign-in, for the account's own new key
  binding;
- Bearer an administrator's session, for a new account's key binding;
- nothing, for a sign-up's new key binding, while sign-ups are open
  (`403 registrationClosed` otherwise).

A new key binding must be unused (`409 keyBindingTaken`: draw another). The
grant is checked here and used at the request that stores the record.

**Request body:** `{ "keyBinding": "<uuid v4>", "registrationRequest": "<base64>", "grant": null }`

**Response:** `{ "registrationResponse": "<base64>", "serverKeyId": 1 }`;
for a sign-up (no grant, no Bearer) also `"accountId"` and `"accountIdProof"`:
the new account's permanent id, minted here (random, as Signal mints an ACI),
and a proof bound to the key binding, both given back with
`POST /api/auth/register`. Nothing is stored until then.

---

### POST /api/auth/opaque/register/finish

A new password for an existing account. The grant must be
`passwordChange` (used by the session it was issued to), `recovery`, or
`rotate` (the session it was issued to). In one transaction:
- the record and the password envelope change together (the master key is
  sealed under the new password's export key);
- every outstanding grant and sign-in under way for the account ends.

In the same transaction, a password change ends the account's other sessions
and a recovery all of them; a rotation ends none. Each is recorded as a
security event (`GET /api/user/security-events`). A `rotate` grant is good
only while the account's record is under a retired setup: once moved, a
second one is refused (`403`), so it never serves as a password change.

**Auth:** None, or the Bearer JWT of the grant's session

**Request body:**
```json
{
  "grant": "kg1_…",
  "keyBinding": "<the account's>",
  "opaqueRecord": "<base64>",
  "opaqueServerKeyId": 1,
  "masterKeyEnvelope": "<canonical base64 AccountEnvelopeV1>"
}
```

**Response:** `204`; `403 grantInvalid`; `409 opaqueKeyStale`.

---

### POST /api/auth/refresh

Rotate the session's refresh token and get a new access token. Web sessions
present the token in their `refresh_token` cookie and receive the next one the
same way; the CLI presents it in the body and receives the next one in the body.
A token presented the other way is refused (and does not rotate anything).

A just-rotated token is still honoured for 60 seconds (two tabs refreshing with
the same cookie): it yields an access token but no new refresh token. A rotated
token presented after that window is treated as stolen and **revokes the
session** and everything forked from it. A failed web refresh clears the cookie.

**Auth:** None (the refresh token itself is the credential)

**Request body (CLI only):**
```json
{
  "refreshToken": "<43-char base64url>"
}
```

**Response:**
```json
{
  "accessToken": "<jwt>",
  "sessionId": "<uuid>",
  "refreshToken": "<CLI only, absent within the grace window>"
}
```

---

### POST /api/auth/complete-setup

Called after first login by accounts created via `ADMIN_ACCOUNT` that haven't yet generated a recovery phrase. The client derives a full key bundle (mnemonic, master key, recovery entropy, account Drive keys and typed account envelopes) and submits it here.

**Auth:** Bearer `setupToken` (returned by `/api/auth/login/finish` when `requiresSetup` is true) · **Header:** `X-Kutup-Client` as for sign-in

**Request body:** Same shape as `POST /api/auth/register` (the key bundle, the
OPAQUE record of the person's own password under a key binding they drew now,
registered with the setup token as Bearer, and the required `driveKeyBinding`
for the account's id, the `userId` of the first sign-in; `username` is
ignored, and `accountId`/`accountIdProof` are refused: the account has its
id). The temporary password's
record goes with it.

**Response:** creates a session and issues tokens exactly as `/api/auth/login/finish` does (cookie for `web-account`, body for `cli`) — the encrypted key bundle just submitted is **not** echoed back.
```json
{
  "accessToken": "<jwt>",
  "sessionId": "<uuid>",
  "userId": "<uuid>",
  "username": "alice",
  "isAdmin": false,
  "storageQuotaBytes": 5368709120,
  "storageUsedBytes": 0
}
```

---

## Sessions

### POST /api/auth/logout

End the caller's sign-in: the `web-account` (or `cli`) session **and every
session forked from it**. Signing out of Drive or Chat therefore signs out of
all Kutup web apps on that browser; they notice on their next request.

**Auth:** Bearer · **Response:** `{"ok": true}` (web: also clears the cookie)

### GET /api/auth/sessions

The account's live sessions, most recently used first. `current` marks the
caller's own sign-in (its root and the sessions forked from it).

**Auth:** Bearer

```json
[
  {
    "id": "<uuid>",
    "clientType": "web-drive",
    "parentId": "<uuid of the web-account session>",
    "userAgent": "Mozilla/5.0 …",
    "createdAt": "2026-09-23T14:07:00Z",
    "lastUsedAt": "2026-09-23T14:12:00Z",
    "current": true
  }
]
```

### DELETE /api/auth/sessions/:id

End one session of the caller's account and anything forked from it. `404` for
an unknown or foreign id. **Auth:** Bearer

### DELETE /api/auth/sessions

Sign out everywhere else: end every session except the caller's own sign-in.
**Auth:** Bearer

### POST /api/auth/forks

The account app hands a child web app a session (the Proton pattern). The
payload is a `SessionFork` local-state envelope (`kutup-crypto::local_state`,
profile = the child client type) sealed under a fresh 32-byte key that travels
only in the child URL's fragment; the server stores the envelope once, for 60
seconds, and never sees the key.

**Auth:** Bearer, `web-account` sessions only (`403` otherwise)

**Request body:**
```json
{
  "childClientType": "web-drive",
  "payload": "<canonical base64, ≤ 16 KiB>"
}
```

**Response:**
```json
{
  "selector": "<43-char base64url, single use>",
  "childOrigin": "https://drive.example.org"
}
```

The account app then redirects to
`<childOrigin>/login#selector=<selector>&sk=<key>&state=<state>`.
The child redeems it only when `state` is one its own tab saved when it
asked for the fork; any other link (someone else's, sent to this browser)
is ignored without calling `consume`.

### POST /api/auth/forks/consume

The child app, on its own origin, turns a fork into its own session. The
`X-Kutup-Client` header must be the client type the fork was minted for and the
request `Origin` must equal that app's configured origin (`403`); the selector
is single-use and expires after 60 s (`401`). Sets the child's refresh cookie
on its own origin. Rate-limited with login.

**Request body:** `{"selector": "<selector>"}`

**Response:**
```json
{
  "accessToken": "<jwt>",
  "sessionId": "<uuid>",
  "userId": "<uuid>",
  "payload": "<the SessionFork envelope, canonical base64>"
}
```

### PUT / GET /api/auth/sessions/current/local-key

A web session keeps its unlocked keys in the browser as a `WebSession`
local-state envelope (profile `<client type>:<session id>`); the 32-byte key
that opens it lives only here, released only to that live session. Neither the
browser blob nor this key is useful alone, and revoking the session makes the
blob useless. Web sessions only (`400` for the CLI).

**Auth:** Bearer · **Body / response:** `{"key": "<canonical base64, 32 bytes>"}`
(`404` from GET when none is stored)

---

## User

### GET /api/user/me

Return the current user's profile (public key + storage stats). The encrypted key bundle is **not** returned here — it is delivered as part of the `/api/auth/login` response.

**Auth:** Bearer JWT

**Response:**
```json
{
  "id": "<uuid>",
  "accountId": "<uuid, the same: the account's permanent id>",
  "server": "example.com",
  "address": "alice@example.com",
  "envelopeBinding": "<the account's key binding>",
  "username": "alice",
  "publicKey": "<base64>",
  "totpEnabled": false,
  "storageQuotaBytes": 5368709120,
  "storageUsedBytes": 104857600,
  "isAdmin": false,
  "color": "",
  "versionRetentionDays": 30
}
```

`storageQuotaBytes` / `storageUsedBytes` are the account's one storage pool.
Drive, Photos, Office, Maps and Chat all count against it.

---

### GET /api/user/storage/versions

The caller's deletable earlier versions (every version they saved except each
file's newest), grouped by whole days of age and whether they are kept
forever, so a client can show what deleting by age would free.

**Auth:** Bearer JWT

**Response:** `[{ "ageDays": 0, "keepForever": false, "bytes": 1300, "count": 2 }, …]`

### POST /api/user/storage/versions/prune

Delete for good the caller's earlier versions at least `olderThanDays` whole
days old (`0`: every earlier version). Each file's newest version always
stays; kept-forever versions go only with `includeKeptForever`. Charges are
released with each row. At most 500 versions per request: repeat while
`more` is true.

**Auth:** Bearer JWT

**Body:** `{ "olderThanDays": 30, "includeKeptForever": false }` (`olderThanDays`
0–36500, else `400`)

**Response:** `{ "deletedCount": 12, "freedBytes": 4800000, "more": false }`

### GET /api/user/storage

Return what fills the caller's storage pool, by app and by kind of stored
bytes. All sizes are the ciphertext bytes the server stores and charges. The
server cannot tell what the files are; the Account app's Settings → Storage
page works out "Files by type" in the browser from decrypted names.

**Auth:** Bearer JWT

**Response:**
```json
{
  "quotaBytes": 10737418240,
  "usedBytes": 524288000,
  "reservedBytes": 0,
  "drive": {
    "filesBytes": 400000000,
    "filesCount": 120,
    "trashBytes": 20000000,
    "trashCount": 4,
    "versionsBytes": 30000000,
    "thumbnailsBytes": 5000000,
    "assetsBytes": 1000000
  },
  "chat": {
    "mediaBytes": 50000000,
    "historyBytes": 10000000,
    "historyMediaBytes": 8288000
  },
  "contacts": { "bytes": 52000, "count": 40 },
  "mail": { "bytes": 41000000, "count": 900 }
}
```

- `contacts` is the address book: each contact's summary and sealed card.
- `mail` is every stored message, encrypted, attachments included.
- `usedBytes` is the account counter every write charges and every limit checks.
- `reservedBytes` is held for work still in flight: open tus uploads, the
  unreceived part of open Chat media uploads, and pending federated inbound
  Chat-media hand-overs. It counts against the quota until the work finishes
  or is abandoned.
- `drive.files*` are files the caller uploaded that are not in the trash,
  wherever they are (pruned originals excluded). `drive.trash*` are the
  caller's trashed files. `versionsBytes` are file versions the caller saved,
  `thumbnailsBytes` thumbnails and previews, and `assetsBytes` images that
  documents and whiteboards embed.
- `chat.mediaBytes` is delivery media the caller holds a reference to,
  `historyBytes` the history backup segments and base, and `historyMediaBytes`
  the backup media copies. Every stored copy counts, so an attachment kept for
  delivery and in the backup is charged twice.

---

### POST /api/user/2fa/setup

Generate a TOTP secret and return a QR code URI.

**Auth:** Bearer JWT

**Response:**
```json
{
  "secret": "BASE32SECRET",
  "qrUri": "otpauth://totp/Kutup:user@example.com?secret=BASE32SECRET&issuer=Kutup"
}
```

The secret is stored as *pending* and only becomes active after `POST /api/user/2fa/verify` succeeds. While two-step sign-in is on, this is `409`: the secret in use changes only by turning it off and on again.

---

### POST /api/user/2fa/verify

Confirm TOTP setup by providing the first valid code, with the password proved
again: a `totp` grant from a reauth of this session. Beside security keys
(two-step sign-in already on), a factor the account has is proved too:
`recoveryCode` or `securityKey` (`403 secondFactorRequired` without), and
the response's `recoveryCodes` is empty (the account's codes stay).

**Auth:** Bearer JWT

**Request body:**
```json
{
  "code": "123456",
  "grant": "kg1_…"
}
```

**Response:** `{ "message": "TOTP enabled", "recoveryCodes": ["xxxxx-xxxxx", …] }`:
the account's recovery codes, shown once (Crockford base32, 10 characters;
as many as `twoFactorRecoveryCodes`, 16 at first). Each takes the second
factor's place once. The server keeps only a MAC of each, under a key it
makes for itself, bound to the account.

---

### GET /api/user/2fa/recovery-codes

`{ "remaining": <n> }`: how many recovery codes are left. **Auth:** Bearer JWT.

### POST /api/user/2fa/recovery-codes

New recovery codes in place of the old ones, which stop working: `{ "code":
"…", "grant": "kg1_…" }` → `{ "recoveryCodes": [...] }`, shown once. The code
is the authenticator's or an unused recovery code (then spent), and the grant
is a `totp` grant from a reauth of this session: as in Proton, a session and
the password alone cannot mint codes. `400` for a wrong code, `409` while
two-step sign-in is off.
**Auth:** Bearer JWT.

---

### DELETE /api/user/2fa

Turn the authenticator app off. Requires a valid TOTP code (or a recovery
code, or `securityKey`: a key's answer to `POST
/api/auth/security-keys/proof/start`) and a `totp` grant from a reauth of
this session, so a stolen session cannot remove 2FA. With security keys left
two-step sign-in stays on, with its recovery codes; otherwise they go with
it.

A wrong code here or at `POST /api/user/2fa/recovery-codes` still uses up
the grant, so each guess takes the password again. Wrong codes count per
account: the `totp_attempts`-th (5) blocks both routes for
`totp_block_minutes` (both rate-limit settings), with `429`, the right code
included.

**Auth:** Bearer JWT

**Request body:**
```json
{
  "code": "123456",
  "grant": "kg1_…"
}
```

---

### Security keys: `/api/auth/security-keys`

Security keys (WebAuthn: a YubiKey, or a phone's or computer's built-in
authenticator used as a key) as a second factor beside the authenticator app,
as Proton has them (docs/plans/security-keys.md): several per account, each
named; not passkeys (no passwordless sign-in). The relying party is the
account app's origin and the RP id (`KUTUP_WEBAUTHN_RP_ID`, else
`KUTUP_BASE_DOMAIN`, else the account app's host); where WebAuthn can't work (plain http off localhost) keys are
off: `available: false`, and the routes answer `503 securityKeysOff`.

- `GET` → `{ keys: [{ id, name, createdAt, lastUsedAt, compromised }],
  requireUv, limit, available }`.
- `POST register/start` `{ grant, code | securityKey }` (a `totp` grant
  from a reauth of this session; while two-step sign-in is on, a factor the
  account has proved again, as `DELETE` takes it, else `403
  secondFactorRequired`) → `PublicKeyCredentialCreationOptions` (JSON form): attestation
  `none`, not discoverable, the account's keys excluded, user verification
  from "Require PIN". `409 securityKeyLimit` at `securityKeysPerAccount`
  (10).
- `POST register/finish` `{ name, credential }` (1–128 characters; the
  browser's `toJSON()` from `create()`) → `{ key, recoveryCodes? }`.
  The account's first second factor turns two-step sign-in on, with its
  recovery codes (shown once). A start that proved no factor can't finish
  once one is on (`403 secondFactorRequired`). Names refuse control and
  format characters (bidi overrides). `409 securityKeyExists` (on this or
  any account: a credential is unique), `400
  securityKeyRefused` (another origin or RP, a wrong answer), `400
  securityKeyCeremony` (expired or answered).
- `PATCH {id}` `{ name }` renames it (`204`).
- `DELETE {id}` `{ grant, code | securityKey }`: the password and the second
  factor proved again, as `DELETE /api/user/2fa` takes them → `{
  twoFactorOff }`. Removing the last factor turns two-step sign-in off and
  drops the recovery codes.
- `POST proof/start` → options for proving the second factor with a key for
  this session: the answer goes in `securityKey` (removing a key or the
  authenticator app, renewing recovery codes).
- `PUT require-uv` `{ grant, requireUv, code | securityKey }`: Proton's
  "Require PIN", user verification when adding and signing in (`204`).
  Turning it off takes the second factor too.

Every change is in the security log (`securityKeyAdded`, `securityKeyRemoved`,
`securityKeyCompromised`, each with the key's name in `oldName`;
`authenticatorOn`, `authenticatorOff`, and `twoFactorOn`/`twoFactorOff`
when two-step sign-in turns on or off), and the account's other sessions
see a new session version.

---

### Usernames and renames

Names are compared folded (docs/plans/username-renames.md): lowercase without
`.`, `_` and `-`, so `ada.l`, `Ada_L` and `adal` are one name. One account
holds a folded name; sign-in takes any spelling; mail to any spelling of a
live address is delivered.

A rename keeps everything but the name. The old name is **held** for the
account: its address receives (only) for `oldAddressReceiveDays`, then
bounces; after `nameHoldDays` the name is freed for anyone (a new owner is
another incarnation, so pins warn). Both are in `GET /api/auth/settings`
(`nameHoldDays`, `oldAddressReceiveDays`) and set by administrators
(`PUT /api/admin/settings`). A deleted account's names are held the same way,
receiving nothing.

- `GET /api/user/rename/check?name=` → `{ "available": true, "takeBack"?,
  "needsKey", "spelling"? }` or `{ "available": false, "reason": "taken" |
  "held" | "reserved" | "invalid" }` (30 per 15 minutes per account).
  `needsKey`: the rename sends the address's first key (`mailAddress`); false
  only for a held name whose address kept its keys. `spelling`: for a name
  taken back, the spelling it is taken back as (its address, keys and key
  lists name it so; another spelling is `renameInvalid` with `spelling`).
- `POST /api/user/rename` → `{ "grant": "<a rename grant from a reauth>",
  "rename": <AccountRenameV1>, "mailAddress": { "publicKey",
  "privateKeyEnvelope", "keyList" } }` (the Drive key binding names the
  account's id, so it stays as it is) → `200 { "username", "address", "sequence", "oldAddressReceivesUntil",
  "oldNameFreeAt" }`. `mailAddress` is the new address's first key and key
  list (sequence 1, that key primary), as `POST /api/mail/addresses/{id}/keys`
  takes them, stored in the rename's transaction so mail to the new address is
  never deferred; sent exactly when the check says `needsKey` (otherwise
  `renameInvalid`). The display
  name and signature move to the new address. Errors: `renameInvalid`, `grantInvalid`, `breakGlassAccount`,
  `setupRequired`, `nameTaken`, `nameReserved`, `renameConflict`,
  `tooManyHeldNames`, `renameTooSoon`. One counted rename per 30 days; going
  back to the name just left within 7 days of that rename is free, once, and
  restarts the clock. No session ends.
- `GET /api/user/names` → `[{ "name", "state": "current" | "held",
  "receiveUntil", "freeAt" }]`.
- `DELETE /api/user/names/:name` (`{ "grant" }`, a rename grant) → `204`:
  receiving there ends now; the name stays held until its date (`notHeld`;
  `dropTooSoon`: one drop per 30 days).
- `GET /api/users/renames/:address[?incarnationId=]` → `{ "version": 1,
  "chains": [{ "incarnationId", "authorityPublicKey", "current", "state":
  "current" | "held" | "gone", "chain": [<AccountRenameV1>, …] }] }`, newest
  first; a reused name appears in several. Clients verify every chain against
  their pins (`version` other than 1: unverifiable, warn). For another
  server's address: the chains this server keeps of it (from announces, earlier
  lookups and relayed `409 renamed`), asked of that server when none is fresh
  (a day). The server unreachable and nothing kept: `{ "version": 1, "chains":
  [], "unavailable": true }`, which says nothing either way (`429 rateLimited`
  past 60 such lookups in 15 minutes per account).
- A peer's `409 renamed` to this server's lookup (Chat keys, manifests and
  profiles, the federated Drive user) reaches the client as the same `409
  renamed`, its chains verified (each signed by its authority, every address on
  that peer, naming the address asked) and kept; a peer's answer that does not
  check out is `502`.
- **Lookups of an old name** (the address lookup, Chat manifests, keys and
  profiles, the federated Drive user and their `/api/fed/` twins) answer
  `409 renamed` with that list.
- `/user/me` carries `renames: { "sequence", "digest"? }`: where the
  account's chain ends, what its devices anchor to.
- **Reauth** (`login/start`, `purpose: "reauth"`) names no account: it is the
  session's own; a `name` is `400`.
- Admin: `POST /api/admin/names/:name/close` (receiving ends now) and
  `POST /api/admin/names/:name/free` (free now) → `204`; recorded on the
  account as `nameClosed` / `nameFreed`.

### GET /api/user/security-events

What changed the caller's sign-in, newest first: a new password, a recovery, a
move to the server's current sign-in setup, an administrator's reset. Kept a
year, or the newest 500. No IP addresses. An account reset keeps the earlier
events.

**Auth:** Bearer JWT

**Query:** `limit` (1–100, default 50), `cursor` (the previous page's `next`;
one that is not one of the caller's events is `400`: start from the first page)

**Response:**
```json
{
  "events": [
    {
      "id": "<uuid>",
      "kind": "passwordChange",
      "at": "2026-10-14T09:00:00Z",
      "thisSession": true,
      "client": "web-account",
      "userAgent": "Mozilla/5.0 …",
      "byAdmin": false
    }
  ],
  "next": "<uuid or null>"
}
```

- `kind`: `passwordChange`, `recovery`, `rotate`, `adminReset`,
  `accountReset`. More kinds will come; show an unknown one generally.
- `thisSession`: made from the caller's own sign-in.
- `client`, `userAgent`: what made it, as the session list shows it (absent
  for a recovery or an administrator's reset).
- `byAdmin`: an administrator's reset.

---

### GET /api/users/by-address/:address

An account by the address a person types: the one place a name becomes an
account (docs/plans/account-ids.md); everything after takes the account id.
An address on another server is asked of that server through signed
federation (its pinned identity, after discovery, admission and response
authentication), each such fetch counting against the caller's limit for
that server (`RATE_LIMIT_ACCOUNT_PEER_FETCHES_PER_MIN`, `429 rateLimited`).
A name held there answers `409` with the rename chains it relays, as Drive's
lookups always have.

**Auth:** Bearer JWT; 30 lookups per minute per IP (`RATE_LIMIT_USER_LOOKUP_PER_MIN`), then `429`
**Param:** `:address` — the URL-encoded Kutup address (`username@<server>`). `404` when no active account has it.

**Response**, one shape for an account here or on another server (the same
as `GET /api/users/by-id`; on this server `accountId` is the user id):
```json
{
  "username": "bob",
  "server": "example.com",
  "accountId": "<uuid>",
  "account": "bob@example.com",
  "driveHpkePublicKey": "<canonical base64, 32 bytes>",
  "accountIncarnationId": "<lowercase SHA-256 hex>",
  "driveSigningPublicKey": "<canonical base64, 32 bytes>",
  "accountAuthorityPublicKey": "<canonical base64, 32 bytes>",
  "driveKeyBinding": "<canonical base64, 64 bytes>"
}
```

The address leads to the account `{ server, accountId }` (docs/plans/account-ids.md):
the answer is the server's word, a lookup handle only, and `account` is a
label. Shares, pins and records name the account, never the address.
`driveKeyBinding` is the account authority's signature over the account
(server and id) and its Drive keys (`kutup_crypto::drive_key_binding`); it is absent only
from a peer server that does not send one. An account still in its first-login
setup (new, or wiped by an administrator) has no keys to share to and answers `404`,
as `by-id` does. Clients check the binding and pin the authority
(docs/plans/drive-identity-pins.md); another server's answer carries the
same two fields.

### GET /api/users/by-id/:accountId

An account by its permanent id (docs/plans/account-ids.md): its address now
(server-asserted, a label) and its Drive identity, as the address lookup
answers them. `?server=` names the account's server (this one when left
out); another server's account is asked of that server through federation
(`GET /api/fed/drive/accounts/:accountId`, the pinned peer, never a URL from
the query). One fetch per account at a time; its answer (or its `404`)
serves every lookup of that account for 30 seconds, unless a rename of the
account reaches this server first (its announce, or a chain a lookup brings),
which drops it so the new name shows at once. Only a real fetch counts,
at most `RATE_LIMIT_ACCOUNT_PEER_FETCHES_PER_MIN` a minute per caller and
peer. The answer must name the same server and id, with the incarnation its
authority key stands for (`502` otherwise).

**Auth:** Bearer JWT; counted with the user lookups
(`RATE_LIMIT_USER_LOOKUP_PER_MIN`). `400` for an id that is not a lowercase
hyphenated UUID or a server that is not a canonical name; `404` when no
active, set-up account has it.

**Response:** `{ "username", "server", "accountId", "account",
"driveHpkePublicKey", "accountIncarnationId", "driveSigningPublicKey",
"accountAuthorityPublicKey", "driveKeyBinding" }`. No rename chain: a client
showing the address verifies it with `GET /api/users/renames/:address`.

### POST /api/users/drive-identities

The Drive identities of up to 100 accounts on this server at once, by exact
address: what a page that shows many people checks them with, in one request.
Body: `{ "accounts": ["alice@example.org", …] }`. Answers an array of
`{ account, accountAuthorityPublicKey, driveHpkePublicKey,
driveSigningPublicKey, driveKeyBinding? }` for the accounts found (unknown,
disabled and not yet set-up accounts are left out); `400` for more than 100.

**Auth:** Bearer JWT; counted with the user lookups (`RATE_LIMIT_USER_LOOKUP_PER_MIN`), one per request.

### GET /api/user/identity-pins · PUT /api/user/identity-pins

The account's pins on other accounts' authorities: one list sealed under a key
derived from its master key (`kutup_crypto::identity_pins`), opaque to the
server, shared by every app of the account.

**Auth:** Bearer JWT

**Response (GET):** `{ "revision": 1791633600000, "envelope": "<canonical base64>" }`
(the revision is the one in the envelope's header).
**Body (PUT):** `{ "baseRevision": 1791633600000, "envelope": "<canonical base64>" }`

`GET` answers `404` before the first list. The revision is sealed in the
envelope's authenticated header (a time in unix milliseconds, above every
revision the writer has seen; docs/plans/sealed-revisions.md). A `PUT` is
stored only if the stored list is still `baseRevision` (0 before the first)
and the envelope's revision is above it (`400` if not), else `409` with
`{ "code": "revision_conflict", "revision": <stored> }`: the client merges with
the stored list and tries again. Clients refuse a list older than one they
have seen.


### GET /api/account/ui-preferences · PUT /api/account/ui-preferences

The account's theme and language, the same in every web app and on every
device. Not secret, so stored as they are (not end-to-end encrypted).

**Auth:** Bearer JWT

**Body (PUT) and response:**
```json
{ "theme": "light" | "dark" | "system" | null, "language": "en" | "tr" | null }
```

A null value means the account has not chosen; each app then keeps its own
(the system theme, the browser's language). `PUT` replaces both values; an
unknown value or an extra field is a `400`.

Each signed-in app keeps a local copy for its first paint, takes the
account's values when it opens and when its tab comes back into view, and
saves a change made in its theme or language control
(`useAccountUiPreferences`, `frontend/packages/session/src/uiPreferences.ts`).
The first app to load for an account that never chose saves its own choice.
Public pages (shared links, public albums) keep only the local choice.
---

## The account head

Rollback protection across devices (docs/plans/rollback-protection.md): one
small sealed head per account, numbered and hash-chained, saying for each kind
of listed value how many there are and a digest of their `(id, revision)`
pairs. The server never opens it; it reads the sequence in clear and keeps the
newest 1,001 (a device anchored 1,000 heads back still gets its whole segment,
anchor included).

**Listed writes** carry the next head as `head` (base64) in their JSON body:
contacts (create, update, delete, `delete` many, import: one head per batch),
mail folder, label and filter names (create, rename, delete), the identity pin
list, Pass vault secrets (keep, forget). A delete takes a JSON body
`{ "head": "…" }`. The head's sequence must be the current one plus one, else
`409 head_conflict`; the check runs last in the write's own transaction, after
the account row is locked and the session found live under the lock (a write
that began before a wipe is refused). Before the chain is started a listed
write needs none (and a head with it is `409 head_conflict`: start the chain
first); after, one without a head is `409 head_required`.

**Starting the chain** is its own call, on the `basis` an index answers with
before the first head (`POST /api/account/head`): a listed write landing
between the client's read and its start moves the basis, and the start is
refused, so the first head always covers every value. A head sent with a change that is no listed write (a
folder's colour, parent, position or folding; a filter switched on or off, or
what it matches or does: these are not sealed and not rollback-protected) is
`400`.

**A folder delete** removes the folders inside it too, so it names them all:
`DELETE /api/mail/folders/:id` with `{ "removes": ["<id>", …], "head": "…" }`.
If they are not exactly the folders it removes (one was added inside since),
`409 head_conflict`.

### GET /api/account/head

**Auth:** Bearer JWT. **Response:** `{ "head": "<base64>" | null }` (null
before the account's first).

### POST /api/account/head

Starts the chain: `{ "head": "<base64, sequence 1>", "basis": "<from an
index>" }` → `201`. `409 head_conflict` when the account has a head already or
the basis moved (read the index again and remake the head). **Auth:** Bearer
JWT.

### GET /api/account/heads?from=n

The chain from sequence `n` toward the newest, oldest first, at most 200 at a
time: `{ "heads": ["<base64>", …], "next": <sequence> | null }` (ask again from
`next` until it is null); empty when `n` is above the newest. `410 tooOld` when
`n` is more than 1,000 behind the newest. `400` for `n` below 1. **Auth:**
Bearer JWT.

The three reads are limited to 300 a minute per account
(`RATE_LIMIT_ACCOUNT_HEAD_READS_PER_MIN`; `429 rateLimited`).

### GET /api/account/index/:scope

A scope's values and the head they go with, read in one snapshot (check the
index against this head, not one fetched separately):
`{ "head": "<base64>" | null, "values": [["<id>", <revision>], …], "basis":
"<hex>" | null }`, sorted by id; `basis` (before the first head only) is what a
chain start names. **Auth:** Bearer JWT. Scopes and their ids:
- `contacts`: the contact's UID (chosen by the client, unique per account, never changed: an update naming another UID is `400`), so a head can be made before a create or an import;
- `mailNames`: `folder:<id>`, `label:<id>`, `filter:<id>`, with the revision in
  the sealed name's header (a folder without a name, kept through an account
  reset, is left out until it is named again);
- `pins`: one value, `pins`;
- `chatGroups`: the group list's entry ids (`GET /api/chat/group-list`), with
  the revision in each sealed entry's header. Readable whether or not pairwise
  groups are on (empty when they are off, since nothing can be written);
- `chatContacts`: the Chat contact list's entry ids (`GET
  /api/chat/contact-list`), with the revision in each sealed entry's header;
- `passSecrets`: the vault's file id, for every secret the account keeps, the
  vault trashed, purged or out of reach included ("unreachable but listed":
  the secret stays until its owner forgets it, `POST
  /api/pass/vault-secrets/forget`).

Any other scope is `404`: a client treats it as one with no index yet
(`IndexCheck::Uncovered`).

**An account reset** (an administrator's wipe) deletes the head chain with the
old incarnation, and every listed value sealed under the old keys: contacts,
the group list, labels, filters and Pass secrets. Custom folders keep their mail and lose their
names (`name: null` in `GET /api/mail/places`; "Unnamed folder" until renamed
with `baseNameRevision: 0`). The new incarnation's first write makes its first
head.

---

## Collections

### GET /api/collections/

List all collections accessible to the current user (owned and shared).

**Auth:** Bearer JWT

**Response:** Array of collection objects. Owned and shared collections use the
same authenticated record. An owned row contains `ownerKeyEnvelope`; a shared
row contains `namedShareEnvelope`, `isShared: true`, and the owner's registered
identity fields required for independent client verification. Neither key
envelope is returned in the other row type.

```json
[
  {
    "id": "<uuid>",
    "ownerUserId": "<uuid>",
    "nameEnvelope": "<DriveEnvelopeV1 base64>",
    "namedShareEnvelope": "<NamedShareEnvelopeV1 base64>",
    "keyEpoch": 1,
    "nameRevision": 1,
    "epochStatement": "<CollectionEpochStatementV1 base64>",
    "epochStatementHash": "<lowercase SHA-256 hex>",
    "ownerServer": "example.com",
    "ownerAccount": "alice@example.com",
    "ownerIncarnationId": "<lowercase SHA-256 hex>",
    "ownerDriveSigningPublicKey": "<canonical base64, 32 bytes>",
    "ownerAuthorityPublicKey": "<canonical base64, 32 bytes>",
    "parentCollectionId": null,
    "color": "blue",
    "canUpload": true,
    "canDelete": false,
    "uploadQuotaBytes": null,
    "uploadUsedBytes": null,
    "isShared": true,
    "createdAt": "2026-09-01T10:00:00Z",
    "updatedAt": "2026-09-23T12:30:00Z"
  }
]
```

`updatedAt` is the folder's "modified" time as a file manager shows it: the
latest of the folder's own change (rename, colour), its newest direct file
change (upload, rename, or a new saved version), and its newest direct
subfolder. `GET /api/collections/:id` returns the same fields.

`canUpload`, `canDelete`, `uploadQuotaBytes`, `uploadUsedBytes`, `isShared`, and
the owner identity fields are present only on shared collections (the owner has
full rights implicitly). Clients verify the named-share signature, recipient
incarnation, epoch statement, epoch hash, collection-key commitment and name
envelope before displaying or using a shared collection.

---

### POST /api/collections/

Create a new collection.

**Auth:** Bearer JWT

**Request body:**
```json
{
  "id": "<client-generated canonical uuid>",
  "nameEnvelope": "<DriveEnvelopeV1 base64>",
  "ownerKeyEnvelope": "<DriveEnvelopeV1 base64>",
  "epochStatement": "<CollectionEpochStatementV1 base64>",
  "parentCollectionId": null,
  "nameHash": "<64 lowercase hex>"
}
```

`nameHash` (required for a folder, see "Names in a folder"; ignored for an
album) keeps the name unique among the parent's files and subfolders, or
among the owner's top-level folders; a missing one is `400`, a taken name
`409 name_taken`.

The name envelope is bound to `(collection ID, owner user ID, epoch 1,
revision 1)`. The owner-key envelope binds the same identifiers with the
collection-key purpose. The account authority signs the epoch-1 statement.
Creation writes the collection and its first immutable epoch-history row in one
database transaction.

**Response:** `201 Created`
```json
{
  "id": "<uuid>"
}
```

---

### GET /api/collections/:id

Get a single owned or shared collection by ID. The response has the same
owner-vs-recipient key-envelope separation as the list route.

**Auth:** Bearer JWT

**Response:**
```json
{
  "id": "<uuid>",
  "ownerUserId": "<uuid>",
  "nameEnvelope": "<DriveEnvelopeV1 base64>",
  "ownerKeyEnvelope": "<DriveEnvelopeV1 base64>",
  "keyEpoch": 1,
  "nameRevision": 1,
  "epochStatement": "<CollectionEpochStatementV1 base64>",
  "epochStatementHash": "<lowercase SHA-256 hex>",
  "parentCollectionId": null,
  "color": "blue"
}
```

---

### PUT /api/collections/:id

Rename a collection (client re-encrypts the name with the collection key).

**Auth:** Bearer JWT

**Request body:**
```json
{
  "nameEnvelope": "<DriveEnvelopeV1 base64>",
  "nameRevision": 2,
  "nameHash": "<64 lowercase hex>"
}
```

`nameHash` (required for a folder; albums have none) is the new name's
hash in the folder's place; a name another item there holds is
`409 name_taken`.

The revision must be exactly one greater than the stored revision and the
envelope must authenticate that exact revision, current epoch, collection and
owner. Concurrent/stale renames fail instead of overwriting a newer name.

**Response:** `200 OK` `{"message": "updated"}`.

---

### DELETE /api/collections/:id

Move a collection — with its whole subtree (sub-folders + files) — to the trash. The folder becomes a single trash entry; restore or purge it via the Trash endpoints. Items already in the trash keep their own entry and deletion time. While trashed, the subtree is invisible to every other endpoint (listings, downloads, shares, federation, collab) and its public share links go dark. Trashed items keep counting against quota until purged.

**Auth:** Bearer JWT (owner only)

**Response:** `204 No Content`.

---

### PATCH /api/collections/:id/color

Set the display color of a folder.

**Auth:** Bearer JWT

**Request body:**
```json
{
  "color": "blue"
}
```

**Response:** `204 No Content`.

---

### POST /api/collections/:id/share

Share a collection with another user on this server.

**Auth:** Bearer JWT

**Request body:**
```json
{
  "recipientUserId": "<uuid>",
  "namedShareEnvelope": "<NamedShareEnvelopeV1 base64>",
  "canUpload": false,
  "canDelete": false,
  "uploadQuotaBytes": null
}
```

`namedShareEnvelope` HPKE-encrypts the collection key to the recipient's
registered Drive key and signs the collection, epoch, sender/recipient accounts
and both incarnation IDs with the sender's registered Drive signing key. All
recipients have read access; `canUpload` and `canDelete` are independent boolean
grants. `uploadQuotaBytes` optionally caps uploads; omit (or `null`) for no
per-share cap.

**Response:** `201 Created` `{"message": "shared"}`. Re-sharing with the same recipient updates the existing grant (upsert).

---

### POST /api/collections/:id/federated-shares

Create a domain-bound share for a user on a remote Kutup instance.

**Auth:** Bearer JWT

**Request body:**
```json
{
  "recipientServer": "other.example.com",
  "recipientAccountId": "<uuid, from the lookup>",
  "namedShareEnvelope": "<NamedShareEnvelopeV1 base64>",
  "canUpload": true,
  "canDelete": false,
  "uploadQuotaBytes": null
}
```

The named envelope is sealed to the account the lookup above returned
(`other.example.com` and its `accountId`). The origin asks the recipient's
server for that account by id (`GET /api/fed/drive/accounts/:accountId`):
the username the share lists is its answer, never the client's, and the
envelope must be sealed to the incarnation it answers (`409 keyChanged`).
Accepting compares the account id, so a rename on either side never breaks
the share. The origin validates the sender signature and all
routing bindings before storing it. The destination repeats that validation
against Bob's current registered incarnation and verifies the owner-signed epoch
statement before accepting the invite. The origin stores the canonical
recipient domain and a SHA-256 capability verifier, not a remote URL or
plaintext capability.

**Response:** `201 Created`
```json
{
  "inviteUrl": "https://this.example.com/invite#server=this.example.com&capability=<base64url>"
}
```

The capability appears only in the fragment so browsers do not send it to the
sharer's web origin. It is shown once and cannot be recovered from the outgoing
share row.

For a Photos album (`kind = 'album'`) the link ends in `&kind=album`, and the
share is view only: `canUpload`, `canDelete` and `uploadQuotaBytes` must be
`false`/`null`, else `400`.

---

## People you share with (profiles)

People who share a folder, either way round and across servers, hand each
other the key to their end-to-end encrypted profile so Drive can show names
and pictures (docs/plans/unified-profile.md). One key per pair, however many
folders they share.

### GET /api/drive/people

**Auth:** Bearer JWT

Everyone you share a folder with or who shares one with you:

```json
{
  "people": [{
    "server": "example.org",
    "accountId": "<uuid>",
    "account": "bob@example.org",
    "local": true,
    "accountIncarnationId": "<hex>",
    "drivePublicKey": "<base64>",
    "driveSigningPublicKey": "<base64>",
    "receivedEnvelope": "<ProfileKeyEnvelopeV1 base64> | null",
    "sentProfileVersion": "<hex> | null"
  }]
}
```

People are their server and account id; `account` is their address now,
shown only. For someone on another server (`local: false`) the three key
fields are null: look them up with `GET /api/users/by-id/:accountId?server=`. Open
`receivedEnvelope` with your Drive key and check it with theirs; the profile
key then fetches their profile through
`GET /api/chat/accounts/:accountId/profile/:version?server=`. When `sentProfileVersion` is
not your current profile version, give them your key again.

### PUT /api/drive/profile-keys

**Auth:** Bearer JWT

```json
{
  "recipientServer": "example.org",
  "recipientAccountId": "<uuid>",
  "envelope": "<ProfileKeyEnvelopeV1 base64>",
  "profileVersion": "<hex, the version the key opens>"
}
```

The server checks that the envelope is from you (your account, incarnation
and Drive signing key), is for that account (and, here, its current
incarnation), and that a share exists between you. Someone on another server
gets it through `PUT /api/fed/drive/profile-keys`. `204`; `404` when there is
no share between you; `400` for an envelope that does not match.

---

## Mail address keys

Each account's email address is `username@<server name>`, with OpenPGP keys
as Proton keeps address keys (`docs/plans/mail-address-keys.md`). The server
never holds a private key: it stores the public key, the secret key sealed in
an `AccountEnvelopeV1` under the master key (purpose `MailAddressPrivateKey`,
binding the address and fingerprint), and each address's signed key list
(`MailKeyListV1`, signed by the account authority and hash-chained). Key flags
use Proton's bits: `1` may verify, `2` may encrypt to, `4` mail not end-to-end
encrypted, `8` mail not expected to be signed.

### GET /api/mail/addresses

The caller's addresses: its current ones in the account's order (the first
enabled one with a key is the default), then, after a rename, the old ones,
newest first, with their keys, which open the mail they received. `state` is
`active` (a current address: the account's own, and its addresses on custom
domains), `receiving`, `closed` or `freed`. `domainId` names the custom
domain (null for the server's own), `position` its place in the order, and
`disabled` a disabled address (it neither receives nor sends; its keys keep
opening its mail). An account without a username has none.

**Auth:** Bearer JWT

**Response:**
```json
[{
  "id": "uuid",
  "address": "alice@kutup.dev",
  "state": "active",
  "domainId": null,
  "position": 0,
  "disabled": false,
  "keys": [{
    "id": "uuid", "fingerprint": "40 hex", "sha256Fingerprint": "64 hex",
    "publicKey": "base64 binary OpenPGP certificate",
    "privateKeyEnvelope": "base64 AccountEnvelopeV1",
    "primary": true, "flags": 3, "createdAt": "RFC 3339", "forwarding": false
  }],
  "keyList": { "data": "base64 canonical MailKeyListV1", "signature": "base64 Ed25519" }
}]
```

`keyList` is null until the first key is added. A key with `forwarding: true`
is a forwarding key (below): it opens only mail forwarded to the address, is
never primary or encrypted to, and isn't in `keyList`.

### GET /api/mail/identity · PATCH /api/mail/identity

An address's display name and signature, as Proton's per-address identity:
`?addressId=` one of the caller's current addresses, or the default address
when none is named (clients that name none keep the account's). `GET`
answers `{ address, displayName, signature }` (the display name is the
username when none is set); `PATCH` takes `{ displayName?, signature? }`
(a name up to 100 characters without control characters, a signature up to
10 KB of HTML) and answers the same.

### PUT /api/mail/addresses/order

Proton's `PUT addresses/order`: `{ "ids": [...] }`, every current address of
the account (enabled or disabled) in the new order; "Set as default" moves one
first. Not exactly the account's current addresses: `409 addressSetChanged`
(a tab that missed one added or deleted); a disabled address first: `400
disabledDefault`. `204`.

### PUT /api/mail/addresses/:id/disable · PUT /api/mail/addresses/:id/enable

Proton's Disable and Enable, for an address on a custom domain (the account's
own address stays enabled: `409 ownAddress`). The body is the address's next
signed key list (`{ "keyList" }`, the same keys): for disabling, none of them
to be encrypted to (`FLAG_NOT_OBSOLETE` cleared), so senders and WKD stop
offering it and a lookup answers `404 addressDisabled`; for enabling, its
primary key to be encrypted to again. A disabled address neither receives
(its mail is refused, never caught by a catch-all, which it stops being) nor
sends (`403 addressDisabled`); its keys keep opening the mail it received.
The default address can't be disabled (`409 defaultAddress`). `200` with the
address.

### PUT /api/mail/addresses/:id/delete

Proton's Delete for a disabled address on a custom domain (`409
addressEnabled` while enabled: disable it first, as Proton's client does; one
that never had a key is deleted at once). The name is free for anyone again;
its keys stay with this account, opening the mail it received, never
published or used for new mail. Its forwardings end, from it and to it, and
never come back if the account takes the address back. `204`.

### POST /api/mail/addresses/:id/keys

Add a key to one of the caller's addresses together with the next signed key
list. The server checks: the public key is a v4 Ed25519 + Curve25519 key whose
only user ID is this address, with valid self-signatures; the envelope has the
mail-key purpose and this account's key binding; the key list verifies against
the account's authority key, names this account and address, follows the
current list (sequence + 1, previous hash) or is sequence 1, and lists exactly
the stored keys plus the new one. Primary and flags then follow the list. All
in one transaction. The same call adds a new key (rotation: the list makes it
primary and keeps the others to open older mail) and a key imported from an
OpenPGP secret key file (the browser unlocks the file and seals the key like a
generated one; the server cannot tell them apart).

**Auth:** Bearer JWT

**Body:** `{ "publicKey": "base64", "privateKeyEnvelope": "base64", "keyList": { "data": "base64", "signature": "base64" } }`

**Response:** the address, as in `GET /api/mail/addresses`. `400` for an
invalid key, envelope or list; `409` when the list does not follow the current
one (another device changed it; reload and retry) or the key is in use.

### PUT /api/mail/addresses/:id/key-list

Publish the next signed key list for the same keys: another key made primary,
or a key marked obsolete (flag `NOT_OBSOLETE` cleared: not encrypted to, still
opens older mail) or compromised (both flags cleared: its signatures are no
longer trusted either). The list is checked as for adding a key and must list
exactly the stored keys; its primary must keep both flags. A list with no key to
encrypt to (every `NOT_OBSOLETE` cleared, the primary still `NOT_COMPROMISED`)
is a disabled address's, and only Disable publishes one (Proton's).

**Auth:** Bearer JWT

**Body:** `{ "keyList": { "data": "base64", "signature": "base64" } }`

**Response:** the address, as in `GET /api/mail/addresses`. `400` for an
invalid list or one that adds or leaves out a key; `409` when it does not
follow the current one.

### GET /api/mail/keys?email=

A Kutup address's public keys (primary first) and every signed key list, oldest
first. Clients verify the chain against `accountAuthorityPublicKey`, checked
against their pin of the account. Rate-limited like user lookup. `email` may
be any spelling of the address (`.`, `_`, `-` and case ignored); the answer
names it as stored, and the account it belongs to by `server` and
`accountId` (server-asserted, as the address lookup's answer is). A shared
mailbox's answer is `{ address, server, groupId, firstSigner, keys,
keyLists, signerHandovers? }` instead: no account, and its chain checked with
`mail_group::verify_group_key_chain` (WASM `verifyMailGroupKeyChain`) from
`firstSigner` through the handovers. A key
list names its address, never a username (docs/plans/account-ids.md), so a
rename leaves it as it is. Clients check that `address` is the one asked,
compared folded, and that the newest list names it.

**Auth:** Bearer JWT

**Response:** `{ "address": "...", "server": "...", "accountId": "<uuid>", "accountAuthorityPublicKey": "...", "keys": [{ "fingerprint", "sha256Fingerprint", "publicKey", "primary", "flags" }], "keyLists": [{ "data", "signature" }] }`; `404` when the address has no keys.

### GET /api/mail/keys/outside?email=

An outside address's OpenPGP key (docs/plans/mail.md, C3), looked up by the
server in order: its Web Key Directory (advanced, then direct), Proton's key
server for Proton's own domains, keys.openpgp.org (verified addresses). The
key is checked before it is returned: version 4, not revoked, a user ID for
the address with a valid self-signature (other keys' certifications are
ignored), not expired, a bound encryption subkey. Cached for an hour.
Rate-limited like user lookup.

**Auth:** Bearer JWT

**Response:** `{ "address", "source": "wkd" | "proton" | "keysOpenpgp", "publicKey", "fingerprint", "createdAt" }`;
`404` when no source has a usable key; `400` for a Kutup address (use
`GET /api/mail/keys`).

### GET /.well-known/openpgpkey/hu/:hash?l=:local

Web Key Directory, direct method, outside `/api`: the binary public keys of
`local@<server name>` that may be encrypted to, primary first,
`application/octet-stream`. `hash` is the z-base-32 SHA-1 of the lowercased
local part and must match `l`; anything else is `404`. No authentication;
rate-limited. `GET /.well-known/openpgpkey/policy` returns an empty policy.
The advanced method answers the same at
`/.well-known/openpgpkey/:domain/hu/:hash?l=` and
`/.well-known/openpgpkey/:domain/policy`, for `domain` equal to the server
name (served on `openpgpkey.<server name>`); any other domain is `404`.

---

## Mail forwarding

Proton's forwarding ([`plans/mail-forwarding.md`](plans/mail-forwarding.md)).
To a Kutup address on this server it is end to end: the server turns each
arriving key packet into one for the forwardee with a proxy factor k, and
reads no message. To anything else it is outside: the server re-sends the
mail it can read, and the address's end-to-end encryption is off while any
outside forwarding lasts (as Proton's). k is sealed at once under
`MAIL_FORWARDING_KEYS` and no answer carries it. **Auth:** Bearer JWT, but
for the three `external` endpoints.

A forwarding: `{ "id", "kind": "end_to_end"|"outside", "state":
"pending"|"active"|"outdated"|"paused"|"rejected", "forwarderAddress",
"forwardeeEmail", "match": "all"|"any", "conditions": [filter conditions on
sender, subject, attachments], "skipped": <messages that couldn't be
forwarded>, "notice": null|"bounces"|"budget", "createdAt", "expiresAt" |
null }`. `notice` says why an outside forwarding stopped on its own: paused
after 5 bounces in a day, or today's budget (200 per forwarding, 500 per
account) spent; it goes on tomorrow.

### GET /api/mail/forwardings

`{ "outgoing": [...], "incoming": [...] }`: the caller's addresses'
forwardings ("From me") and those to them ("To me", declined ones left out).
Pending forwardings past their expiry (7 days) lapse to `rejected` first.

### POST /api/mail/forwardings

`{ "id": "<UUID v4 the client chose>", "forwarderAddressId", "forwardeeEmail",
"match", "conditions", "endToEnd": { "forwardeePublicKey": "<base64>",
"instances": [{ "forwarderFingerprint", "forwardeeFingerprint",
"proxyParameter": "<base64, 32 bytes>" }], "activation": "<armored>" } }` →
`201` with the forwarding, pending. The client chooses the id so the
activation can bind it.

**Outside Kutup** there is no `endToEnd`, the account must be allowed to send outside now (`403
outsideSendingOff` under the server's policy, `403 sendingPaused` while its
sending is paused; Mail's own rules), and `forwardeeEmail` must be a plain mailbox (an RFC 5321
dot-atom local part, a domain of two or more labels; no quoting, IP
literals, control characters or whitespace). The first outside forwarding of an
address brings `"keyList"`: its next signed key list, every key as it is
plus `EMAIL_NO_ENCRYPT` (`400 keyListRequired` without it, `400
keyListMismatch` for any other change). It stays pending (7 days) until the
forwarder enters the code mailed to the destination (see Verification below). While the address forwards outside,
WKD offers none of its keys, and a key list clearing the flag is `409
forwardingKeepsNoEncrypt`. When the last one ends without the owner's client
(declined, or deleted), `GET /api/mail/addresses` says `keyListOwed: true`
until the client signs a list without the flag. The forwarder address must be the caller's current
one; the forwardee a Kutup person address of someone else on this server.
The instances must cover exactly the forwarder primary key's encryption
subkeys and name exactly the forwardee key's subkeys
(`400 forwardingMaterialMismatch`). `400 endToEndRequired` without
`endToEnd`; `409 forwardingExists` for the same pair; `409 forwardingLimit`
past 10 per address or 25 per account; `409 forwardingUnavailable` when the
server has no `MAIL_FORWARDING_KEYS`.

**Verification.** Every new forwarding, to a Kutup address or outside, is
unverified, and nothing is forwarded until it is verified. Creating it mails
a 6-digit code to the destination from `postmaster@` the server, in the
forwarder's language: who asks, the code, when it expires, and to ignore it
if unexpected. To a Kutup address it arrives in that inbox, and the
forwardee sees the forwarding (in `incoming`, its activation, accept and
decline) only once it is verified. Outside, the mail also carries a link
that can only refuse the forwarding (the stop page below), never start it.
The code is kept as an HMAC under a key derived from `MAIL_FORWARDING_KEYS`.
Limits (Administration → Rate limits): `forwarding_code_minutes` (15),
`forwarding_code_attempts` (5), `forwarding_code_resends` (1 a minute),
`forwarding_invites` (10 a day per forwarding) and
`forwarding_confirmations_sent` (10 a day per account, across its
forwardings); past them `429 rateLimited`. Renewing or asking again makes
a forwarding unverified and sends a new code. A forwarding's row says
`"verified"` and, for the forwarder while a code is live,
`"codeExpiresAt"` and `"codeAttemptsLeft"`.

### POST /api/mail/forwardings/:id/code

The forwarder has a new code mailed (the last one void) → the forwarding.
`409 forwardingVerified` when verified; `409 forwardingState` when rejected
or outdated; `429 rateLimited` past the limits above.

### POST /api/mail/forwardings/:id/verify

The forwarder enters `{ "code": "123456" }` → the forwarding, verified: an
outside one becomes active; an end-to-end one now waits for its forwardee to
accept. `400` when it isn't six digits (no try counted); `400 codeWrong`
with `attemptsLeft`; `409 codeVoid` after the last wrong try; `409
codeExpired` when no code is live. Verifying a verified one answers it
unchanged.

### PUT /api/mail/forwardings/:id

The forwarder renews an `outdated` or `rejected` forwarding with new
material: `{ "endToEnd": {...} }` as above → pending and unverified again,
with a new code mailed.

### PUT /api/mail/forwardings/:id/reinvite

The forwarder asks an outside destination again (pending, or declined):
pending and unverified, with a new code mailed; `429 rateLimited` past the
code limits above (deleted forwardings' codes count for the account; making
forwardings is likewise limited to 10 an hour per account, however many are
deleted). A declined one whose address is end to end again is `400
keyListRequired`: set it up anew.

### POST /api/mail/forwardings/external · /external/decline

No account: the stop page, with `{ "token" }` from the link in an outside
forwarding's code mail (in the body, never the URL); 30 requests a minute
per client (`429 rateLimited`). The first answers `{ "state",
"forwarderEmail", "forwardeeEmail" }`; decline makes it `rejected`, pending
or active, and spends the link. Nothing here starts a forwarding: only the
forwarder's code does. The link doesn't expire (it is derived from the
current `MAIL_FORWARDING_KEYS` key; rotating the key ends old links). `404`
for an unknown token.

### PUT /api/mail/forwardings/:id/pause · /resume · /conditions

The forwarder pauses an active forwarding (k is kept), resumes a paused one,
or changes `{ "match", "conditions" }`. `409 forwardingState` from the wrong
state.

### GET /api/mail/forwardings/:id/activation

The forwardee's pending activation: `{ "forwardingId", "forwarderAddress",
"forwardeeAddress", "activation", "expiresAt" }`. Their client checks it
(signed by the forwarder's key from its signed key list, for this
forwarding, unexpired) before accepting.

### POST /api/mail/forwardings/:id/accept

The forwardee keeps the forwarding key: `{ "publicKey": "<base64>",
"privateKeyEnvelope": "<base64, purpose MailAddressPrivateKey>" }`. Its
subkeys must be exactly the forwarding's. The key becomes an address key
with `forwarding: true`; the forwarding is active, and its activation is
dropped.

### POST /api/mail/forwardings/:id/decline

The forwardee declines a pending forwarding → `204`; its k and activation go
and it is `rejected` for the forwarder.

### DELETE /api/mail/forwardings/:id

Either side ends a forwarding → `204`; its k goes. The forwardee keeps the
forwarding key until they delete it.

### DELETE /api/mail/addresses/:address/forwarding-keys/:key

The forwardee deletes a forwarding key → `204`; the forwarding it serves
ends with it.

**Forwarded mail** is stored for the forwardee as the forwarder's copy with
its key packet transformed (the data packet unchanged) and carries
`forwardedFrom: "<forwarder address>"` on its message row: open it with the
forwarding key only. Spam, mail that itself came by forwarding, and mail
that came back through a loop (our `X-Kutup-Forwarded: <forwarding>-<hmac>`
marker, its HMAC checked under `MAIL_FORWARDING_KEYS`, a forged one ignored;
more than 20 `Received` header lines) aren't forwarded. Outside, a forward goes out unchanged
but for the marker on top, from a return path of ours
(`fwd-<forwarding>-<day>-<hmac>@<server>`) that a bounce comes back to: it is
checked at RCPT (a forged or older-than-21-days one is refused there) and
counted. Mail that arrived PGP-encrypted, and end-to-end Kutup mail, can't
be re-sent: skipped and counted, as is everything while the forwarder may
not send outside (the server's policy, or its sending paused); confirmation
emails wait likewise. A forwarder's new primary key makes
its end-to-end forwardings `outdated` and deletes their k.


## Custom mail domains

An account's own domains, as Proton's
([`plans/mail-custom-domains.md`](plans/mail-custom-domains.md)): added,
proved with a TXT record before any mail flows, checked as Proton checks them,
and given addresses. `404` unless the server has Mail; adds answer `403
customDomainsOff` unless an administrator allows them and the server has
Stalwart's management key and `MAIL_DKIM_KEYS`. **Auth:** Bearer JWT.

A domain: `{ "id", "name", "state", "verifyState", "mxState", "spfState",
"dkimState", "dmarcState", "awaitingApproval", "stopped", "catchAllAddressId",
"addressCount", "records", "createdAt", "checkedAt", "warnedAt" }`. The states
are Proton's numbers (`DOMAIN_STATE` 0 not verified, 1 verified, 2 warn;
`VERIFY_STATE`, `MX_STATE`, `SPF_STATE`, `DKIM_STATE`, `DMARC_STATE` as in
Proton's `Domain.ts`). `records` lists what to publish, each `{ "type", "host",
"value", "priority"? }`: `verify` (TXT `@` = `kutup-verification=…`), `mx`,
`spf` (`v=spf1 include:_spf.<server> ~all`), `dkim` (three CNAMEs,
`kutupN._domainkey` → `<domain id>.kutupN._dk.<server>.`) and `dmarc`.

A held domain whose TXT goes missing keeps working in `warn` for 14 days
(admin-settable) while its MX is still this server; with its MX gone too,
sending and delivery stop at once (`stopped`) and it ends within 72 hours.
Then its addresses are freed and its owner sees a `domainLost` security
event, as when another account proves the domain (two checks an hour apart
that find that account's code and not the holder's).

### GET /api/mail/domains

`{ "domains": [...], "used", "max", "mode": "everyone"|"approve"|"off" }`.

### POST /api/mail/domains

`{ "name" }` → `201` with the domain (or the one the account removed before,
with its code). The name is lowercased and put in its IDNA form. `400`
`invalidDomain`, `domainIsAddress`, `serverDomain` (this server's or a name
under it) or `publicSuffix`; `409` `domainLimit`, `domainDailyLimit`,
`serverDomainLimit` or `domainBlocked`.

### GET /api/mail/domains/{id}?refresh=1

The domain; `refresh=1` checks its DNS now, uncached (Proton's "Refresh
status"), at most 30 times an hour per account (`429`), and at most
`mail_domains.refreshes_at_once` across the server at a time (`429`). A
check that runs past `mail_domains.check_timeout_seconds` changes nothing
(`503` `checkTimedOut`). A check that finds the domain changed since it was
read (another check, an administrator) returns it as it is.

### DELETE /api/mail/domains/{id}

`204`: the domain is removed and its addresses freed (their keys stay for old
mail; nothing is published for them).

### PUT /api/mail/domains/{id}/catch-all

`{ "addressId": "<an active address on the domain>" | null }` → `204`. Unknown
names on the domain then reach it, at most the owner's
`mail_domains.catch_all_per_day` a day (500 at first; `452 4.2.2` after),
counted once per stored message across every backend; caught mail is never
forwarded. `403` when catch-alls are off, `409`
while the domain isn't verified.

### POST /api/mail/domains/addresses

`{ "local", "domainId" }` → `201 { "id", "address" }`: an address on one of
the caller's verified domains, compared lowercased (no `. _ -` folding there).
It has no key yet: the client adds one with `POST
/api/mail/addresses/{id}/keys`. Every address counts toward the account's
limit (10 by default), its username's included. `400 invalidAddress`, `409`
`addressLimit`, `addressTaken` or `domainNotVerified`. An address the
account held before (deleted, or freed with its domain lost) comes back with
its keys and signed key list, disabled, and `continues: true`: the client
enables it with the chain's next list (`PUT /api/mail/addresses/{id}/enable`),
so devices that saw the old chain never see it start over. After an account
reset the address starts a new chain instead. Sending from it: `POST
/api/mail/send` (and drafts) with `fromAddress: "<its id>"` in the meta.

### GET /api/admin/mail/domains · PUT /api/admin/mail/domains/settings

Administrators only. `GET`: `{ "configured", "stalwartDriftAt", "settings": { "mail_domains.mode":
"everyone"|"approve"|"off", "mail_domains.per_account", …addresses_per_account,
…on_server, …adds_per_day, …pending_days, …catch_all, …catch_all_per_day,
…grace_warn_days, …grace_stopped_hours, …refreshes_at_once, …check_timeout_seconds }, "ranges": {
"<key>": { "min", "max" } } (each numeric setting's range, what the page offers), "spf", "dkimKeys": [{ "selector",
"state", "host", "txt", "publishedSince" }], "domains": [... "blocked" ...] }`.
`stalwartDriftAt` is when Stalwart's domains or DKIM signatures outside the
custom domains (`MAIL_DOMAIN`'s own) last changed, as the reconcile saw them
(it never touches them, so a change is someone else's; it is also logged as
an error). A pending
DKIM key signs only once its TXT (`*.kutupN._dk.<server>`) has been in DNS for
a day. `PUT` takes any of the settings, each checked against its range
(`400` otherwise), applies at once and is audited (`mail.domains.settings`).
The mode `off` stops every custom domain at once: no new ones, and held ones
neither send nor receive; the reconcile then removes them from Stalwart, so
mail to them is refused at RCPT (`5xx`, the sender bounces it) rather than
deferred. Turning the mode back on restores held domains that still prove
themselves; their addresses keep working as before.

### POST /api/admin/mail/domains/{id}/approve · /deactivate

Administrators only. `approve` lets a verified domain take mail in the
`approve` mode; `deactivate` ends a domain at once (its addresses freed, its
owner told in its inbox and its security events) and blocks its name and
every name under it (`mail.<name>` too), so no account proves or takes any of
them over until the block is lifted. Both audited.

### GET /api/admin/mail/domains/blocks · DELETE /api/admin/mail/domains/blocks/{name}

Administrators only. `GET`: the blocked names, newest first, `[{ "name",
"blockedAt", "blockedBy" }]` (`blockedBy` null once that administrator's
account is gone), whether or not a domain row is left for them. `DELETE`
lifts one by its name (`204`; `404` for a name not blocked), audited
(`mail.domains.unblock`).

### GET · PUT /api/admin/users/{id}/mail-domains

Administrators only. One account's limits over the site's: `{ "maxDomains":
0–100 | null, "maxAddresses": 1–1000 | null, "catchAll": bool | null }`, `null`
keeping the site's; `GET` adds `maxDomainsRange` and `maxAddressesRange`
(`{ min, max }`, the ranges of the site settings they override), which the
`PUT` checks against.

## Mail

Mail from outside arrives through Stalwart and is encrypted to the address's
primary key on arrival (`docs/plans/mail.md`). The server keeps the readable
fields: subject, addresses, dates, size, folder and flags. Each message is
stored whole as a binary OpenPGP message that the client opens with its
address key.

### GET /api/mail/messages?folder=&before=&limit=

One folder (`inbox`, `drafts`, `sent`, `archive`, `spam` or `trash`), newest
first, at most 200 per page (default 50).

**Auth:** Bearer JWT

**Response:** `{ "messages": [{ "id", "threadId", "folder", "seen", "starred", "protection", "size", "receivedAt", "sentAt", "subject", "from": { "address", "name" }, "to": [...], "cc": [...], "replyTo": [...], "messageId", "attachmentCount" }], "next": "..." }`.
`protection` is `zero_access` (encrypted on arrival) or `end_to_end` (between
Kutup users, or arrived OpenPGP-encrypted by its sender). Pass
`next` as `before` for the next page; it is absent on the last. Instead,
`page` (from 0) pages by number, `limit` to a page (Proton's paging), and the
answer carries `total`, how many the place holds with the filters; `page` with
`before` is `400`. `400` for an unknown folder or cursor.

### GET /api/mail/messages/:id/content

The stored message: `application/octet-stream`, an OpenPGP message encrypted to
the address key. `404` unless it is the caller's.

**Auth:** Bearer JWT

### PATCH /api/mail/messages

`{ "ids": [...], "seen"?, "starred"?, "folder"? }`, 1 to 500 ids. Received mail
can go to `inbox`, `archive`, `spam` or `trash`; sent mail to `sent`,
`archive` or `trash`; drafts stay in Drafts. Moving to Trash marks read.
**Response:** `{ "updated": 3 }`, counting only the messages that changed.

### POST /api/mail/messages/batch

`{ "place", "seen"?, "folder"?, "customFolder"?, "addLabels"?, "removeLabels"?, "group"? }`:
the same change as `PATCH /api/mail/messages`, on every message of a place
(Proton's select all): a folder, `starred`, `folder:<id>` or `label:<id>`; All
mail is `400`. Only the caller's mailbox, or a shared one they are a member of.
Runs in chunks (`MAIL_BATCH_CHUNK`, 5,000 messages), each its own transaction.
**Response:** `{ "updated": 1234 }`.

### POST /api/mail/messages/delete

`{ "ids": [...] }`: deletes for good, only from Trash, Spam and Drafts (a
draft's attachments go with it), and frees their storage.
**Response:** `{ "updated": 2 }`.

### GET /api/mail/counts · GET /api/mail/threads/:id

`counts`: `[{ "folder", "unread", "total" }]`, one per folder in use plus
`starred`. `threads/:id`: the thread's messages, oldest first, as in the list.

`GET /api/mail/messages` also takes `q` (subjects and addresses) and the
folders `starred` and `all` (everything but Spam and Trash). Each message
carries `direction` (`inbound` or `outbound`), `bcc` (your sent copies
only), `inReplyTo` and `references`.

### POST /api/mail/drafts · PUT /api/mail/drafts/:id

Multipart: `meta` (JSON: `subject`, `fromName`, `to`, `cc`, `bcc` as
`[{ "address", "name" }]`, `messageId` as `…@<server name>` or `…@<the sender's domain>`, `inReplyTo`,
`references`, `attachmentCount`, `threadId`) and `body` (the message without
attachments, encrypted to your own address key; `400` with `code: keyChanged`
otherwise). **Response:** the draft, as in the list. `413` when too large or
over quota.

### Draft attachments

`POST /api/mail/drafts/:id/attachments` (multipart `part`: the MIME part as
it will be sent, encrypted to your own key, all of a draft's together at
most 25 MB) → `{ "id", "size" }`; `GET` the list; `GET` or `DELETE`
`/api/mail/drafts/:id/attachments/:attachment`.

### POST /api/mail/send

Multipart: `meta` (the draft fields, plus `draftId`, `keyPackets`: base64
key packets, `self` for your copy and one per Kutup recipient address, and
`pgp`: `[{ "recipients": [...] }]`), `data` (the shared data packet),
`pgp0`, `pgp1`, … (one per `pgp` entry: an RFC 3156 `multipart/encrypted`
message for outside recipients with OpenPGP keys, To and Cc together, each
Bcc recipient alone) and, when outside recipients without a PGP message
remain, `mime` (the message in plaintext). Each of `mime` and the PGP
messages must be From you with the same Message-ID and no Bcc header; a PGP
message must hold an encrypted OpenPGP message, and `mime` is refused when
nobody needs it. The server stores `key packet || data packet` for you
(Sent) and each Kutup recipient (Inbox), hands `mime` and each PGP message
to Stalwart, and deletes the draft. Your sent copy is `end_to_end` when no
recipient got the plaintext.

**Response:** `{ "message": {...your sent copy...}, "recipients": [{ "address", "status" }] }`,
status `delivered` (Kutup, end to end), `sent` (outside), `full` (a Kutup
user out of storage; not delivered) or `failed` (refused by Stalwart after
an earlier submission of the same send went out; the plaintext goes first,
and its refusal fails the whole send). Errors: `409` `keyChanged` with
`address` (fetch the key again), `422` `unknownRecipient` or `refused`, `429`
`sendLimit` (`MAIL_SEND_RECIPIENTS_PER_HOUR`, `…_PER_DAY`: 100 and 500 outside
recipients by default), `413` over 25 MB or quota, `503` when Stalwart is
unreachable.

With undo send on (`delaySendSeconds` in `/api/mail/settings`: 5, 10 or 20)
and a `draftId`, the send is checked at once (every error above still comes
now) and held: **202** `{ "outboxId", "deliverAt" }`. The server sends it at
`deliverAt`, also with the browser closed; until then the draft stays and
cannot change (`409`, code `sending`). A send that was going out when the
server stopped fails rather than going twice.

### GET /api/mail/outbox/:id

A held send's `state` (`pending`, `sending`, `sent`, `cancelled`, `failed`)
and `result`: `{ "recipients": [...] }` once sent, the send's error body once
failed. `404` unless it is yours.

### POST /api/mail/outbox/:id/cancel

Undo: the held send does not go; its draft stays. `204`, or `409` once it has
gone out.

### GET /api/mail/sending

Your limits on mail to outside addresses: `{ "perHour", "perDay", "sentHour",
"sentDay", "newAccount", "paused", "outsideAllowed" }`. `outsideAllowed` is
false while the server does not send outside for you (the administrators'
setting is `off`, or `admins` and you are not one); `POST /api/mail/send` then answers
`403` with `code: outsideSendingOff` for any outside recipient. `paused` is `admin`, `bounces` or `spam`
while sending outside is paused (mail between Kutup users still goes). New
accounts may send to 50 outside recipients a day in their first week
(`MAIL_NEW_ACCOUNT_RECIPIENTS_PER_DAY`, `MAIL_NEW_ACCOUNT_DAYS`), then
`MAIL_SEND_RECIPIENTS_PER_HOUR` and `…_PER_DAY`. `POST /api/mail/send` answers
`403` with `code: sendingPaused` while paused, and `429` `sendLimit` (with
`perHour`, `perDay`, `newAccount`) over a limit.

### GET · PUT /api/admin/mail/outside-sending

Administrators only. Who may send mail to addresses outside Kutup:
`{ "outsideSending": "off" | "admins" | "on" }`. A `PUT` applies at once,
without a restart, and writes `mail.outside_sending.update` to the audit log
(`payload: { from, to }`); anything else is `400`. `MAIL_OUTSIDE_SENDING`
only seeds the stored value when the server starts without one.

### GET /api/admin/mail/senders?attention= · PUT /api/admin/users/:id/mail-sending

Admin only. The list: accounts that sent outside in the last week, or have
their own limits, a pause or a flag, paused and flagged first:
`[{ "userId", "username", "sentDay", "sentWeek", "bouncesWeek",
"spamRefusedWeek", "perHour", "perDay", "pausedAt", "pausedReason",
"flaggedAt", "flagReason" }]` (counts only, never content). `attention=true`
keeps only paused and flagged ones. The update takes `{ "perHour"?, "perDay"?
(a number or null for the server's), "paused"?, "clearFlag"? }` → `204`, and is
in the audit log. An account is paused automatically after 10 bounces in a day
that are also 10 % of what it sent (flagged from 5 and 5 %), counting only
delivery reports for its own messages; a submission Stalwart refuses as spam
flags it, and three in a day pause it.

### Mail groups

Distribution lists ([`plans/mail-groups.md`](plans/mail-groups.md)): an
address whose mail every member receives in their own mailbox, stored once
(one data packet in the group's storage, one key packet per member in the
member's row) and charged to the group's own quota, never to its members.
The role addresses are system groups: they take mail from anyone, cannot be
deleted, and while none of their members can receive mail it goes to every
active administrator.

- `GET /api/mail/groups` — the caller's groups, with `myRole` and
  `myCanSendAs`.
- `GET /api/mail/accounts?address=` — `{ "userId", "username", "address" }`
  of the active account at a Kutup address with a mail key, so members are
  added by address (there is no user search). Rate-limited like user lookup.
- `GET /api/mail/groups/directory?q=` — up to 10 groups whose address or name
  starts with `q` and that take the caller's mail, for the composer's
  suggestions.
- Message rows carry `groupAddress` (the list or shared mailbox a copy came
  through) and `sentBy` (who sent a shared mailbox's message).
- `GET /api/mail/groups/:id` — `{ "group", "members": [{ "userId", "username",
  "address", "role", "canSendAs", "active" }], "goesToAdministrators" }`, for
  members and administrators.
- `PATCH /api/mail/groups/:id` — `displayName`, `description`, `postPolicy`
  (`anyone`, `local`, `members`, `managers`; role addresses stay `anyone`),
  for owners, managers and administrators.
- `PUT /api/mail/groups/:id/members` — `{ "members": [{ "userId", "role":
  "owner" | "manager" | "member", "canSendAs" }] }`, the whole list. Owners
  and administrators change anyone; managers neither add, remove nor change
  owners; a group other than a role address keeps an owner. At most 1000.
- `GET /api/mail/groups/recipients?email=` — the receivers of a group the
  caller may post to, each as `GET /api/mail/keys` answers: the browser
  encrypts a key packet per member and sends them in `keyPackets` by member
  address. `403` `notAllowed` when the group does not take the caller's
  mail. `GET /api/mail/keys` answers a group's address with `404` and `code:
  group`. `POST /api/mail/send` answers `409` `groupChanged` when a member's
  key packet is missing (look the group up again) and gives the group one
  status (`delivered` or `full`); members who get the message directly and
  the sender get it once.
- Shared mailboxes (`kind: "shared"`): one mailbox with shared read state and
  its own address key, made in a browser; each member holds a share (the
  key's secret sealed with HPKE to their account key, their Drive HPKE key
  that their key binding ties to their account id, and bound to the group
  id, the group key's fingerprint, their account and its incarnation:
  `mail_key::seal_group_key_share`; a rename keeps it,
  docs/plans/account-ids.md). `GET /api/mail/keys` answers
  a shared mailbox with its key-list chain, signed by the group's own signing
  key, which its owners and managers hold (never by the server), and WKD
  serves its key.
  Its messages are read and filed with `?group={id}` on `GET
  /api/mail/messages`, `/counts`, `/threads/:id` and `/messages/:id/content`,
  and `"group"` in the bodies of `PATCH /api/mail/messages` and `POST
  /api/mail/messages/delete` (members only; anything else is `404`).
  `POST /api/mail/send` with `fromGroup` sends as it (owners, managers and
  members with `canSendAs`; `403` `notAllowedToSendAs` otherwise): From is its
  address, `keyPackets.self` is for its key, the copy lands in its Sent with
  `sentBy`, and the sender's limits count it.
  - `GET /api/mail/groups/:id/keys` — `{ keys, signer?, signingShare? }`:
    its keys, primary first, with the caller's `share` (only one sealed to
    their current account keys), the signer in force of its key lists and,
    for an owner or manager, their share of its seed.
  - `POST /api/mail/groups/:id/keys` — `{ "key": NewGroupKey }`, a new
    primary key with a share for every member and none for anyone else
    (owners and managers). `NewGroupKey` is `{ publicKey, shares, keyList:
    { data, signature }, signer?: { publicKey, shares, handover? } }`:
    `keyList` is the next list (the keys before not primary and no longer to
    encrypt to, this one primary), signed in the browser by the signer in
    force, or by `signer` with the handover from the one in force (`shares`
    for each owner and manager). The server checks the whole chain and
    stores it; it never signs. `400 keyListInvalid` for a list the chain
    refuses (another signer, an old signer after its handover, a gap, other
    keys); `403 handoverNeeded` for a new signer without a handover from
    anyone but an administrator (who starts a new chain).
  - `PUT /api/mail/groups/:id/members` also takes `keyShares` (`[{
    "groupFingerprint", "userId", "share" }]`, every existing key for each
    joining member; `400` `sharesNeeded`) and `newKey` (required when anyone
    leaves, with a share for exactly the members who stay; `400`
    `newKeyNeeded`), and `signerShares` (`[{ "userId", "share" }]`, the
    signer in force's seed for owners and managers who lack it: joining,
    promoted, or reset since). Losing an owner or manager (removed, or no
    longer one) needs `newKey` with a new `signer` (`400 newSignerNeeded`).
    So does a group whose owner or manager was deleted or deactivated
    (`needsNewSigner: true` on the group; every publish, by members or
    rotation, without a new signer is refused, and the signer in force is
    shared with nobody new). Shares, of a key or the signer, go to active
    accounts only.
    Keys may be sealed again to a member whose shares no longer open (reset
    since: `needsKeys` in the group's detail), and to nobody else. The
    changes are checked under the group's lock, against the members they
    change. Each share must be sealed to the member's current account
    incarnation (`409` `keyChanged`; `400` `noAccountKey` for an account not
    set up yet). Browsers look each member up by
    `GET /api/users/by-id/:accountId` and check their Drive key binding
    before sealing.
- Administrators: `GET /api/admin/mail/groups`, `POST /api/admin/mail/groups`
  (`id`, a lowercase UUID the browser draws, which a shared mailbox's key
  shares are bound to (`409` `idTaken`: draw another); `name`, `displayName`, `description`, `kind: "list" | "shared"`,
  `postPolicy`, `storageQuotaBytes`, `owners`, and for a shared mailbox
  `groupKey` (a `NewGroupKey` with the first `signer`, no handover) with a
  share for each owner; `409` `nameTaken` when the name is an
  account's, a group's or reserved), `PATCH /api/admin/mail/groups/:id`
  (quota, names, policy), `DELETE /api/admin/mail/groups/:id` (not a role
  address; members keep their copies). Each change is in the audit log, by
  the group's id and members' account ids (the address is a snapshot).
- `GET /.well-known/security.txt` (RFC 9116, no authentication): `Contact:
  mailto:security@<server name>`, `Expires` a year ahead, `Preferred-Languages:
  en, tr`.

### POST /internal/mail/rcpt

Stalwart's MTA hook at the RCPT stage, outside `/api` and not routed by
nginx, and only for mail arriving on port 25. `Authorization: Bearer <MAIL_INBOUND_TOKEN>`. Accepts a recipient when
the address (any case, without a `+tag`) is a Kutup address on this server
with a primary key, on an active account with room in its pool, or a group
that takes mail from anyone, has room in its own storage and someone to
receive it; otherwise answers `{ "action": "reject", "response": { "status":
550 | 452, ... } }`. `postmaster@`, `abuse@`, `security@` and `hostmaster@`
are system groups (below); `mailer-daemon@` is refused; those five names
cannot be registered as usernames, and neither can a group's name.
`404` when mail is off.

---

## Contacts

The account's address book (`docs/plans/contacts.md`), Proton's split. Each
contact is a **summary** (canonical JSON: `uid`, `name`, `emails[{address,
label?}]`, `groups[]`, `pinnedKeys[]`) signed by the account authority, and a
**card** (the full vCard 4.0) sealed under a contacts key only the account
holds. The server verifies every summary against the account's authority key,
indexes its emails (autocomplete) and groups, and charges summary and card to
the storage pool (`413` when full).

### GET /api/contacts?offset=&limit=

The caller's contacts by name, at most 1000 per page.
**Response:** `{ "contacts": [{ "id", "summary", "signature", "card", "revision", "createdAt", "updatedAt" }], "total": 12 }`.
Clients verify `summary` with `signature` against their own authority before
using a contact.

Each contact's `revision` is its card's: a time in unix milliseconds in the
card's authenticated header, which the summary's signature binds too
(docs/plans/sealed-revisions.md); clients refuse a contact older than one they
have seen.

### POST /api/contacts

**Body:** `{ "summary": "canonical JSON", "signature": "base64", "card": "base64" }`.
**Response 201:** the contact. `400` for a summary that is not canonical, not
signed by this account, or names a group that does not exist; `409` when the
UID is already in the address book.

### PUT /api/contacts/:id

**Body:** the same plus `baseRevision` (the revision the edit started from);
the new card's revision must be above it (`400` if not). The UID cannot
change. **Response:** the contact at its new revision; `409` with
`{ "code": "revision_conflict", "revision": <stored> }` when it changed
elsewhere.

### DELETE /api/contacts/:id · POST /api/contacts/delete

Delete one, or `{ "ids": [...] }` (up to 500). Storage is released.
**Response:** `204`.

### POST /api/contacts/import

`{ "contacts": [ ...like POST... ] }`, 1 to 500, all or nothing.
**Response:** `{ "imported": 2 }`.

### GET /api/contacts/emails?q=&limit=

Addresses whose address, or any word of the contact's name, starts with `q`;
recently used first. For recipient, share and invitee pickers.
**Response:** `[{ "contactId", "name", "address", "label" }]`.

### Groups

`GET /api/contacts/groups` → `[{ "id", "name", "color", "members" }]`;
`POST /api/contacts/groups` `{ "name", "color": "#rrggbb" }` → `201`;
`PUT /api/contacts/groups/:id` (rename, recolour) → `204`;
`DELETE /api/contacts/groups/:id` → `204` (members stay; their summaries are
re-signed without it on their next edit, and readers ignore unknown ids).
Membership is the summary's `groups`, so it is signed.

---

## Calendar

Proton Calendar's model (docs/plans/calendar.md, E1): each calendar is an
OpenPGP key whose secret is locked with a passphrase; the passphrase is
sealed per member to the member's address key and signed by the owner; the
name and description are sealed to the calendar key. Events are Proton's
parts (`SealedEventV1`): signed parts in the clear, encrypted parts as data
packets, two key packets to the calendar key, every part signed by its
author's address key. The browser makes and opens all of it through the
`crypto-calendar` WASM. Every calendar a member holds is listed by the
account head's `calendars` scope (the calendar id and the member row's
`revision`); a write that adds, changes or removes one carries `head`.

### GET /api/calendar/calendars · POST /api/calendar/calendars

**Auth:** Bearer JWT

`GET` answers `{ "calendars": [CalendarView] }`, the caller's calendars:
`id`, `ownerAddress` (whose key list verifies the passphrase and metadata
signatures), `publicKey`, `fingerprint`, `lockedSecretKey`, `passphrase`
(`dataPacket`, `signature`, `keyPacket`), `addressId` (the member's address
the key packet is to), `metadata` (`keyPacket`, `dataPacket`, `signature`),
`permissions` (Proton's bits; 127 for the owner), `color`, `display`,
`revision`, `createdAt`, `updatedAt`.

`POST` makes one: `{ id, addressId, publicKey, lockedSecretKey, passphrase,
metadata, color, head }` (`createCalendar` in WASM makes the keys, the
passphrase and the metadata). `id` is a fresh UUID v4 the client draws, so
the account head naming it is made before the create; one in use is
`409 calendarExists`. The server checks the key's shape, that the locked secret is the
key's and locked, that the passphrase's key packet is to the address's
primary key and the metadata's to the calendar key. `201` with the
CalendarView; `400` when a check fails; `409 calendarLimit` at the
administrators' `calendarsPerAccount` (25 at first); `413` over the storage
quota.

### PUT /api/calendar/calendars/{id} · DELETE /api/calendar/calendars/{id}

`PUT` takes `{ metadata?, color?, display?, defaultReminders?, baseRevision,
revision, head }`: the owner's new sealed name and description, and the
member's own colour, visibility and default reminders (`{ timed, allDay }`,
lists of reminders as below, `calendarDefaultReminders` (5) each; Proton's
defaults: 15 minutes before a timed event, 15 hours before an all-day one,
on the device and by email). A calendar's view carries the member's
`defaultReminders`. `409 revision_conflict` when `baseRevision` is not the
member row's; `403` when someone else than the owner sends `metadata`.
`DELETE` (body `{ head }`) deletes the calendar and its events, owner only.

### GET /api/calendar/calendars/{id}/events?start=&end=&afterStart=&afterId=&limit=

The events that meet the half-open window `[start, end)` (RFC 3339, at most
`calendarWindowDays`, 400 at first), ordered by start then id, at most
`calendarEventsPage` (1000) a page: `{ events: [EventView], next }`. `next`
is `null` on the last page, else `{ afterStart, afterId }`, the last event's
start and id, which the client sends back for the next page (the cursor is
the client's, so an event deleted or moved meanwhile never ends or skips a
page); one of the two without the other is `400`. An EventView is `{ id,
calendarId, uid, authorAddress, event: SealedEventV1, startUtc, endUtc,
fullDay, rangeEndUtc, sequence, revision, modifiedAt, reminders }` (`reminders`:
the caller's own for it, null for their calendar's defaults); the times are what the server read from the shared signed
part, which a client checks again when it opens the event. A calendar the
caller isn't a member of is `404`. `GET …/events/{eventId}` answers one.

### POST /api/calendar/calendars/{id}/events/sync

`{ addressId, changes: [{"create": {id, event}} | {"update": {id,
baseRevision, event}} | {"delete": {id, baseRevision}}] }` (a create's `id`
is drawn by the client, a UUID v4: a create sent again with the same id and
parts answers the stored event, the id holding another is `409
eventIdTaken`), 1 to `calendarSyncBatch` (10) changes, each applied
alone (Proton's sync): `{ results: [{ status, event?, code?, error? }] }` in
the order sent. A created or changed event's signed parts must be signed by
one of the address's keys, its key packets be to the calendar key, and it
must keep its UID; `ORGANIZER` is refused (invitations come in E4).
Repeating events (E2): the shared part's `RRULE` and `EXDATE`s are Proton's
subset (`kutup_crypto::calendar_recurrence`), a `COUNT` at most
`calendarMaxCount` (49; `400 countTooLarge`). The calendar part's `EXDATE`s
remove occurrences on this calendar only: each must be an occurrence of
the series in its form (`400 exdateNotAnOccurrence`), and with the shared
ones at least one occurrence is left. The server stores the series' last
end (`rangeEndUtc`, absent for one without end) from both parts'
`EXDATE`s. A changed occurrence (`RECURRENCE-ID`) needs its series in the
calendar, the same UID with a rule (`400 parentMissing`), and its
`RECURRENCE-ID` must be one of the series' occurrences, an excluded one
included (`400 notAnOccurrence`), and its `SEQUENCE` is not lower than the
series' (`409 sequenceBehind`). An update keeps the event's `RECURRENCE-ID`
(or its absence; `400 recurrenceIdChanged`). A series deleted later leaves
its changes as single events, which can still be changed. A window lists
every event that meets it, and also those ending exactly at its start (a
series' last occurrence of no length there). `409 uidTaken`
for a UID already in the calendar, `409 eventLimit` at
`calendarEventsPerCalendar` (25,000). An update or a delete names
the event's `revision` it was made from: another one is `409 revision_conflict` (with
the stored `revision`), so a replayed or older change never overwrites a
newer one; a `SEQUENCE` lower than the stored one is `409 sequenceBehind`.
An event starts at revision 1 and each update adds one. The caller's
permissions are checked again in each change's transaction, so a member
removed mid-sync writes nothing further. Everything is charged to the
calendar owner's storage pool.

## Maps

Kutup stores no map data (docs/plans/maps.md). The administrator chooses the
providers people may use and whether map traffic goes through this server;
each person turns maps on (off by default) and chooses within that. Places
themselves are end-to-end encrypted elsewhere and drawn in the browser.

### Calendar reminders

A reminder is `{ "type": "device" | "email", "trigger": "-PT15M" }`, as
Proton's notifications: an RFC 5545 duration from the event's start, at
most 999 weeks, 6999 days, 999 hours or 9999 minutes before, each in its own
unit; a timed event's at its start or before, an all-day event's before its
day ends (`PT9H`: 09:00 that day). Readable by the server, which fires them;
never in the encrypted parts. An event sync's `create` and `update` take the
caller's own `reminders` for the event (`calendarRemindersPerEvent`, 10;
`400 invalidReminders` otherwise): on a create a list, absent for the
calendar's defaults; on an update absent keeps them, `null` goes back to the
defaults, a list replaces them. Each member's are their own.

The server keeps each member's next alarm per event and reminder (the
series expanded from both parts' `EXDATE`s; all-day ones in the zone of
`/api/calendar/settings`) and fires the due ones: a **device** reminder as a
web push to each of the member's signed-in browsers that subscribed, its
payload encrypted to the browser (RFC 8291) and only `{ eventId, startUtc }`;
an **email** reminder to the member's own Kutup address, saying only when,
with a link (an all-day event's says its date, "all day"). One later than
`calendarReminderLatenessSeconds` (60) is skipped, and the occurrences it
missed with it. The job looks every `calendarAlarmTickSeconds` (20) and
takes due alarms `calendarAlarmBatch` (200) at a time until none is due, at
most `calendarAlarmBatchPerAccount` (20) of one account's per batch, sending
`calendarAlarmSends` (16) at once. An account keeps at most
`calendarAlarmsPerAccount` (10,000) alarms; reminders past it fire nothing.
A reminder push lives at the push service until its occurrence starts (at
least the lateness), one per event (`Topic`), signed with the server's
VAPID key (the one Chat's pushes carry).

### GET /api/calendar/alarms?start=&end=&afterFire=&afterEvent=

The caller's next alarms firing in the window, by fire time,
`calendarAlarmsPage` (100) at most; the page's last `fireAt` and `eventId`
continue it. `{ alarms: [{ calendarId, eventId, action, occurrenceStart,
fireAt }] }`: the open app fires its own notifications from these.

### GET · PUT /api/calendar/settings

`{ zone }`: the IANA zone the account's calendars show in, where all-day
reminders fire (`null`: UTC). `400 unknownZone` for a zone the bundled
database doesn't know. Setting it moves the account's all-day alarms
shortly after: the job recomputes them, `calendarRecomputeBatch` (500)
events at a time (as for a change of a calendar's default reminders).

### PUT · DELETE /api/calendar/push-subscription

`{ endpoint, p256dh, auth }` from the browser's `PushSubscription`
(base64url keys): this signed-in session's browser takes reminder pushes,
one per session, ended by signing out. A browser's endpoint is the
account's once: a new session's subscription takes it over from an earlier
one (signed out, expired or not); another account signed in to the same
browser has its own. An account keeps at most
`calendarPushSubscriptionsPerAccount` (10): ended sessions' go first, then
the longest-held. A push's payload is `{ eventId, startUtc, fireAt, allDay, account }`,
`account` and its `Topic` keyed by the subscription's own secret
(base64url HMAC-SHA256 over the account or event id), so the push service
links neither two members' pushes nor one account's browsers. The push service must be on Chat's
allowlist (`400`); `404` where Web Push is off. A push service's `404` or
`410` drops the subscription. `DELETE` ends it.

### GET /api/maps

**Auth:** Bearer JWT

```json
{
  "enabled": true,
  "proxy": "off | available | enforced",
  "providers": [{
    "id": "openfreemap | openstreetmap | custom",
    "name": "OpenFreeMap",
    "kind": "vector | raster",
    "url": "https://tiles.openfreemap.org/styles/liberty",
    "proxyUrl": "/api/maps/proxy/openfreemap/styles/liberty",
    "attribution": "…"
  }],
  "preferences": { "enabled": false, "provider": null, "viaProxy": true }
}
```

`enabled: false` means the administrator turned maps off (no providers are
listed). `proxyUrl` is null when the relay is off. A vector provider's `url`
is a MapLibre style; a raster provider's is a `{z}/{x}/{y}` template.

### PUT /api/maps/preferences

**Auth:** Bearer JWT. Body: `{ enabled, provider, viaProxy, saveFolderId }`;
`provider` must be one on offer (or null). `saveFolderId` is where the Maps
app puts new lists: one of your own folders, not in the trash (`400`
otherwise), or null for My files. Returns the same shape as `GET /api/maps`.

### GET /api/maps/proxy/:provider/*path

**Auth:** Bearer JWT. The resource at that path on the provider (style,
TileJSON, tile, glyphs, sprite), fetched by this server and kept in its
shared cache; JSON is rewritten so every URL on the provider points back
here. Only offered providers while the relay is on; plain path segments
only; images, JSON and vector tiles only, at most 4 MiB. `404` for a provider
not offered or a resource it does not have, `429` above 1,200 requests a
minute per person, `502` when the provider fails (an expired cached copy is
served instead when there is one).

## Kutup Pass

A re-authentication (Kutup Pass's lock, a new password, turning 2FA off,
deleting the account, an admin reset) is a sign-in exchange with `purpose:
"reauth"` (`POST /api/auth/login/start`, above), whose answer is a one-time
grant for that action.

Vault secrets (docs/plans/pass.md, "Vault secrets"). A vault is a KeePass
file in Drive with its own key; each person may keep, per vault they can
open, that key sealed under their master key: an `AccountEnvelopeV1` with
purpose `PassVaultSecret` (6) whose payload binds the vault's file id
(`kutup_crypto::pass_vault`, vectors in
`crates/kutup-crypto/tests/vectors/pass-vault-secret-v1.json`). Kutup Pass and
`kutup sync` then open the vault with the Kutup sign-in. The server checks
only the envelope's public header.

### GET /api/pass/vault-secrets

Every one of the caller's vault secrets, as the account head's `passSecrets`
index lists them: `[{fileId, envelope, state, revision, updatedAt}]`
(`envelope` base64; `revision` the one in its header, the base of the next
keep). `state` says what has become of the vault: `open` (the caller can
open it: the only state whose key clients use), `trashed` (kept for a
restore), `unreachable` (the vault is there but not shared with the caller
now; `open` again if access comes back) or `gone` (purged). A read never
deletes one, and a failed access check fails the request; a secret goes only
when its owner forgets it (`DELETE`, or `POST …/forget` for several), since
it may be the only copy of a generated password or a key file's element.
Clients check the whole list, every state, against the head.

### PUT /api/pass/vault-secrets/:fileId

**Body:** `{envelope, baseRevision}`, the envelope canonical base64 of at
most 4608 bytes. Stores or replaces the caller's secret for that vault, on
top of the secret it was kept at (`baseRevision`, 0 for none;
docs/plans/sealed-revisions.md). `400` unless the envelope is a
`PassVaultSecret` envelope for the caller's key binding and this vault, with
a revision above `baseRevision` (at most 2^53 − 1); `404` for a vault that
does not exist, is in the trash, or the caller cannot open; `409` with
`{ "code": "revision_conflict", "revision": <stored> }` when another device
kept a key first.
**Response:** `204`.

### DELETE /api/pass/vault-secrets/:fileId

Forgets the caller's secret for the vault (the vault is untouched). Body
`{ "head": "…" }` once the account keeps a head. **Response:** `204`.

A secret goes only this way, never with its vault: a purged or unreachable
vault's secret stays in the account's `passSecrets` index ("unreachable but
listed") until the owner's client forgets it, which it does on its next Pass
write or unlock, all such secrets under one head:

### POST /api/pass/vault-secrets/forget

`{ "fileIds": ["<id>", …], "head": "…" }` (1 to 1,000). **Response:** `204`
(those there were).

The PIN lock (docs/plans/pass.md, "The PIN"): six digits per account, kept
as a bcrypt hash and checked only here. It releases no key; the server's part
is the limit of three tries per sign-in. **Auth:** Bearer JWT for all four.

### GET /api/pass/pin

`{set}`: whether the account has a PIN.

### PUT /api/pass/pin

**Body:** `{grant, pin}`. Sets or changes the PIN; `grant` is a `pass` grant
from a reauth of this session, used once. Resets the wrong-PIN count of every
sign-in. **Response:** `204`, `400` unless `pin` is six digits (checked first:
no grant is spent on a typo), `403 grantInvalid`.

### DELETE /api/pass/pin

**Body:** `{grant}`, as above. **Response:** `204` (also when there was
none), `403 grantInvalid`.

### POST /api/pass/pin/verify

**Body:** `{pin}`. **Response:** `204` when right (this sign-in's wrong-PIN
count starts again); `403 {error: "wrongPin", attemptsLeft}`; `403 {error:
"signedOut", attemptsLeft: 0}` on the third wrong PIN in a row, which ends the
caller's whole sign-in (as `POST /api/auth/logout`); `404 {error: "noPin"}`.
The count is per sign-in (the root session and the app sessions forked from
it), each try is reserved before the check so parallel tries get no more than
three, and other sign-ins neither add to it nor clear it.

Website icons for entries (docs/plans/pass.md, "Site icons"). **Auth:**
Bearer JWT.

### GET /api/pass/settings

`{siteIcons}`: whether the account's entries show their website's icon, the
same on every device: `"kutup"` (through this server; the default) or
`"off"`.

### PUT /api/pass/settings

**Body:** `{siteIcons}`. **Response:** `204`, `400` for another value.

### POST /api/pass/icon

**Body:** `{domain}`: a host name only (`accounts.example.org`; no IP
address, port, path or `localhost`). The server reads the site's home page
for its icon links, then tries `/favicon.ico`, over https to public
addresses only. **Response:** `200` with the image (`image/png`,
`image/jpeg`, `image/gif`, `image/webp` or `image/x-icon`, recognised by its
bytes; never SVG; `Cache-Control: no-store`); `400` for a name that is not a
public host name; `403` unless the account chose `"kutup"`; `404` when the
site has no usable icon; `429` past 600 a minute, or past 120 sites a
minute that the cache could not answer. Icons are kept in the server's
memory, per account, for a day (no icon: an hour), never written down; at
most 16 sites are fetched at once, and a second ask for a site being
fetched waits for it. The response carries `X-Content-Type-Options:
nosniff` and a sandboxing CSP.

---

## Photos

The Photos app's library (docs/plans/photos.md). Photos are Drive files;
their details are sealed in each file's metadata (`media`), never sent here.

### GET /api/photos/preferences

**Auth:** Bearer JWT. `{ uploadFolderId, libraryFolderIds }`: where uploads
go (one of your own folders, or null until the app makes "Photos" in My
files), and the other folders the library shows, each with its subfolders.
Folders deleted, or no longer shared with you, are left out.

### PUT /api/photos/preferences

**Auth:** Bearer JWT. Body: the same shape. `uploadFolderId` must be one of
your own folders, not in the trash; each library folder one you can open,
at most 200 (`400` otherwise). Returns what was saved.

### GET /api/photos/library · PUT /api/photos/library

Your own marks on photos (favourites, archived, hidden) as one
account-private envelope (`kutup-crypto` `photos_library`), sealed under a
subkey of the master key; the server never reads it.

- **GET** (Bearer JWT): `{ envelope, revision, envelopeDigest }`, `404`
  before the first.
- **PUT** (Bearer JWT): `{ envelope }`, the next revision: its header must
  name this account's incarnation, the stored revision plus one and the
  stored envelope's SHA-256 (revision 1 when there is none, or when the
  stored one is from before the account was reset). `200` with the stored
  record; `409` with the current record otherwise, which the client merges
  into and seals again. Up to 6 MiB.

### Albums

Albums (docs/plans/photos.md) are collections of kind `album`: keys and
epochs as a folder's, but they hold references to photos, never files or
folders (the database refuses both), sit at the top level, and are left out
of `GET /api/collections` and the trash. Each item is a file and its key
sealed under the album key (Drive envelope purpose 12: object = file,
parent = album, epoch = album epoch, revision = file key generation).

- `GET /api/albums`: your albums (`{ id, ownerUserId, nameEnvelope,
  ownerKeyEnvelope, keyEpoch, nameRevision, epochStatement,
  epochStatementHash, itemCount, createdAt, updatedAt }`).
- `POST /api/albums`: a new album, with the body of `POST /api/collections`
  and no parent. Rename it with `PUT /api/collections/:id`.
- `DELETE /api/albums/:id`: the album goes; its photos stay.
- `GET /api/albums/:id/items`: `[{ file, fileKeyEnvelope, keyGeneration,
  albumEpoch, addedBy, addedAt }]`, `file` as in a folder listing; photos in
  the trash are left out.
- `POST /api/albums/:id/items`: `{ items: [{ fileId, fileKeyEnvelope,
  keyGeneration }] }`, up to 500; each one of your own files, sealed at its
  current generation and the album's current epoch (`409` when a key
  changed). Adding again re-seals.
- `POST /api/albums/:id/items/remove`: `{ fileIds }`.

- `GET /api/albums/:id/keys` (owner): every item's sealed key, those in
  the trash too, for a rotation.
- `DELETE /api/albums/:id/membership` (member): leave; the photos you put in
  leave with you.

Albums are shared as folders are (`POST /api/collections/:id/share`, with
`canUpload` meaning "can add photos"; `GET /api/collections/:id/access`).
`GET /api/albums` lists albums shared with you too. Members read the items
and open the photos (their content, versions and thumbnails); members who may
add put in their own photos and take out only those. Removing someone is a
rotation (`POST /api/collections/:id/rotate`) whose body also carries
`albumItems: [{ fileId, fileKeyEnvelope }]`: every item re-sealed under the
new album key at the new epoch, or nothing changes (`409`).

### Live-location streams

A live location's stream on the sharer's server (docs/chat-protocol.md
"Live locations"). The server keeps only the latest sealed update and
deletes the stream at its end.

- `POST /api/live-locations` (Bearer JWT):
  `{ streamId: <16 bytes hex>, writeSecret: <32 bytes b64>,
  readCapability: <32 bytes b64>, expiresAtMs }`, at most 8 hours ahead.
  `201`; `409` for a taken id; `429` above 60 a hour per person.
- `PUT /api/live-locations/:streamId` (Bearer JWT, `x-kutup-live-write`):
  `{ update: <88-byte LiveLocationUpdateV1 b64> }`. `204`; `404` for a wrong
  secret or an ended stream; `409` when the counter is not above the stored
  one; `429` within 3 s of the last write.
- `GET /api/live-locations/:streamId[?server=]` (Bearer JWT,
  `x-kutup-live-read`): `{ update, updatedAtMs, expiresAtMs }`; with
  `server`, read from the sharer's server over signed federation
  (`GET /api/fed/chat/live-locations/:streamId`). `404` for a wrong
  capability or an ended stream; `429` above 600 reads a minute per person.
- `DELETE /api/live-locations/:streamId` (Bearer JWT, `x-kutup-live-write`):
  `204`.

---

## Files

**Write rights.** Reading a file needs the folder's owner or any share on it.
Changing it — uploading into the folder, saving a version, naming or keeping
one, storing a whiteboard asset or thumbnail, claiming a note's seed, or
sending edits over the collab socket — needs the owner or a share with
`canUpload` ("can add and edit"). Everything a recipient stores is charged to
them and counts against the share's `uploadQuotaBytes`.

**Quota.** Every writer checks the same headroom: quota − stored − the full
declared length of the user's open tus uploads (an upload reserves its whole
length until it is finalised).

**Revisions and the block format** (docs/plans/drive-block-format.md §3).
Each stored content of a file — its first upload and every version — is a
revision with its own id, stored at `files/{fileId}/revisions/{revisionId}`.
An upload in the block format (suite 2) names its revision with
`revisionId`: the client chooses it before it seals, and the blob's header
binds it, so the server checks the two agree. It also checks the blob's
structure from its length and trailer (the manifest length fits the block
count, and the count the length); it can't check the AEAD. An upload without
`revisionId` is the streaming format (suite 1) and gets a new revision id. A
revision id already used is `409 revisionTaken`.

**Ranges.** Every content route (download, original, version, public link,
Chat media and the federated reads) takes one `Range: bytes=a-b`, `a-` or
`-k` and answers `206` with `Content-Range`, or `416` with
`Content-Range: bytes */<length>` for a range past the end. Several ranges, or
a malformed one, are answered whole (`200`). The ETag is the revision id (an
attachment id for Chat media) and `If-Range` is honoured: a range of other
content gets the whole new content. One answer carries at most
`driveStreamResponseMaxBytes`; a longer range is answered in part, as its
`Content-Range` says: its first part, or a suffix's last.

**Limits** are settings an administrator changes, for the site or for one
account (docs/plans/settings-registry.md): the largest upload
(`driveUploadMaxBytes`, 10 GiB) and version (`driveVersionMaxBytes`, 2 GiB)
for the uploading account, counted as the body arrives (`413` past them),
and the streaming settings `GET /api/drive/limits` lists.

### GET /api/drive/limits

The upload and streaming limits a client works with, as they are for this
account: its own where administrators set them, else the site's.
`streamResponseMaxBytes` is the site's always (a transport parameter).

**Auth:** Bearer JWT

```json
{
  "uploadMaxBytes": 10737418240,
  "versionMaxBytes": 2147483648,
  "streamMaxBytes": 10737418240,
  "streamCacheBlocks": 3,
  "streamReadaheadBlocks": 1,
  "streamMaxConcurrent": 3,
  "streamResponseMaxBytes": 5242880,
  "streamBlobFallbackMaxBytes": 1073741824
}
```

### POST /api/files/upload

Upload an encrypted file to a collection. Multipart form.

**Auth:** Bearer JWT

**Form fields:**

| Field | Type | Description |
|-------|------|-------------|
| `fileId` | string (canonical UUID) | Client-generated before envelope construction |
| `collectionId` | string (UUID) | Target collection |
| `metadataEnvelope` | string (canonical base64) | `DriveEnvelopeV1` metadata record under the file key, bound to the file (object = parent = file), key generation 1 and revision 1 |
| `fileKeyEnvelope` | string (canonical base64) | `DriveEnvelopeV1` file-key record under the collection key, bound to file, collection, the collection's current epoch and key generation 1 (the revision slot) |
| `nameHash` | string | The name's hash in the folder ("Names in a folder"); required, checked before anything is stored |
| `contentHash` | string (optional) | The content's hash in the folder, when known before the upload |
| `revisionId` | string (canonical UUID, optional) | The block-format blob's revision (see "Revisions and the block format") |
| `file` | binary | Complete typed Drive file blob (`application/octet-stream`) |

The server obtains the current collection epoch itself and rejects malformed,
noncanonical, relocated, stale-epoch, wrong-purpose, or wrong-revision
envelopes. It also validates that the blob's authenticated-format header binds
the same file and key generation 1 before storage (the blob names no folder:
docs/plans/drive-move.md). It never accepts a
server-generated replacement for `fileId`. A `fileId` already used by a
stored file or an open upload is refused with `409` and nothing is written —
a retry cannot overwrite what an earlier attempt stored.

**Response:** `201 Created`
```json
{
  "id": "<same client-generated uuid>"
}
```

---

### GET /api/collections/:id/files

List files in a collection.

**Auth:** Bearer JWT

**Response:** Array of file objects:
```json
[
  {
    "id": "<uuid>",
    "collectionId": "<uuid>",
    "uploaderUserId": "<uuid>",
    "metadataEnvelope": "<DriveEnvelopeV1 base64>",
    "fileKeyEnvelope": "<DriveEnvelopeV1 base64>",
    "keyEpoch": 1,
    "keyGeneration": 1,
    "metadataRevision": 1,
    "encryptedSizeBytes": 4096,
    "createdAt": "2026-03-14T12:00:00Z",
    "updatedAt": "2026-03-14T12:00:00Z",
    "thumbnails": { "sm": "2026-03-14T12:00:05Z", "smKeyGeneration": 1 },
    "thumbnailStale": false,
    "originalKeyGeneration": 1,
    "contentKeyGeneration": 1
  }
]
```

`keyEpoch` is the collection epoch the file key is wrapped at; `keyGeneration`
counts the file's own keys (see "Moving" and `rekey` below).

`thumbnails` has the store time of each thumbnail variant that exists (`sm`,
`lg`; absent keys mean none). `thumbnailStale` is true when a stored thumbnail
was drawn from something other than the file's latest version, so a client
with write access should redraw it (see "Thumbnails" below).

`encryptedSizeBytes` is the size of the ciphertext blob on disk: a 32-byte
typed Drive header, a 24-byte secretstream header, and at least one frame with
a 17-byte authentication/tag overhead.

---

### GET /api/drive/files

Every file in the folders the account owns or has been given (not albums,
not the trash, not folders on other servers), newest first, in one request:
the rows of `GET /api/collections/:id/files` for all of them. The Office
home lists documents across all folders with it instead of one request per
folder.

**Auth:** Bearer JWT

---

### PUT /api/files/:id

Replace only the authenticated metadata envelope, sealed at the file's current
key generation. The request must advance the stored revision by exactly one;
gaps, rollback, replay, a wrong file binding, and a stale key generation
return `409` or `400` without changing the row.

```json
{
  "metadataEnvelope": "<DriveEnvelopeV1 base64>",
  "metadataRevision": 2,
  "nameHash": "<64 lowercase hex>"
}
```

`nameHash` is the new name's hash in the file's folder; a name another item
there holds is `409 name_taken`. Absent, the stored hash stays (the metadata
changed, not the name). Someone renaming a file shared by itself, without
the folder's key, sends a random hash (docs/plans/drive-unique-names.md).

---

### GET /api/files/:id/download

Download the encrypted content of a file.

**Auth:** Bearer JWT

**Response:** Raw binary (`application/octet-stream`) — the encrypted file
bytes as the file is now: its latest `kind = file` version when it has one
(the same sealed format as the upload), otherwise the original upload.
Public links and federated reads serve the same. The `X-Kutup-Version` header
names what was served: the version id, or `original` for the upload. A client
that saves its edit with `basedOn` passes it on (see
`POST /api/files/:fileId/versions`). The ETag is the content's revision id,
and one `Range` is served (see "Ranges").

---

### GET /api/files/:id/original

Download the encrypted original upload, while it is kept (retention prunes
it once versions cover it): the base of an office editing session that began
before the file's first saved version (docs/onlyoffice.md, "Collaboration
sessions").

**Auth:** Bearer JWT (the same access as download)

**Response:** Raw binary (`application/octet-stream`); `404` for no such
file or a pruned original.

---

### DELETE /api/files/:id

Move a file to the trash (soft delete). The file disappears from every normal endpoint but keeps counting against quota; restore or purge it via the Trash endpoints. Permanent deletion happens from the trash — explicitly, or automatically after `TRASH_RETENTION_DAYS` (default 30).

**Auth:** Bearer JWT (collection owner, or the uploader holding a `canDelete` share)

**Response:** `204 No Content`.

---

## Names in a folder

docs/plans/drive-unique-names.md. A name is unique among a folder's files
and subfolders together, and among an owner's top-level folders (albums
aside), compared without letter case or Unicode composition. The server
never reads a name: clients send its hash, `HMAC-SHA256(hash key, "name" ‖
0 ‖ canonical name)` (`kutup_crypto::drive_names`), under the folder's hash
key (from its first key) or, at the top level, the account's. A file's
content hash, `HMAC-SHA256(hash key, "content" ‖ 0 ‖ SHA-256 of the
plaintext)`, lets a client tell that the file it is about to upload is
already there.

- Hashes are 64 lowercase hex digits; anything else is `400`. Listings
  return `nameHash` (files and folders) and `contentHash` (files) when
  known.
- Every write that names something or puts it somewhere requires `nameHash`
  (`400` with code `nameNeeded` without it):
  `POST /api/collections`, `PUT /api/collections/:id`,
  `POST /api/collections/:id/move`, `POST /api/files/upload`, tus
  `POST /api/uploads` (`nameHash` in `Upload-Metadata`; checked again when
  the upload finishes), `PUT /api/files/:id`, `POST /api/files/:id/move`
  (with `contentHash` under the destination's key, if known; otherwise the
  content hash is dropped), and uploads from another server
  (`nameHash` multipart field). `PUT /api/files/:id` may leave it out when
  the name does not change.
- A taken name is `409` with what holds it:

  ```json
  { "error": "an item with this name is already here", "code": "name_taken",
    "holder": { "kind": "file", "id": "<uuid>", "contentHash": "<hex or null>" } }
  ```
- A file or folder restored from the trash after its name was taken is
  `409 name_taken`; restore it under a new name in the same request
  (`POST /api/trash/:id/restore`).
- A new version (`POST /api/files/:id/versions`) clears the content hash;
  the client records the new one. A version uploaded over tus (below)
  carries its content hash and lands with it.

### POST /api/uploads with `versionOf` — a new version over tus

Replace on an upload clash, and a CLI sync push of an edited file, upload
the new content as a version of the file there, as Proton Drive's revisions:
resumable (tus `HEAD`/`PATCH` as for a new file) and of any size. The
`Upload-Metadata` holds `versionOf` (the file id), `metadataEnvelope` and
`metadataRevision` (the file's next metadata revision: its new size and
`sha256`), and optionally `contentHash` (the new content's hash in its
folder) and `basedOn` (a version id or `original`, as a multipart save). The
blob is sealed for the file at its current key generation. In the block
format `revisionId` names the blob's revision, which becomes the version's
id; its structure is checked when the last part lands. Answers `201` with
`{ "fileId", "versionId" }` (the upload's id is the version's). At most
`driveVersionMaxBytes` (`413`).

Checked when the upload starts, so a conflict fails before the content is
sent, and again when its last part lands: the caller may write the file
(`403`), the file is live (`404`), it still holds `basedOn`
(`409 version_conflict`), its key has not changed (`409`), the metadata is
its next revision (`409 revision_conflict`), and the upload fits the
uploader's storage and share limits (`413`). One open upload per file:
another is `409 versionUploading`, with `idleSeconds` since its last part,
and its `uploadId` when the caller uploads it (`yours: true`) or owns the
folder (`yours: false`): either may cancel it (tus `DELETE`), so nobody can
hold the file's slot. A client cancels its own idle one (left by a crash)
and starts again, and waits for an active one (a save running on another
device), never merging over it. Each part re-checks that its writer may
still write the file: one whose access was taken away loses the upload.
Purging the file drops its open version upload. The last part stores the version, the
file's new metadata and its content hash in one transaction, charged to the
uploader as a multipart version is; refused there, the upload is discarded
at once. An abandoned one is reaped like any tus upload, and reserves its
length until then. Folders on other servers take versions by multipart only
(`POST BASE/versions`, at most 2 GiB).

### PUT /api/files/:id/content-hash

`{ "contentHash": "<hex>" }` — what the file's content is recognised by in
its folder, recorded once an upload has read the whole file. Whoever can
write the folder (or edit the file shared by itself). `204`.

### POST /api/collections/:id/available-hashes

`{ "hashes": ["<hex>", …] }` (1 to 10) → `{ "available": ["<hex>", …] }`:
the ones no file or folder there holds (items in the trash hold none), so a
client finds the first free `name (n)` without listing the folder again (as
Proton Drive's `checkAvailableHashes`). Whoever can write the folder;
`RATE_LIMIT_AVAILABLE_HASHES_PER_MIN` (default 120) per account, then
`429 rateLimited`.

### POST /api/drive/top-level-available-hashes

The same among the account's own top-level folders.

---

## Folder access and keys

Who can open a folder and taking that access away
(docs/plans/drive-share-revocation.md). A folder's keys form a chain of
epochs; every removal rotates to the next.

### GET /api/collections/:id/epochs

The folder's key history, oldest first:
`[{ epoch, epochStatement, epochStatementHash, previousKeyEnvelope? }]`.
`previousKeyEnvelope` (absent for epoch 1) is the previous epoch's key sealed
under this epoch's (purpose 8). Clients unlock older keys from the current one
with `collection_keyring::unlock`, which verifies the owner-signed chain and
every key commitment. **Auth:** owner (also for a trashed folder) or member.
Public links: `GET /api/share/:token/epochs` (anonymous); federated
recipients: `GET /api/drive/federation/shares/:shareId/epochs`.

### GET /api/collections/:id/access

Owner only. `{ keyEpoch, epochStatementHash, members: [{ userId, account,
accountIncarnationId, drivePublicKey, driveSigningPublicKey, canUpload, canDelete, uploadQuotaBytes,
createdAt }], publicLinks: [{ id, token, ownerLinkKeyEnvelope, expiresAt?,
createdAt }], federatedShares: [{ id, recipientUsername, recipientServer,
recipientIncarnationId, canUpload, canDelete, uploadQuotaBytes, createdAt }] }`.
Every link carries `ownerLinkKeyEnvelope`, so a rotation re-wraps it.

### POST /api/collections/:id/rotate

Owner only; all or nothing. **Body:** `{ fromEpoch, epochStatement,
ownerKeyEnvelope, previousKeyEnvelope, nameEnvelope, members: [{ userId,
namedShareEnvelope }], publicLinks: [{ id, collectionKeyEnvelope }],
federatedShares: [{ id, namedShareEnvelope }], removed: { members: [userId],
publicLinks: [id], federatedShares: [id] } }`. The statement must chain from
the current one under the owner's authority; the owner key, previous-key and
name (next name revision) envelopes must be at `fromEpoch + 1`; every kept
member's named share must be sealed at the new epoch to that exact account
(federated: the same account incarnation as before), every kept link
re-wrapped. Kept plus removed must be exactly the current access, else `409`
(also when `fromEpoch` is stale). **Response:** `{ keyEpoch,
epochStatementHash }`.

### POST /api/files/:id/rekey

Give a file a new key before writing to it (or moving it) when its folder has
rotated past it. **Body:** `{ fromGeneration, fileKeyEnvelope,
metadataEnvelope, previousKeyEnvelope }` — a new random file key of generation
`fromGeneration + 1` wrapped at the folder's current epoch, the metadata (same
revision) sealed under it, and the key being left sealed under it
(`PreviousFileKey`, purpose 10). **Response:** `{ keyEpoch, keyGeneration }`.
`409` if another editor re-keyed first or the file is already current.
**Auth:** write access. Open collaboration sockets on the file are closed so
peers reconnect under the new key.

**New content only under the current key.** Versions, assets, thumbnails,
renames and collaborative edits must be sealed at the file's current key
generation (`409 file key changed` otherwise), and are refused for a file
whose key is wrapped at an older epoch than its folder's (`409 file needs a
re-key`). An upload sealed at an older folder epoch gets `409 folder key
changed` (reload the folder and retry).

**Listing fields.** File rows carry `keyGeneration`, `originalKeyGeneration`
(the upload's), `contentKeyGeneration` (that of what `/download` serves),
`keyHistory` (`[{ generation, previousKeyEnvelope }]`, generations 2 to
`keyGeneration` in order, each sealing the one before) and
`thumbnails.{sm,lg}KeyGeneration`; version rows carry `keyGeneration`; an
asset download carries `X-Kutup-Key-Generation`. Each object opens with the
file key of its own generation, reached from the current key through
`keyHistory` wherever the file is.

### Sharing a single file

A file can be shared by itself with someone on this server, like Proton Drive
and CryptPad (docs/plans/drive-file-sharing.md). They get the file's own key in
a `FileShareEnvelopeV1` (magic `KUTPFS1`), bound to the file id, the file key
generation, both accounts and both incarnations, and signed with the owner's
Drive key. They never get the folder's key. Only the folder's owner shares.
A file share lets its recipient open, download, list versions and join the
collaboration socket (read-only for view). With edit, the recipient can also
save versions, thumbnails and live edits, but only while the share opens the
file's current key generation and that key is wrapped at the folder's current
epoch. Otherwise `403`, and the share waits for the owner. Rename, move,
delete and share stay with the owner. A file in the trash is out of reach
through its shares.

- **`POST /api/files/:id/share`**: owner only. **Body:** `{ recipientUserId,
  shareEnvelope, canEdit }`. The envelope must be at the file's current
  generation, sealed to that exact account (`400` otherwise). Sharing again
  replaces the envelope and permission. `204`.
- **`GET /api/files/:id/access`**: owner only. `{ keyGeneration, members:
  [{ userId, account, accountIncarnationId, drivePublicKey,
  driveSigningPublicKey, canEdit, keyGeneration, createdAt }] }`. A member
  whose `keyGeneration` is below the file's is waiting to be re-sealed.
- **`POST /api/files/:id/rotate`**: remove people, owner only, all or
  nothing. **Body:** `{ fromGeneration, fileKeyEnvelope, metadataEnvelope,
  previousKeyEnvelope, members: [{ userId, shareEnvelope }], removed: [userId]
  }`. It uses the same new-generation envelopes as `rekey`, wrapped at the
  folder's current epoch, plus an envelope at the new generation for everyone
  who stays. Kept plus removed must be exactly the file's people and `removed`
  must not be empty, else `409`. Collaboration sockets on the file are
  closed. **Response:** the new `FileAccess`.
- **`PUT /api/files/:id/shares`**: owner only. **Body:** `{ members: [{
  userId, shareEnvelope }] }`. It re-seals shares left at an older generation
  (someone else re-keyed the file) at the current one. `204`.
- **`GET /api/file-shares/pending`**: the caller's files with shares to bring
  up to date, `[{ fileId, collectionId }]`. These are shares below the file's
  generation, or a file wrapped below its folder's epoch. The owner's Drive
  re-keys the file if needed and re-seals.
- **`GET /api/shared-files`**: files shared with the caller. `[{ file:
  FileRow, shareEnvelope, canEdit, keyGeneration, folderKeyCurrent, server,
  ownerUserId, ownerAccount, ownerIncarnationId, ownerSigningPublicKey,
  sharedAt }]`. The owner and the sharer are accounts on `server`, by their
  user ids (as the envelope names them); `ownerAccount` and `sharerAccount`
  are their addresses now, shown only. With `keyGeneration` below `file.keyGeneration`, the current
  metadata cannot be opened yet. With `folderKeyCurrent: false`, the file
  opens but edits wait.

In a folder listing, a file shared by itself carries `shared: true`, for the
folder's owner only.

**Editors.** Someone with edit access may rename the file (at its current
key). If the owner turns on "Editors can share"
(`PUT /api/files/:id/sharing`, body `{ editorsCanShare }`, owner only, off by
default), an editor may also share it with new people. They sign the
envelope themselves, may not change anyone who already has it (`409`), and
may read `GET /api/files/:id/access`. Only the owner removes people (the
rotation takes the folder's key). Envelopes the owner re-seals become the
owner's.

- `GET /api/shared-files` rows also carry the envelope's sender
  (`sharerUserId`, `sharerAccount`, `sharerIncarnationId`,
  `sharerSigningPublicKey`), which is
  the owner or an editor, plus `editorsCanShare`. A share left at an older
  generation carries `metadataAtShare: { envelope, revision }`: the file's
  metadata as it was then, under the key the share opens.
- `GET /api/files/:id/access` also returns `editorsCanShare`.
- **Public link to one file:** `POST /api/share` with `shareType: "file"`,
  `targetId` = the file, `collectionKeyEnvelope` = the file's current key
  sealed under the link key (Drive envelope purpose 11,
  `public_link_file_key`: object = file, parent = owner, epoch = key
  generation), `id` and `ownerLinkKeyEnvelope` as for folder links. Owner
  only.
  - Anonymous reads through the token: `GET /api/share/:token` (with
    `file`, the file's record) and `GET /api/share/:token/download/:fileId`
    (that file only).
  - The file's links appear in its `access` (`publicLinks`, for the owner).
  - Removing a link is a rotation (`removedLinks`), and a rotation re-wraps
    every kept link (`publicLinks: [{ id, keyEnvelope }]`); kept plus
    removed links must be exactly the current ones. `PUT /api/files/:id/shares`
    re-wraps links left behind, and `pending` lists files whose links wait.
- **`GET /api/share/:token/state/:fileId`** (anonymous, folder or file
  links): the latest saved Yjs state of a note or place list, sealed under
  the file key of the generation in `X-Kutup-Key-Generation` (`404` when it
  has none). Their edits are not whole-file versions, so a link's page turns
  the state back into the file.
- **`GET /api/shared-by-me`**: `[{ collectionId, fileId?, people,
  otherServers, links }]`. These are your folders shared with people or by
  link, and your files shared by themselves, with counts.

### POST /api/files/:id/move

Move a file to another folder of the same owner (docs/plans/drive-move.md).
**Body:** `{ fromCollectionId, toCollectionId, toKeyEpoch, fileKeyEnvelope,
nameHash, contentHash? }` — the name's (and, if known, the content's) hash
in the destination ("Names in a folder"; a taken name is `409 name_taken`),
and the file's current key sealed under the destination's key at its current
epoch `toKeyEpoch`, with the file's key generation. Nothing else changes: the
content, metadata, versions, thumbnails and assets are bound to the file, not
the folder. **Response:** `{ collectionId, keyEpoch }`. **Auth:** write access
to both folders. `400` same folder, another owner's folder (copy instead) or
an invalid envelope; `403` no write access; `409 the file moved`
(`fromCollectionId` is stale), `409 file needs a re-key` (re-key it in its
folder first, so no one removed from that folder can follow it), `409 folder
key changed` (the destination rotated; reload). Open collaboration sockets on
the file are closed.

### POST /api/collections/:id/move

Put a folder under another of the owner's folders, or at the top level.
**Body:** `{ parentCollectionId: string | null, nameHash }` — its name's hash
in the new place (`409 name_taken` when held). A folder's key is sealed to
its owner, not its parent, so nothing encrypted changes. **Response:** `204`.
**Auth:** owner (`404` otherwise). `400` into itself or a folder inside it, or
under a folder the caller does not own.

---

## Trash

Trash is **owner-scoped**: an item lives in the trash of the user who owns the collection it belongs to (a share recipient's delete lands in the owner's trash — the Google Drive model). Every entry is a *trash root*: a deleted file, or a deleted folder carrying its whole subtree. A background sweeper purges roots older than `TRASH_RETENTION_DAYS` (default 30; `0` disables the sweeper). Federated Drive deletes (`DELETE /api/fed/drive/files/:fileId`) remain permanent — there is no cross-server trash.

### GET /api/trash

List the caller's trash roots, newest first. Folder rows carry the complete
authenticated owner collection record. File rows additionally carry the parent
collection's owner-key envelope and signed epoch record so the metadata chain
can be verified even when the collection is absent from the live listing.
A folder's `parentCollectionId` is where a restore puts it: its parent while
that folder is live, otherwise `null` (the top level), so a client hashes a
new name for the right place.

**Auth:** Bearer JWT

**Response:** `200 OK`
```json
{
  "folders": [
    {
      "id": "<uuid>",
      "ownerUserId": "<uuid>",
      "nameEnvelope": "<DriveEnvelopeV1 base64>",
      "ownerKeyEnvelope": "<DriveEnvelopeV1 base64>",
      "keyEpoch": 1,
      "nameRevision": 1,
      "epochStatement": "<CollectionEpochStatementV1 base64>",
      "epochStatementHash": "<lowercase SHA-256 hex>",
      "color": "blue",
      "parentCollectionId": "<uuid or null>",
      "items": 12,
      "deletedAt": "2026-06-11T11:22:33Z"
    }
  ],
  "files": [
    {
      "id": "<uuid>",
      "collectionId": "<uuid>",
      "metadataEnvelope": "<DriveEnvelopeV1 base64>",
      "fileKeyEnvelope": "<DriveEnvelopeV1 base64>",
      "keyEpoch": 1,
      "metadataRevision": 1,
      "collectionOwnerUserId": "<uuid>",
      "collectionOwnerKeyEnvelope": "<DriveEnvelopeV1 base64>",
      "collectionKeyEpoch": 1,
      "collectionEpochStatement": "<CollectionEpochStatementV1 base64>",
      "collectionEpochStatementHash": "<lowercase SHA-256 hex>",
      "deletedAt": "2026-06-11T11:22:33Z",
      "thumbnails": { "sm": "2026-06-11T11:20:00Z", "smKeyGeneration": 1 }
    }
  ]
}
```

`items` is the number of files trashed together with the folder (its subtree).
A file row's `thumbnails` are as in a folder listing: while a file is in its
owner's trash on its own, its owner may still read them
(`GET /api/files/:id/thumbnails/:variant`), as Photos' trash shows them.

### POST /api/trash/:id/restore

Put a trash root back where it was. Restoring a folder restores its whole subtree; if its original parent is gone or still trashed, it comes back at the top level. Restoring a file whose folder is still in the trash returns `409 Conflict` (restore the folder instead).

Its name must be free where it lands ("Names in a folder"): a taken one is `409 name_taken` (with what holds it), and a folder that comes back at the top level, where its hash never applied, is `409` with code `nameNeeded`. Either way, restore it again with a name for that place:

```json
{
  "nameHash": "<64 lowercase hex>",
  "nameEnvelope": "<DriveEnvelopeV1 base64>", "nameRevision": 3,
  "metadataEnvelope": "<DriveEnvelopeV1 base64>", "metadataRevision": 4
}
```

`nameHash` alone keeps the name (a folder at the top level). A new name comes with its envelope at exactly the next revision: `nameEnvelope`/`nameRevision` for a folder, `metadataEnvelope`/`metadataRevision` for a file. The body is optional.

**Auth:** Bearer JWT (owner only)

**Response:** `200 OK` `{"message": "restored"}` · `409 Conflict` when the parent folder is still trashed, the name is taken or a name is needed.

### DELETE /api/trash/:id

Permanently purge one trash root: DB rows, S3 blobs (including version/asset children), and the held quota. Irreversible.

**Auth:** Bearer JWT (owner only)

**Response:** `204 No Content`.

### DELETE /api/trash

Empty the caller's whole trash. Irreversible.

**Auth:** Bearer JWT

**Response:** `204 No Content`.

---

## Public Shares

### POST /api/share/

Create a public share link for one collection. **Body** also carries the
link's client-chosen `id` (canonical UUID) and `ownerLinkKeyEnvelope`: the
link key sealed for the owner under their master key (`DriveEnvelopeV1`
purpose 9, object = link id, parent = owner, epoch 1), so the owner can list
and copy the link and keep it working across folder-key rotations. The link key used to open the
typed collection-key envelope lives only in the URL fragment; the server never
sees it.

**Auth:** Bearer JWT

**Request body:**
```json
{
  "shareType": "collection",
  "targetId": "<uuid>",
  "collectionKeyEnvelope": "<DriveEnvelopeV1 base64>",
  "expiresInHours": 48
}
```

V1 accepts only `shareType: "collection"`. `expiresInHours` is optional; omit
or send `null` for no expiry; otherwise 1 to 87,840 (ten years), else `400`.
A link's folder in the trash makes the link answer `404` until it is
restored. `collectionKeyEnvelope` uses the public-link
purpose and binds the target collection, owner and current collection epoch.
Malformed, relocated, stale-epoch or wrong-purpose envelopes are rejected
before storage.

**Response:** `201 Created`
```json
{
  "id": "<uuid>",
  "token": "<random-token>"
}
```

The client builds the share URL as
`<SERVER_URL>/s/<token>#key=<base64-link-key>`; the server returns only the
token.

---

### GET /api/share/:token

Get metadata for a public share. The wrapped collection key is included; the link key needed to unwrap it lives only in the URL fragment held by the recipient.

**Auth:** None

**Response:**
```json
{
  "id": "<uuid>",
  "shareType": "collection",
  "targetId": "<uuid>",
  "collectionKeyEnvelope": "<DriveEnvelopeV1 base64>",
  "collectionKeyEpoch": 1,
  "ownerUserId": "<uuid>",
  "ownerAccount": "alice@example.org",
  "expiresAt": "2026-04-01T00:00:00Z",
  "collectionKind": "album",
  "nameEnvelope": "<DriveEnvelopeV1 base64>",
  "nameRevision": 1
}
```

`expiresAt` is `null` when the share has no expiry. Returns `410 Gone` if the share has expired.
`ownerAccount` is the address of the account that made the link: every public
page says who shared it, so a link cannot pass its content off as the server's.
`collectionKind`, `nameEnvelope` and `nameRevision` are present for collection shares; the name
opens under the collection key (album links show the album's name).

---

### GET /api/share/:token/album

The items of an album reached by a public link: each photo's file record, its
thumbnails, and its file key sealed under the album key (Drive envelope
purpose 12, `AlbumFileKey`).

**Auth:** None (the token is the capability)

**Response:**
```json
[
  {
    "file": { "id": "<uuid>", "collectionId": "<uuid>", "metadataEnvelope": "…", "fileKeyEnvelope": "…", "keyEpoch": 1, "keyGeneration": 1, "metadataRevision": 1, "encryptedSizeBytes": 4096, "createdAt": "…", "originalKeyGeneration": 1, "contentKeyGeneration": 1 },
    "thumbnails": [{ "variant": "sm", "keyGeneration": 1, "…": "…" }],
    "fileKeyEnvelope": "<DriveEnvelopeV1 base64>",
    "keyGeneration": 1,
    "albumEpoch": 1
  }
]
```

Returns `404` for an unknown token or a link that is not to an album, `410` if it has expired.
Trashed photos are left out.

---

### GET /api/share/:token/thumbnails/:fileId/:variant

A thumbnail (`sm` or `lg`) of a file the link reaches (for an album, one of
its items). Streams the encrypted thumbnail; the client opens it with the
file key. `404` when the file is not reached or has no such thumbnail.

**Auth:** None

---

### GET /api/share/:token/files

List files in a public share.

**Auth:** None

**Response:** Array of file objects. Note: shape is similar to `GET /api/collections/:id/files` but **omits** `uploaderUserId` and `updatedAt`, and `createdAt` is serialized as a string (matches the database `TIMESTAMP` text form).
```json
[
  {
    "id": "<uuid>",
    "collectionId": "<uuid>",
    "metadataEnvelope": "<DriveEnvelopeV1 base64>",
    "fileKeyEnvelope": "<DriveEnvelopeV1 base64>",
    "keyEpoch": 1,
    "keyGeneration": 1,
    "metadataRevision": 1,
    "encryptedSizeBytes": 4096,
    "createdAt": "2026-03-14T12:00:00Z",
    "originalKeyGeneration": 1,
    "contentKeyGeneration": 1
  }
]
```

Returns `400` if the share targets a single file (use `/download/:fileId` instead), `410` if the share has expired.

---

### GET /api/share/:token/download/:fileId

Download a file from a public share. Streams the encrypted blob (`application/octet-stream`) through the backend; the client decrypts it with the link key from the URL fragment.

**Auth:** None (the token is the capability)

**Response:** the raw encrypted bytes.

Returns `410 Gone` if the share has expired, `403` if the file does not belong to the shared target. For an album link, the album's items count as belonging to it.

---

### POST /api/share/:token/report

Report a public link to the server's administrators. Anyone may, without an
account; rate-limited per address (20/hour, `RATE_LIMIT_REPORT_PER_HOUR`),
which is not stored.

**Auth:** None

**Request body:**
```json
{
  "reason": "phishing",
  "details": "Asks for a bank password",
  "link": "https://office.example.org/s/<token>#key=…"
}
```

`reason` is `phishing`, `malware`, `illegal`, `abuse` or `other`; `details`
(optional) is at most 2,000 characters. `link` (optional) is the whole link,
key included, so an administrator can see what it shows: it must be one of this
server's Drive, Office or Photos public pages for this token, else `400`. It is
erased when the report is resolved. A link with 50 open reports takes no more.

**Response:** `204 No Content` · `404` unknown link · `410` removed.

Every public-link endpoint answers `410` with `{"error": "…", "code":
"link_removed"}` for a link an administrator took down or whose owner's
account is disabled (an expired link answers `410` without that code).

---

### GET /api/share/:token/files/:fileId/assets/:assetId

A picture in a note reached by a public link: the asset envelope, sealed
under the note's file key at the generation in `X-Kutup-Key-Generation`, as
`GET /api/files/:fileId/assets/:assetId` serves it to members.

**Auth:** None (the token is the capability)

Returns `403` if the file does not belong to the shared target, `404` for an
unknown asset, `410` if the share has expired.

---

## Chat (E2EE messaging)

The current Chat protocol is described in `docs/chat-protocol.md`, media in
`docs/chat-media.md`, and continuous display-history recovery in
`docs/chat-backup.md`. Clients run libsignal Direct Chat and pairwise groups
(docs/plans/pairwise-groups.md); servers retain public routing/identity material, operational metadata,
and opaque ciphertext rather than protected plaintext. All endpoints require a
Bearer JWT unless noted. Wire types live in `crates/kutup-chat-proto` and are
fully described by the OpenAPI document.

### One identity per account (docs/plans/account-identity-key.md)

A Chat account has one libsignal identity key, as Signal's ACI: every device
of the account holds it, and each device has its own registration id and
prekeys, signed by that identity. The account authority's signed manifest
(`AccountManifestV3`) names the identity and every device of the account
(docs/plans/one-device-list.md).

**The manifest's devices.** Each entry is `{ deviceId, kind, chat?,
frameKey?, session }`: `kind` is `chat` (a Chat app), `editor` (an editing
app: Drive, Office, Maps, Pass) or `cli`; `chat: { directChatSuite,
registrationId }` on a device that takes Chat (required on `chat`, optional
on `cli`, never on `editor`); `frameKey`, its Ed25519 collab-frame key
(required on `editor` and `cli`); and `session`, the hash of its sign-in
(`GET /api/device-session`). Messages go to the Chat devices only. A manifest
lists at most `devicesPerAccount` devices (`409 deviceLimit`; the format's cap
is 127).

### GET /api/device-session

`{ "session": "<64 hex>" }`: what a device of the caller's sign-in lists as
its manifest entry's `session`. It is SHA-256 over
`kutup/account/device-session/v1\0` and the root sign-in's id: an app
session's parent, or the session itself. A device asks before it signs its
own entry.

**Device credentials.** A device draws 32 random bytes at registration (its
`credential`, unpadded base64url); the server keeps a salted hash. Every call
a device makes as itself carries `X-Kutup-Device: <deviceId>.<credential>`
beside the JWT: keys, `keys/check`, the manifest, link tokens and relays, the
identity distribution, sends and syncs, the mailbox, socket tickets, the
sender certificate, push subscriptions, profile writes as a device, backup
segments, and device rename and removal. A missing or
wrong credential, or one of a removed or expired device, is `401
deviceCredential`.

### POST /api/chat/device

Register a Chat device (`RegisterChatDeviceRequestV2`): `suite` (`1`),
`registrationId` (`1..16383`), the account's `identityKey`, `signedPreKey`
and `lastResortKyberPreKey` (both signed by that identity; one-time Kyber
keys too: `400 badSignature`), optional `oneTimePreKeys[]` /
`oneTimeKyberPreKeys[]`, optional `name`, the device's `credential`, and
`registration`, one of:

- `{"type": "link", "linkToken"}`: a device linked by one of the account's
  (below). The identity is the account's (`409 identityMismatch`; `409
  noAccountIdentity` when it has none); the token is unused, unexpired and the
  account's (`403 linkToken`), consumed with the insert. The server assigns the
  lowest device id no row of the account holds, within `chatMaxActiveDevices`
  Chat devices (`409`) and `devicesPerAccount` devices of every kind (`409
  deviceLimit`). A device of the account then publishes the manifest that
  lists it.
- `{"type": "reregistration", "manifest"}`: a new identity (Signal's
  `reclaimAccount`): the account's first Chat device, or one restoring after
  every Chat device is lost. The manifest is the account's next
  (`verifySuccessor`: sequence 1 with no manifest, else head + 1 linked by
  hash) and lists this device as its one Chat device, under this sign-in's
  `session`, with the head's other (non-Chat) entries unchanged (`409
  devicesMismatch`); the device takes the lowest id those leave free (1 when
  there are none). In one transaction the server drops every other Chat
  device of the account and every row the manifest doesn't list (prekeys,
  mailboxes, tickets and push subscriptions with them), inserts this one,
  records the identity and publishes the manifest. The gate is the account
  authority, so the master key.

A retry with the same credential answers the device it made. `200 OK` →
`{ "deviceId": 1 }`.

### GET /api/chat/device

The account's Chat devices: those its manifest lists with Chat keys (a registration not yet listed isn't one): `{ "devices": [{ "deviceId", "suite", "name", "createdAt", "lastSeenAt" }] }`.

### PATCH /api/chat/device/{deviceId}

Rename one of the caller's registered Chat installations. The body is
`{ "name": "Work laptop" }`; names are trimmed, required, limited to 64 Unicode
characters, and cannot contain control characters. This changes only
account-private display metadata—the numeric device ID, encryption keys,
sessions, signed device manifest, and protected history remain unchanged.
`204`.

### DELETE /api/chat/device/{deviceId}

Revoke a chat device — hard delete; prekey pools and mailbox rows are removed,
and live sockets close. It does not delete account-level Chat history backup.
`204`.

### POST /api/chat/backup

Idempotently provision the always-on Chat archive after account recovery. The
body contains a typed account-master-key envelope for the random backup root
and an account-authority-signed manifest-signer authorization. The server
validates public bindings and signatures but never receives the root key.

### GET /api/chat/backup

Return provisioning state, current signed manifest/cursor, latest
server-acknowledged protected time, and Chat's usage of the account storage
pool split into message history, administrator-retained delivery media, and
history media. `deviceHeads` lists, per source device number, the sequence
and digest of the last segment accepted from it: a device continues its
number's chain from there (`docs/chat-backup.md`).

### POST /api/chat/backup/segments

Append one idempotent encrypted event segment. Requests bind a random operation
ID, active source device, contiguous per-device sequence and digest chain,
account-manifest sequence, ciphertext digest and length. The server assigns the
monotonic account cursor. `507` means the durable local outbox is not yet
protected; clients must show the latest acknowledged time and storage action.

### GET /api/chat/backup/segments?after=N&limit=N

Page the complete ordered encrypted event tail. Restoring it does not advance a
mailbox cursor or establish Direct Chat or group protocol state.

### POST /api/chat/backup/bases

Stage a typed encrypted compacted base using multipart `metadata` and
`ciphertext` fields. Staging is bounded and expires after 24 hours. Temporary
overlap with the current archive is allowed only when the post-CAS footprint
fits the account storage pool.

### GET /api/chat/backup/bases/{objectId}

Stream only the currently committed encrypted base and its ciphertext digest.

### PUT /api/chat/backup/manifest

Verify and compare-and-swap a signed manifest against the exact current
generation, cursor and digest. Commit atomically activates the staged base and
reconciled media set, then releases superseded message/media quota.

### POST /api/chat/backup/media/copy

Copy an account-owned ordinary Chat-media ciphertext into a padded,
backup-specific outer encryption. The client supplies only the derived outer
key; the original attachment plaintext/key never reaches the server.

### POST /api/chat/backup/media

Multipart direct-upload fallback for a verified outer-encrypted media object
retained locally after its ordinary delivery object has expired.

### GET /api/chat/backup/media/{mediaId}

Lazily stream one opaque history-media object. Clients validate its typed
header, digest, secretstream final tag, source length and zero padding before
placing the inner Chat-media ciphertext in the private cache.

### POST /api/chat/backup/media/reconciliation

Page the exact, digest-bound media reference set for a target generation before
manifest CAS. Unreferenced history media is garbage-collected only at commit.

There is no Chat-backup DELETE route, ordinary disable action, or
device-transfer fallback. Account deletion and administrator loss-recovery wipe
invoke internal lifecycle cleanup that transactionally removes backup database
state/quota and deletes its object-storage prefix.

### GET /api/chat/media/storage

The caller's storage pool as the Chat storage screen shows it:
`{ "totalQuotaBytes", "totalUsedBytes", "driveBytes", "chatMediaBytes" }`.
`totalQuotaBytes` / `totalUsedBytes` are the account pool. `driveBytes` sums
the caller's files, assets, thumbnails and versions; `chatMediaBytes` sums the
caller's Chat delivery media references. Per-conversation totals are computed
on the client from the encrypted attachment ledger. `GET /api/user/storage`
gives the full breakdown.

### PUT /api/chat/keys?deviceId=N

Rotate `signedPreKey` / `lastResortKyberPreKey` and/or upload more one-time prekeys (only fields present are changed; pool inserts are idempotent per `keyId`). Signed keys must be the account identity's (`400 badSignature`).

### POST /api/chat/keys/check

Signal's `/v2/keys/check`: `{ "digest" }`, lowercase hex of
`repeated_use_keys_digest` (kutup-chat-proto) over the account identity, the
device's signed prekey and its last-resort key. `204` when the server holds
the same, `409 keysDiffer` otherwise (the device uploads its keys again).

### PUT /api/chat/account-identity

A new account identity for the devices the account keeps (Signal's
`PhoneNumberIdentityKeyDistributionRequest`), for "reset identity, keep my
devices" after a lost or stolen device: `{ identityKey, devices: [{ deviceId,
registrationId, signedPreKey, lastResortKyberPreKey }], deviceMessages:
[OutgoingEnvelope], manifest }`, each list strictly ordered by `deviceId`.
`devices` names exactly the manifest's devices (the sender included) with its
registration ids, and `deviceMessages` one sealed `accountIdentity` sync per
other listed device on its current session (each at most
`chatDistributionMessageBytes`). `409` (`DeviceListMismatch`) when
the lists don't match the manifest or name a device the account doesn't have;
`410` (`staleDevices`) when a message's `registrationId` is no longer its
device's; `400 badSignature` for a key not signed by the new identity. In one
transaction the server records the identity, publishes the manifest, drops
the devices it leaves out, swaps every kept device's identity, registration
id and keys, deletes every one-time prekey of the account (the devices upload
new ones) and queues the syncs. At most `chatIdentityDistributions` a day.

### Linking a device

As Signal links Desktop to the phone:

1. The new device, signed in, asks `POST /api/chat/provisioning/ticket` for a
   socket ticket (`{ ticket }`, once, within `chatProvisioningTicketSeconds`;
   per address at most `chatProvisioningSockets` a minute; at most
   `chatProvisioningSocketsPerAccount` sockets of one account open at once) and opens `GET
   /api/chat/provisioning?ticket=` (WebSocket). The socket sends `{ "type":
   "address", "address" }` (16 random bytes, base64url) and shows it with its
   ephemeral key as the link code `kutup://link?address=…&key=…`. Pings every
   30 seconds; closed `1000` after the envelope, `4408` (expired) after
   `chatLinkTokenSeconds`.
2. A device of the account asks `POST /api/chat/link-tokens` for a token
   (`{ token, expiresAt }`, single use, lasting `chatLinkTokenSeconds`; at most
   `chatLinkTokensPerAccount` unused: `409 linkTokenLimit`; at most
   `chatLinkTokens` an hour).
3. It sends the provisioning message, encrypted to the new device's key, with
   `PUT /api/chat/provisioning/{address}` (`{ envelope: ProvisionEnvelopeV1 }`,
   at most `chatProvisionBodyBytes`; `chatProvisioningRelays` a minute). The
   server relays it to that socket (`{ "type": "envelope", "envelope" }`) and
   keeps nothing; an address that is no socket of the account is `404`.
4. The new device registers with `{"type": "link", "linkToken"}`.

### GET /api/chat/keys/count?deviceId=N

Remaining one-time pool sizes: `{ "oneTimePreKeys": n, "oneTimeKyberPreKeys": n }` — clients replenish below a threshold.

### POST /api/chat/manifest

Publish the account's next `AccountManifestV3`, signed by the account
self-authority (device-authenticated: any device of the account, of every
kind; without `X-Kutup-Device`, a sign-in alone may publish one that only
removes devices, every other entry as the head lists it, which the Account
app does: `401 deviceCredential` for anything else). It follows the head
(`verifySuccessor`: head + 1, linked by hash, the same account, incarnation
and authority), names the account's identity (`409 identityMismatch`: the
identity changes only by a distribution or a re-registration), carries
that identity's `identityBinding` (its signature over the authority key id,
incarnation, account and identity key; `400 badSignature` otherwise, here and
wherever a manifest is uploaded), and every listed device is a live
registered row of the account with its listed kind, sign-in, frame key, and
registration id and suite (`409 devicesMismatch`), at most
`devicesPerAccount` of them (`409 deviceLimit`). Rows it doesn't list (a crash between registration and publication, an
expired device, an injected row) are pruned atomically. The Drive HPKE and
share-signing keys are account-scoped fields in the same manifest. Publication
atomically updates the current head and immutable history; exact replay is
idempotent. `AccountManifestPublicationV3`.

### Device expiry

A device idle for the administrators' `deviceExpiryDays` is marked expired:
it leaves send device sets and key bundles at once and its credential stops
working; the account's next manifest (any of its devices publishes one on
`DevicesChanged`) drops the row.

### Chat routes name accounts by id

Every Chat route that names another person takes their permanent account id
in the path and their server as `?server=` (this server when absent): `aci`
accounts, never names (docs/plans/account-ids.md). A name becomes an account
only through `GET /api/users/by-address/:address`. A local account that is
not active answers `404`; the anonymous routes give one answer for every
failure. Manifests, profiles, key bundles (`account`) and mailbox envelopes
(`sender`) name accounts as `{ "server", "accountId" }`.

### GET /api/chat/accounts/{accountId}/manifest

Return the current account-signed device manifest for an account. This direct
manifest endpoint is authenticated. A client independently verifies its
signature, authority continuity, and hash chain rather than trusting a server
status label. `404 noManifest`: the account has no Chat manifest yet; a 404
without that code (an unknown account; a remote server that didn't say so)
is not that answer.

### GET /api/chat/accounts/{accountId}/manifest-history

Return complete, individually account-signed manifest records for an exact
inclusive range. Query parameters are `fromSequence`, `toSequence`, and an
optional `pageFromSequence`. Pages contain at most 64 records and carry the
next exact sequence, never an opaque server cursor. Missing, duplicated,
reordered, cross-incarnation, or partially verified history does not clear a
client gap and blocks new sends to that peer. Another server's account is
asked only through the authenticated federation transport.

### GET /api/chat/profile

Owner-only recovery of the current opaque encrypted profile, including the
random profile key wrapped under the account master key for linked-device
recovery. Returns `404` until a profile has been published.
The response carries `suite: 1`, canonical `account`, version, revision,
source device, and canonical `ProfileEnvelopeV1` fields. The owner-only
response includes the wrapped profile-key envelope; peer responses omit it.

### PUT /api/chat/profile

Publish a new opaque encrypted profile: display name, optional avatar and
optional `about` (Signal's one-line "about", ≤ 140 characters, padded to
128/254/512 bytes before encryption). The server sees
only ciphertext, a profile-key-derived version, an access-key verifier, a
master-key-wrapped profile key, revision, and source device. Revision plus
source-device ordering resolves concurrent linked-device writes; exact replay
is idempotent and a stale/conflicting revision returns `409`.
Every encrypted field binds the exact profile suite, the authenticated
account (server and account id, so a rename leaves it valid), version,
revision, source device and purpose. Unknown suites,
noncanonical base64, malformed headers, relocation and trailing bytes return
`400` before persistence.

### GET /api/chat/accounts/{accountId}/profile/{version}

Capability-gated encrypted profile lookup for a local or federated account. The caller supplies the profile access key in the dedicated request
header rather than the URL. A wrong version or capability is deliberately
indistinguishable from a missing profile and returns `404`.

### GET /api/chat/accounts/{accountId}/keys

Return `AccountPreKeyBundlesResponse`: the account's `identityKey` once,
PQXDH prekey bundles for **every** device its manifest lists that hasn't
expired (a logical message encrypts to all of them), and the exact complete
account-signed `AccountManifestV3`, for its Chat devices. Each bundle carries its `deviceId`,
`registrationId`, `suite`, `signedPreKey`, `kyberPreKey` (a consumed one-time
ML-KEM-1024 prekey, or the reusable last-resort key when the pool is empty),
and optionally a consumed one-time EC prekey. The client checks the bundles
against the manifest (`check_against_manifest`) and the prekey signatures
against the identity before creating sessions; a server relaying another
server's bundles checks them against its manifest first. A `syncDeviceId`
fetch is made as that device (its credential). Fetches are limited to 30/min per authenticated account
(`RATE_LIMIT_CHAT_KEYS_PER_MIN`) with a coarse 120/min IP wall
(`RATE_LIMIT_CHAT_KEYS_IP_PER_MIN`).

### POST /api/chat/accounts/{accountId}/messages

Deliver one logical message as per-device ciphertexts: `{ "senderDeviceId": n, "envelopes": [{ "deviceId", "registrationId", "envelopeType": "preKey"|"message", "suite": 1, "content": "<base64>" }] }`. The device set must exactly match the recipient's current devices — ids **and** registration ids — or the send fails with `409 { "missingDevices": [], "staleDevices": [], "extraDevices": [] }` (Signal's contract: no device can be silently skipped, and reinstalled devices are detected). Stored envelopes are also pushed to the recipient's live chat sockets.

### POST /api/chat/sync/messages

Deliver an encrypted sent transcript to every other active device belonging to
the authenticated account. The sending device is excluded from the exact
device-set check; an empty destination set succeeds for a single-device
account. Note to Self and ordinary outgoing-message synchronization use this
same idempotent mailbox path.

### GET /api/chat/messages?deviceId=N&limit=100

Drain the device's mailbox, oldest first (max 500/page): `{ "envelopes": [{ "id", "sender" (`{ server, accountId }`, absent under sealed sender), "senderDeviceId", "envelopeType", "suite", "content", "serverTimestamp" }], "more": bool }`. Envelopes stay stored until acked.

### POST /api/chat/messages/ack?deviceId=N

`{ "ids": ["<uuid>", …] }` → deletes processed envelopes; returns `{ "acked": n }`.

### POST /api/chat/link-preview

Fetch one public page or image for a link preview the caller is building
(`{ "url": "https://…", "kind": "page" | "image" }` → `{ finalUrl,
contentType, body }`, body standard base64). Only `https` on port 443 whose
every resolved address is public; the connection is pinned to the checked
address; at most three redirects, each checked again; pages are cut at
512 KiB and must be HTML, images must be JPEG/PNG/WebP/GIF of at most 2 MiB;
8 s total. 30 per minute per account. `404` when `CHAT_LINK_PREVIEWS=false`
(then `/api/auth/settings` → `chat.linkPreviews` is false), `400` for a
non-public or non-https URL, `422` when the site gives nothing usable. The
browser parses the page (`DOMParser`) and resizes the image; the preview then
travels end-to-end encrypted in the message.

### GET /api/chat/call-servers

ICE servers for a call ([`chat-calls.md`](chat-calls.md)):
`{ "iceServers": [{ "urls": [...], "username"?, "credential"? }], "relay": bool, "expiresAt"? }`.
With `CHAT_TURN_URLS` and `CHAT_TURN_SECRET` set, the TURN entry carries a
12-hour coturn shared-secret credential (username `<expiry>:<pseudonym>`,
password `base64(HMAC-SHA1(secret, username))`); `relay` is then true. 60
per minute per account.

### POST /api/chat/group-calls/token

`{ "host", "roomId", "participantId" }` (room and tag: 32 lowercase hex each)
→ `{ "url", "token" }`: the SFU's WebSocket URL and a 6-hour LiveKit token
for that room ([`chat-calls.md`](chat-calls.md) "Group calls"). The host
mints it; another host is asked over signed federation
(`POST /api/fed/chat/group-calls/token`). `404` when the host has no SFU,
`429` over 30 per minute per account (300 per origin server), `502` when
the host cannot be reached.

### GET /api/chat/groups/gateway-key?server={home}&fromSequence={n}

Pairwise groups' anonymous route ([`plans/pairwise-groups.md`](plans/pairwise-groups.md) §3;
groups are off unless `CHAT_GROUPS=true`, `404` otherwise). Signed-in:
`{ "config": GroupGatewayKeyConfigV1, "identityHistory": [identity documents] }`,
the home's HPKE key config, signed by its federation identity, and its
identity documents from sequence `n` (the one the group pins) on, at most 64.
This server fetches a peer's config over signed federation
(`GET /api/fed/chat/groups/gateway-key`) and gives the history it has
verified; the client trusts neither until it follows the history from its
pin and verifies the config. The key changes weekly; the previous one is
accepted for 24 hours. `502` when the home is unreachable.

### POST /api/chat/groups/relay/{home}

Signed-in. The body is a request sealed to the home's gateway key
(RFC 9458 encapsulation, `message/ohttp-req`, at most 256 KiB + 55 bytes);
the answer is the sealed response (`application/octet-stream`, `no-store`).
This server passes it on unread: to its own gateway when it is the home,
otherwise over signed federation to `POST /api/fed/chat/groups/gateway`, and
only to federation peers. `400` (empty) when the home could not open it,
`429` over 240 per minute per account, `502` when the home is unreachable.
Inside, the home checks the request's home, clock (5 minutes), signature and
nonce, and answers with one `notFound` for an unknown group, a non-member and
a bad signature; the operations and answers are `GroupRequestV1` /
`GroupResponseV1` in `kutup_chat_proto::group_route`. The home limits per
relaying server (6000/min), per pseudonym (240/min), changes per pseudonym
(30/min) and per group (60/min), link requests per group (30/min), and new
groups per relaying server (600/hour). Joins from a link and requests to
join are limited per relaying server and group, and per relaying server, as
administrators set them (`chatGroupLinkJoinsPerRelayGroupPerMin`, 120/min,
and `chatGroupLinkJoinsPerRelayPerMin`, 1200/min, at first): charged once the
link's password holds and before the rest of the change is checked, so a
change without the link spends nothing and one link's holders crowd only
its group. Group budgets are charged only for
valid changes and proven link requests; failed requests spend a separate
budget per relaying server (600/min). A stranger, a removed member, or a
newcomer whose claim, link password or request doesn't hold gets the same
`notFound` as an unknown group, never a conflict or a refusal code.
Refusal codes besides the group checks' own (`kutup_chat_proto::group`):
`malformed` (a body that doesn't parse), `wrongActor` (a change whose actor
isn't the request's signer), `wrongGroup` (a genesis for another group),
`serverFull`, and `pseudonymUsed`: a newcomer's claim, join from the link or
request to join under a pseudonym the group has had before, as a member or
a requester. The home answers `pseudonymUsed` only once the claim's or the
link's proof holds and the change passes every other check, and only its own
key holder can sign a request as that pseudonym, so nobody else learns it.
It is the one refusal that spends neither the relaying server's failure
budget nor the group's change budget: the client retries at its next join
epoch (up to 64).
Group send endorsements (§3.3): `putEndorsement`, signed by a member, takes
`GroupEndorsementUploadV1 { expiration, sealed }`: the member's blob for one
expiration, sealed under the group's state key (553 bytes, base64; the home
never opens it). The home refuses an expiration not day-aligned, past, or more
than 3 days ahead (`endorsementExpiration`) and any other length
(`endorsementSize`), keeps at most two per member (a third replaces the
oldest; the same expiration again replaces it) and counts uploads per member
and group a day (`chatGroupEndorsementUploadsPerDay`, 8 at first;
`rateLimited` past it); it answers `ok` with no body. `getEndorsements`
takes `GroupEndorsementQueryV1 { after, limit }` and answers
`GroupEndorsementPageV1 { endorsements: [{ pseudonym, expiration, sealed,
seq }], more, nextAfter }`: the members' blobs uploaded after the cursor, in
upload order, none past its expiration, at most `limit` and the page size
(`chatGroupEndorsementPageSize`, 100 at first, at most 200); `nextAfter` is
past every blob the page read (or `after` when it read none). A removed member's blobs go with the
change that removes it, and blobs go an hour after they expire. Both answer a
non-member `notFound`.
`getRequestStatus` (no body, signed by the requesting pseudonym) answers
where the signer's own request stands, as `GroupRequestStatusV1`:
`{ "status": "pending", "revision", "head" }` while it requests (what a
cancel names, so it works after a link reset too), `member` once approved,
`denied` when banned, or when the group saw the pseudonym (as a requester or
a member) and it is neither now, and `unknown` for a pseudonym the group never
saw or an unknown group: never `notFound`. It spends the per-pseudonym budget,
and an `unknown` answer also the relaying server's failure budget; every
answer takes the same reads, so its timing doesn't tell whether the group
exists. A cancel is done once: sent again it meets `notFound`, so a client
that lost the answer to its cancel asks the status (`denied` then).
Avatars: `putAvatar` (signed by a member that `access.attributes` lets
change attributes, else `notAllowed`) carries the sealed blob padded to one
size (`pad_group_avatar`: its length, the blob, zeros to 41,005 bytes; the
blob is 8,233, 16,425, 32,809 or 41,001 bytes). It becomes the group's one
pending upload for `chatGroupAvatarPendingSeconds` (a day at first), in
place of any earlier one; once that passes it counts as missing, swept or
not. A change naming an
avatar hash must find that blob, pending or current (`avatarMissing`
otherwise; a genesis can't name one); once accepted it becomes the current
blob and the others go, and removing the avatar drops its blob.
`getAvatar` answers the current blob padded the same way, to a member or
with the link's password (charged as join info), or `avatarMissing`.
Refusals: `avatarTooLarge` over the largest blob and `avatarStorageFull`
over the storage per group (the current blob and the upload), both
administrators' settings; `malformed` for a body not padded so. An upload
spends the change budgets.

### GET /api/chat/group-send/endorsement

Group send endorsements ([`plans/group-send-endorsements.md`](plans/group-send-endorsements.md)
§3.2; `404` unless `CHAT_GROUPS=true` and federation is on). Signed-in: today's
endorsement of the account, `GroupSendEndorsementResponseV1 { keyId,
expiration, response }`, issued with this server's issuing key for
libsignal's default expiration (the end of the next day UTC, 25 to 49 hours
ahead). `response` is the serialized `GroupSendEndorsementsResponse` with its
proof; the client checks it with the key `keyId` names (`params`) and shares
it, sealed, with each of its groups. It says nothing about groups: every
account fetches one a day. `429` past the account's endorsements a day
(`chatGroupSendEndorsementsPerDay`, 48 at first).

### GET /api/chat/group-send/params?server={host}

Signed-in (§4). `GroupSendParamsV1 { keys: [{ keyId, endorsementPublicKey,
issuesUntil }] }`: the server's issuing key and, while it still verifies, the
one before it. Without `server` (or with this server's name) this server's
own; with another's, that server's keys from its signed discovery
(`chatGroupSend`), verified and cached by this server's federation. A sender
checks a recipient's endorsement with its server's key; a wrong key costs
only that check, as each server verifies tokens with its own secret.
`issuesUntil` is when a key stopped issuing, and 9007199254740991 (the
largest integer every client reads exactly) for the issuing key. `404` when
that server publishes none, `502` when it is unreachable. An operator rotates
the key with `kutup-server chat-zk-keys rotate`: the new key issues at once,
the old one verifies until the last endorsement it issued expires, and a
second rotation waits for that.

### GET /api/chat/group-list

The account's group list ([`plans/pairwise-groups.md`](plans/pairwise-groups.md) §5;
`404` unless `CHAT_GROUPS=true` and federation is on): one sealed entry per
pairwise group the account is in, so its other devices find its groups.
`{ "entries": [{ "id", "revision", "envelope" }] }`. `id` is a keyed hash of
the group id under a key derived from the account's master key (43
characters of base64url without padding), so lists can't be matched across
members; `envelope` is the sealed entry (standard base64, always 4032 bytes),
whose authenticated header carries its revision. The server never opens it.
The account head's `chatGroups` scope lists every entry. **Auth:** Bearer JWT.

### PUT /api/chat/group-list/{id}

`{ "baseRevision": <n>, "envelope": "<base64>", "head"?: "<base64>" }` →
`200` with the stored entry. `baseRevision` is the revision the write started
from (0 for a new entry); the new revision is read from the envelope's header
and must be above it (`400` otherwise; a body carrying its own `revision` is
`422`). `409 revision_conflict` with `revision`, the current one, when another
device wrote first. Once the account keeps a head, `head` must be the next
one, covering the new revision (`409 head_required` / `head_conflict`).
`400` for an envelope that isn't 4032 bytes of canonical base64 or doesn't
parse, and for a new entry past 1024; `404` for an id that isn't one.

### DELETE /api/chat/group-list/{id}

`{ "baseRevision": <n>, "head"?: "<base64>" }` → `204`: removes the entry if
it is still at `baseRevision` (an ended group whose chat its person deleted).
`409 revision_conflict` with the current revision when it moved, `404` when
there is no such entry; `head` as for `PUT`.

### GET /api/chat/contact-list

The account's Chat contacts ([`plans/chat-contacts-sync.md`](plans/chat-contacts-sync.md)):
one sealed entry per person the account accepted, rejected, blocked or asked,
so a device that lost everything restores them. Wherever Chat is (pairwise
groups needn't be on). `{ "entries": [{ "id", "revision", "envelope" }] }`.
`id` is a keyed hash of the contact's account (`AccountRef`) under a key
derived from the account's master key (43 characters of base64url without
padding); `envelope` is the sealed entry (standard base64, always 2048 bytes),
whose authenticated header carries its revision. The server never opens it.
The account head's `chatContacts` scope lists every entry. **Auth:** Bearer
JWT. An account reset clears the list.

### PUT /api/chat/contact-list/{id}

As `PUT /api/chat/group-list/{id}`: `{ "baseRevision", "envelope", "head"? }`
→ `200` with the stored entry; `409 revision_conflict` with the current
`revision`, `head_required` / `head_conflict`. `400` for an envelope that
isn't 2048 bytes of canonical base64 or isn't a contact list entry (a group
list entry isn't one), and `400 contactListFull` for a new entry past 10,000
(the client evicts before that: the oldest rejections, then the oldest pending
requests, never a block); `404` for an id that isn't one.

### DELETE /api/chat/contact-list/{id}

`{ "baseRevision": <n>, "head"?: "<base64>" }` → `204`: removes the entry if
it is still at `baseRevision` (one the client evicted). `409
revision_conflict` with the current revision when it moved, `404` when there
is no such entry; `head` as for `PUT`.

### POST /api/chat/call-links

`{ "roomId", "nonce", "accessTokenHash", "info", "hostTokenHash", "waitingRoom"? }` → `201` with
`{ "roomId", "nonce", "info", "createdAt" }`: register a meeting
([`chat-calls.md`](chat-calls.md) "Meetings"). `roomId` and `nonce` are 32
lowercase hex characters; `accessTokenHash` is the SHA-256 of the link's
access token (standard base64); `info` is the sealed title and time (552
bytes of standard base64). The link's secret never reaches the server.
`404` when the server has no SFU, `409` when the meeting exists or the
account already has 50. Optional `"replaces"` (another of the account's
room ids, "New link"): in the same transaction the old meeting is closed at
the SFU and its link deleted, so the two never both work; the new link
does not count against the 50. `404` when the account has no such link,
`502` when the SFU cannot close the old meeting (nothing changes).

### GET /api/chat/call-links

→ `{ "links": [{ "roomId", "nonce", "info", "createdAt" }] }`: the
account's meetings, newest first. Its clients derive each link again from
the nonce and open the info.

### PUT /api/chat/call-links/:roomId/info

`{ "info" }` → `204`: replace the meeting's sealed title and time. `404`
when the account has no such meeting.

### DELETE /api/chat/call-links/:roomId

→ `204`: nobody can join through the link any more, and whoever is in the
meeting is disconnected. `404` when the account has no such meeting.

### POST /api/chat/call-links/info

**No authentication.** `{ "roomId", "accessToken" }` →
`{ "info", "waitingRoom", "locked" }`: the meeting's sealed title and time,
whether joiners wait to be let in and whether a host locked it, for whoever
holds the link. `404` for an
unknown room and for a wrong access token alike, `429` over 60 a minute per
address (`RATE_LIMIT_CALL_LINK_PER_MIN`, shared with the token route).

### POST /api/chat/call-links/token

**No authentication needed.**
`{ "roomId", "accessToken", "participantId", "seat", "label", "hostToken"? }`
→ `{ "url", "token" }`: the SFU's WebSocket URL and a 6-hour LiveKit token
for the meeting's current sitting, for whoever holds the link. `accessToken`
is 32 bytes of standard base64, `participantId` 32 lowercase hex characters,
`seat` a 32-byte secret (standard base64) only the joining browser holds,
and `label` the joiner's sealed name (168 bytes of standard base64), which
the token carries to the other participants as metadata
([`chat-calls.md`](chat-calls.md) "Seats"). A token for an identity is
minted only to the holder of its seat: `409` when the identity is someone
else's, `410` when a host removed it. `423` when a host locked the meeting.
`404` and `429` as above.

Sent with a signed-in account's `Authorization: Bearer` access token, the
SFU token also carries that account's address as the participant's name,
which the others see as vouched for by this server. The seat or knock keeps
the account's id; the address is its current one, read at every token, so a
rename shows at the next one. Without it the joiner is a guest. The same
holds for `…/knock`.

### PUT /api/chat/call-links/:roomId/waiting-room

`{ "enabled", "hostTokenHash" }` → `204`: turn the meeting's waiting room on
or off ([`chat-calls.md`](chat-calls.md) "The waiting room"). `hostTokenHash`
is the SHA-256 of the owner's host token (standard base64, 32 bytes).
Turning it off lets in everyone still waiting. `404` when the account has no
such meeting. `POST /api/chat/call-links` takes the same two fields
(`hostTokenHash` required, `waitingRoom` optional) when a meeting is made, the list returns
`waitingRoom`, and `POST /api/chat/call-links/info` returns it beside the
sealed info.

With a waiting room, `POST /api/chat/call-links/token` answers `403` unless
its optional `hostToken` is the owner's, or the seat was already let in.

### POST /api/chat/call-links/knock

**No authentication needed.**
`{ "roomId", "accessToken", "participantId", "seat", "label" }` → `201` with
`{ "knockId", "ticket" }`: ask to be let in. `409` when the meeting has no
waiting room, `423` when it is locked, `429` when 50 people are already
waiting or over 60 a minute per address.

### POST /api/chat/call-links/knock/leave

**No authentication.** `{ "roomId", "accessToken", "knockId", "ticket" }` →
`204`: the knocker stops waiting and the knock leaves the host's list at
once. Sent with
`keepalive` as the page closes. A knock already let in or turned away keeps
its outcome; a wrong ticket changes nothing (still `204`). `404` for an
unknown link or a wrong access token.

### POST /api/chat/call-links/knock/status

**No authentication.** `{ "roomId", "accessToken", "knockId", "ticket" }` →
`{ "status" }` (`waiting`, `turnedAway`) or
`{ "status": "admitted", "url", "token" }` with the SFU token. Asking keeps
the knock alive. `404` for a wrong ticket or a knock that is gone. This and
the two routes below are limited to 600 a minute per address
(`RATE_LIMIT_CALL_LINK_POLL_PER_MIN`).

### POST /api/chat/call-links/knocks

**No authentication; a host's proof.** A host is the owner, who sends
`hostToken`, or a co-host, who sends `sfuToken`: the SFU token this server
minted for them ([`chat-calls.md`](chat-calls.md) "Hosts").
`{ "roomId", "accessToken", "hostToken" | "sfuToken" }` →
`{ "knocks": [{ "knockId", "label", "account"?, "createdAt" }] }`: who is
waiting, oldest first, each with their sealed name and, when they showed
it, the account this server vouches for (its current address). `404` for anyone who is not a
host, as for an unknown room.

### POST /api/chat/call-links/knocks/decide

**No authentication; a host's proof.**
`{ "roomId", "accessToken", "hostToken" | "sfuToken", "knockId", "admit" }`
→ `204`. `404` when nobody is waiting under that knock.

### POST /api/chat/call-links/roles

**No authentication.** `{ "roomId", "accessToken", "hostToken"?, "sfuToken"? }`
→ `{ "me"?, "roles": [{ "participantId", "role" }], "locked", "waitingRoom",
"noHost" }`: the meeting's hosts by SFU identity, `role` being `owner` or
`coHost`, and how the meeting is set, for anyone holding the link. `me` is
the asker's own role when the token they sent carries one. `noHost` says no
host is in the meeting now: if that lasts 20 seconds the longest-present
participant becomes a co-host, so ask again then. Asking also has the
server remove again anyone who was removed and is back in the room. The
routes from here to `…/end` are limited like the knock routes.

### POST /api/chat/call-links/co-hosts

**No authentication; the owner's host token.**
`{ "roomId", "accessToken", "hostToken", "participantId", "enabled" }` →
`204`: make that participant a co-host, or stop them being one. `409` when
it is the owner's own identity; `404` for anyone but the owner, or when
nobody in the meeting has that identity.

### POST /api/chat/call-links/participants/remove

**No authentication; a host's proof.**
`{ "roomId", "accessToken", "hostToken" | "sfuToken", "participantId" }` →
`204`: disconnect that participant at the SFU and turn the meeting's
waiting room on. `403` when a co-host names a host, or anyone names the
owner; `404` for anyone who is not a host; `502` when the SFU's API
(`CHAT_SFU_API_URL`) cannot be reached. The same answers apply to the two
routes below.

### POST /api/chat/call-links/participants/mute

**No authentication; a host's proof.**
`{ "roomId", "accessToken", "hostToken" | "sfuToken", "participantId"? }` →
`204`: mute that participant's microphone, or, with nobody named, the
microphone of everyone who is not a host. They can turn it back on.

### POST /api/chat/call-links/participants/screen

**No authentication; a host's proof.**
`{ "roomId", "accessToken", "hostToken" | "sfuToken", "participantId",
"allowed" }` → `204`: stop that participant sharing their screen (what they
share ends, and they cannot start again), or allow it again.

### POST /api/chat/call-links/lock

**No authentication; a host's proof.**
`{ "roomId", "accessToken", "hostToken" | "sfuToken", "locked" }` → `204`:
lock the meeting (nobody new comes in; whoever is waiting is turned away) or
unlock it.

### POST /api/chat/call-links/end

**No authentication; the owner's host token.**
`{ "roomId", "accessToken", "hostToken" }` → `204`: end the meeting for
everyone in it and begin a new sitting, which the SFU tokens of the ended
one do not open. Every seat and role is forgotten and whoever is waiting is
turned away; the link keeps working. `404` for anyone but the owner, `502`
when the SFU's API cannot be reached.

### GET /api/chat/joined-meetings

→ `{ "entries": [{ "id", "entry" }] }`: the meetings this account joined,
most recently recorded first, at most 100
([`chat-calls.md`](chat-calls.md) "History"). Each `entry` is a stay sealed
in the browser under a key from the account master key (base64, 1064
bytes); the server cannot open it.

### POST /api/chat/joined-meetings

`{ "id", "entry" }` → `204`: record a stay. `id` is 32 lowercase hex
characters chosen by the browser; recording the same id again changes
nothing. Beyond 100 the oldest are dropped.

### DELETE /api/chat/joined-meetings/:id

→ `204`: take one stay off the list.

### DELETE /api/chat/joined-meetings

→ `204`: clear the list.

### PUT /api/chat/push-subscription

`{ "deviceId": N, "endpoint": "https://…" }` → `204`: wake this chat device
through the browser's push subscription while it has no live socket
([`chat-notifications.md`](chat-notifications.md)). Only endpoints of the
push services in `CHAT_WEB_PUSH_HOSTS` (https, port 443); `400` otherwise,
`404` when Web Push is off (`/api/auth/settings` → `chat.webPushPublicKey`
is then absent) or the device is not the caller's.

### DELETE /api/chat/push-subscription?deviceId=N

`204`: stop waking the device.

Browsers mint the socket's one-time ticket with `POST /api/device-ticket`
(Devices, below); the Chat socket takes only a Chat device's.

### GET /api/chat/ws?ticket=…

WebSocket. Browsers use the one-time ticket; native clients instead send `Authorization: Bearer …` with `?deviceId=N`. Reusable JWT query parameters are rejected. Server → client JSON frames: `{ "type": "drainMailbox" }` once on connect (fetch the backlog over REST), then `{ "type": "envelope", "envelope": {…} }` per newly arrived message (each envelope, here and in the mailbox drain, carries the sender's `sendId` when the server has it, so a device that cannot decrypt one can ask its sender for that message again), and `{ "type": "devicesChanged" }` to every connected device of an account whenever one of its devices is registered, removed or expired or a new signed manifest is published (it carries nothing; each device fetches and verifies the list itself, and one that misses it is corrected by the device-set check on its next send). Acks stay on REST — the mailbox is the source of truth. The only client → server frame is `{ "type": "ping" }`, answered by `{ "type": "pong" }`: browsers cannot send protocol pings, so the web client probes every 25 s and reconnects when no answer arrives within 10 s.

---

## Chat Federation — Server-to-Server Endpoints

Chat federation is present only when the administrator configures a persistent
v2 identity. Admission follows the global stop plus Chat's `disabled`,
`allowlist`, `blocklist`, or `open` mode, trust floor, and directional domain
rules. Policy is evaluated before DNS/discovery or delivery. Admitted traffic
must then pass signed discovery and complete identity-history verification,
persistent pin/rotation/quarantine policy, public-HTTPS and DNS/SSRF checks,
strict RFC 9421/9530 request and response signatures, replay reservation,
request/body bounds, protocol checks, and coarse rate limiting. The normative
common transport contract is in `docs/federation-protocol.md`.

The v2 Ed25519 signature binds method, authority, path/query, exact-body digest,
content type, federation version, feature, origin, destination, key ID, nonce,
and a maximum five-minute lifetime. Authenticated responses bind those request
components in reverse origin/destination order. A destination mismatch,
unknown pinned key, bad signature, nonce/content conflict, or invalid time
window is rejected.

### GET /.well-known/kutup/federation.json

Signed v2 discovery containing the canonical server, delegated `apiBase`,
typed capabilities, embedded current identity document and hash, validity
window, and signature. Returns `404` when the shared identity is absent, the
global stop is active, or both Chat and Drive are disabled. An individually
disabled feature is omitted from `capabilities` while the other remains
discoverable. Production discovery and delegated API targets require public
HTTPS.

### GET /.well-known/kutup/federation/identity/{sequence}.json

Return one immutable identity document from the locally verified, contiguous
history. Genesis is sequence zero. Every rotation hash-links its predecessor
and is signed by both old and new keys.

### GET /api/fed/chat/accounts/{accountId}/keys

Authenticated server-to-server directory lookup. Returns the remote user's
account-signed complete manifest and replay-safe last-resort PQ bundles. It
deliberately does not consume one-time prekeys, so a replayed signed read cannot
exhaust the remote recipient's pool.

### GET /api/fed/chat/accounts/{accountId}/manifest

Return the current complete account-signed manifest through an authenticated,
origin- and destination-bound federation response (`404 noManifest` when the
account has none).

### GET /api/fed/chat/accounts/{accountId}/manifest-history

Return the same exact-sequence, maximum-64-entry history pages as the local
route. The signed request URI binds `fromSequence`, `toSequence`, and optional
`pageFromSequence`.

### GET /api/fed/chat/accounts/{accountId}/profile/{version}

Authenticated proxy lookup for an opaque encrypted profile. The server-to-
server signature authenticates and destination-binds the originating
homeserver; the separate profile access-key header remains the end-to-end
capability. Wrong capabilities return `404`.

### GET /api/fed/{chat|drive}/names/{username}/renames

Signed, under `chat.v2` at `/api/fed/chat/…` or `drive.v1` at
`/api/fed/drive/…` (each feature's requests stay in its own namespace;
servers send under whichever the peer admits). Every
rename chain naming `username@<this server>`, in any spelling, as `GET
/api/users/renames/:address` answers them; `?incarnationId=` narrows them.

### POST /api/fed/{chat|drive}/accounts/renames

Signed (under `chat.v2` or `drive.v1`). A peer announces one of its accounts'
renames: `{ "version": 1, "username", "incarnationId", "authorityPublicKey",
"chain": [<AccountRenameV1>, …] }`, the whole chain, `username` its last
current. Kept when it verifies (the incarnation is its authority's hash, every
address is on the sending server) and extends the one kept (`204`); then this
server's rows about that incarnation (incoming and outgoing federated shares,
profile keys, collaboration devices) move to the new address, by incarnation
only. `400` for a chain that does not check out, `409` for one that does not
extend the one kept, `429` past 50,000 chains of that server or 600 announces
a minute. Announces are sent after a rename commits to every pinned peer not
quarantined, retried with backoff for 7 days.

### POST /api/fed/chat/messages

Receive one signed, ordered `FederatedChatTransaction`. The receiver enforces a
contiguous per-origin sequence, exact recipient device set, canonical
origin/sender and destination/recipient binding, and transaction-id replay
safety. Mailbox rows, the stored idempotent response, and the sequence
high-water mark commit atomically. Exact replay returns the stored response;
device mismatch or sequence gap returns typed `409` data so the origin can
refresh/re-encrypt or replay the missing retained transaction.

---

## Drive Federation — Local Authenticated Endpoints

These routes let a local browser interact with a remote encrypted share. The
local server performs all remote discovery, admission, identity pinning, and
message authentication; browsers never submit a remote API URL.

### POST /api/drive/federation/shares

Accept an invite after the browser parses its fragment.

**Auth:** Bearer JWT

```json
{
  "server": "sharer.example.com",
  "capability": "<base64url>"
}
```

The server fetches the signed invite and verifies that its source domain and
intended recipient username match the authenticated local account. Success is
`201 Created` with:

```json
{
  "id": "<uuid>",
  "remoteDomain": "sharer.example.com",
  "remoteCollectionId": "<uuid>",
  "namedShareEnvelope": "<NamedShareEnvelopeV1 base64>",
  "nameEnvelope": "<DriveEnvelopeV1 base64>",
  "keyEpoch": 1,
  "nameRevision": 1,
  "epochStatement": "<CollectionEpochStatementV1 base64>",
  "epochStatementHash": "<lowercase SHA-256 hex>",
  "ownerUserId": "<uuid>",
  "ownerAccount": "alice@sharer.example.com",
  "ownerIncarnationId": "<lowercase SHA-256 hex>",
  "ownerSigningPublicKey": "<canonical base64, 32 bytes>",
  "ownerAuthorityPublicKey": "<canonical base64, 32 bytes>",
  "canUpload": true,
  "canDelete": false,
  "uploadQuotaBytes": null,
  "collectionKind": "folder",
  "createdAt": "<RFC3339>"
}
```

The retained remote capability is secret server-side state and is omitted from
all responses. `collectionKind` is `folder` or `album`, as the owner's server
states in the invite.

### GET /api/drive/federation/shares

List the authenticated user's accepted remote shares. Returns the same public
shape as acceptance, without any capability. `?kind=folder` (the default)
lists folders, for Drive; `?kind=album` lists Photos albums.

### DELETE /api/drive/federation/shares/:shareId

Remove one accepted remote share for the authenticated user. Returns `204`.

### GET /api/drive/federation/shares/:shareId/files

Return the signed and verified remote ciphertext metadata list.

### GET /api/drive/federation/shares/:shareId/files/:fileId/content

Stream remote ciphertext. The local server first spools and hashes the complete
remote response, verifies its signed RFC 9530 digest under the pinned peer key,
then releases the verified stream to the browser.

### POST /api/drive/federation/shares/:shareId/files

Upload encrypted multipart fields (`fileId`, `metadataEnvelope`,
`fileKeyEnvelope`, and `file`). Exact retries are idempotent
and return the same `201 { "id": "<uuid>" }` result. The body is spooled to
disk and streamed on to the owner's server with its signed content digest;
it is never held in memory.

### POST /api/drive/federation/shares/:shareId/refresh

Bring a share's stored copy up to the owner's current folder key after a
rotation. The recipient's server fetches the invite again and accepts it only
from the same owner, folder and authority, never at an older epoch, and only
if the owner's signed history (`GET /api/fed/drive/epochs`) descends from the
stored epoch. A revoked share fails from the owner's server. **Response:** the
refreshed share.

### GET /api/drive/federation/shares/:shareId/files/:fileId/state

A note's or place list's latest saved Yjs state in the remote folder, relayed:
`{ keyGeneration, state }` (state base64, sealed under the file key of that
generation), `404` when it has none. Their edits are not whole-file versions,
so the browser turns the state back into the file.

### GET /api/drive/federation/shares/:shareId/album

The photos of an album on another server, relayed and verified: each item
is `{ file, thumbnails, fileKeyEnvelope, keyGeneration, albumEpoch }`, the
file key sealed under the album key (Drive envelope purpose 12). Content is
read through `…/files/:fileId/content` above. `404` when the owner stopped
sharing it.

### GET /api/drive/federation/shares/:shareId/files/:fileId/thumbnails/:variant

A thumbnail (`sm` or `lg`) of a file the share reaches, relayed (still
sealed under the file key) after its signed digest is checked.

### Files shared by themselves across servers

A file can be shared with someone on another server
(docs/plans/drive-file-sharing.md, slice 2). It works like a folder invite,
with a capability for that file alone. With `canEdit`, notes and place lists
are edited live through the recipient's server (see *Collaboration across
servers* below).

- **`POST /api/files/:id/federated-shares`**: owner only. **Body:**
  `{ recipientServer, recipientAccountId, shareEnvelope, canEdit }` (the
  recipient's username is taken from their server, as for folders). The envelope is a `FileShareEnvelopeV1` at the file's current
  generation, sealed to the remote account (`recipientServer` and
  `recipientAccountId`, looked up with
  `GET /api/users/by-address/:address`).
  **Response:** `201 { inviteUrl }`, of the form
  `…/invite#server=…&capability=…&kind=file`. Only the capability's hash is
  kept.
  - The file's `access` lists these recipients (`federatedShares`).
  - A rotation re-seals them (`federatedShares: [{ id, shareEnvelope }]`, to
    the same account incarnation) or removes them (`removedFederated`).
  - `PUT /api/files/:id/shares` re-seals any left behind, and `pending`
    lists files whose remote recipients wait.
- **`POST /api/drive/federation/file-shares`** (recipient's server):
  `{ server, capability }`. The server fetches the invite over the pinned
  peer, checks it is for this account and sealed by the named owner, and
  keeps the capability. The browser never gets it.
- **`GET /api/drive/federation/file-shares`**: the accepted files.
  **`GET …/file-shares/:id`**: the file as it is now on its owner's server
  (`{ file, shareEnvelope, keyGeneration, owner… }`), checked again. It must
  still be the owner first accepted; `404` once no longer shared.
- **`GET …/file-shares/:id/content`**: the content, relayed.
  **`GET …/file-shares/:id/state`**: the saved state, as above.
  **`DELETE …/file-shares/:id`**: stop seeing it.

### Collaboration across servers

Live editing of a file on another server, through your own server
(docs/plans/collab-federation.md). `BASE` is
`/api/drive/federation/shares/:shareId/files/:fileId` for a file in a shared
folder, or `/api/drive/federation/file-shares/:id` for a file shared by
itself. Each route behaves as its local counterpart under `/api/files/:id`,
with the same bodies and responses; this server relays it to the file's
server, which applies the share's permission (`canUpload` on a folder,
`canEdit` on a file) to every write.

- **`GET BASE/collab/ws`**: the collab WebSocket (same frames, `hello`,
  `stored` and `replayed` messages). Your server subscribes at the file's
  server while anyone is in the room, and pushes your frames there.
- **`GET BASE/versions`**, **`POST BASE/versions`** (multipart),
  **`GET BASE/versions/:vid/download`**, **`PATCH BASE/versions/:vid`**:
  versions. A version you save lists `remoteAuthor` (`user@server`) and is
  charged to the file's owner.
- **`POST BASE/claim-seed`**: whether your editor seeds a never-saved
  document.

### DELETE /api/drive/federation/shares/:shareId/files/:fileId

Move a file this share uploaded to the owner's trash, when `canDelete`
permits it. Exact retries are idempotent and return `204`.

---

## Drive Federation — Server-to-Server Endpoints

All `/api/fed/drive/*` routes require the unified `drive.v1` RFC 9421/9530
request signature and return an authenticated response. Except for user lookup,
they also require `Kutup-Share-Capability`; the capability is checked only
after the request's canonical origin domain has authenticated, and the share
must be bound to that same domain.

### GET /api/fed/drive/users/:username

Return `{ "username", "server", "publicKey" }` for one active local user.

### PUT /api/fed/drive/profile-keys

Signed server-to-server delivery of a profile key
(`{ sender: { server, accountId }, recipient: { server, accountId },
envelope, profileVersion }`). The sender
must be on the calling server and the recipient here, the envelope must name
both (and the recipient's current incarnation), and a share must exist
between them. The recipient's client checks the sender's signature.

### GET /api/fed/drive/accounts/:accountId

Signed: one active local account by its permanent id, answered as
`GET /api/users/by-id/:accountId` answers it (for a peer whose user holds
the account). `404` when there is none.

### GET /api/fed/drive/invite

Return the encrypted collection metadata, wrapped key, intended recipient, and
grants for the capability-authorized share.

### GET /api/fed/drive/files

List ciphertext file metadata for the capability-authorized collection.

### GET /api/fed/drive/epochs

The capability-authorized folder's key history, signed.

### GET /api/fed/drive/album

The capability-authorized album's photos, signed (see the relayed route
above). `404` when the share is not for an album. For an album share,
`GET /api/fed/drive/files/:fileId/content` reaches the album's items.

### GET /api/fed/drive/files/:fileId/thumbnails/:variant

A thumbnail of a file the capability reaches (a file in the folder, or a
photo in the album), as a signed stream with its digest.

### GET /api/fed/drive/files/:fileId/state

A note's or place list's latest saved state in the capability-authorized
folder, signed (`404` when none).

### GET /api/fed/drive/file-invite · file-content · file-state

The capability names one file shared by itself:
- `file-invite`: its record, its key sealed to the recipient, and the owner's
  identity;
- `file-content`: its current ciphertext, as a signed stream with its digest;
- `file-state`: its saved Yjs state.

A file (or its folder) in the trash answers `404`.

### GET /api/fed/drive/files/:fileId/content

Stream ciphertext with its precomputed signed content digest and exact length;
the ETag is the content's revision id. A ranged read
(docs/plans/drive-block-format.md §3) names its one range in the signed
query, `?range=a-b` (or `a-`, `-k`) and optionally `&ifRange=<etag>`;
nothing else may be in the query. The answer is `206`, signed over the
content digest of that part (at most `driveStreamResponseMaxBytes`), with
`Content-Range`, or `416`. `GET /api/fed/drive/file-content` (a file shared
by itself) takes the same query. The receiving server forwards its client's
`Range` (cut to its own part limit first) and `If-Range` this way, and
releases a part only once it is the one asked: its start, its length (which the signed digest covers) and the part
limit. `Content-Range`'s total is not signed; the reader's own metadata gives
the object's length, and its manifest fixes every byte.

### POST /api/fed/drive/files

Store one encrypted multipart upload. The exact ciphertext is hashed while it
is spooled and the digest is persisted with the file row. A stable request ID
plus authenticated request hash provides persistent idempotency. The folder
owner pays: the upload must fit their quota (less their open uploads) and the
share's `uploadQuotaBytes`, measured from the files the share uploaded. A
`fileId` already in use is `409`. The request is signed over its content
digest: the server verifies the signature first, spools and hashes the body,
and parses nothing until the digest matches. Body cap: the upload limit
(`driveUploadMaxBytes`) plus 16 MiB. A block-format blob names its
`revisionId`, checked as a local upload's.

### DELETE /api/fed/drive/files/:fileId

Move one file **this share uploaded** to the owner's trash (restorable, and
purged with its versions, assets, thumbnails and charges by the trash's own
path), under a persistent idempotent mutation result. Other files are `404`.

### Collaboration: `/api/fed/drive/collab/*`

Between the file's server (home) and an editor's server (bridge). All are
signed and carry the share's capability, except `push`, which home signs
and which names a subscription the bridge made. Bodies are JSON; frames are
base64 sealed collab frames.

- **`POST subscribe`** `{ fileId, subscriptionId }` → `{ headSeq,
  currentDocKeyId, floor, canWrite }`. Home pushes every new frame to the
  bridge from then on. The lease lasts 60 s and is renewed by subscribing
  again. **`POST unsubscribe`**, same body: the room is empty.
- **`POST push`** (home → bridge) `{ subscriptionId, fileId, frames: [{ seq,
  frame }], ephemeral: [frame], throughSeq, floor, close }`: frames in log
  order, never the bridge's own. `404` for an unknown subscription.
- **`POST frames`** `{ fileId, subscriptionId, frames: [{ sender, frame }] }`
  → `{ positions }` (null for relayed-only or refused frames). Each frame
  names its sender account, which its signature covers. Checked as local
  frames are, against the file's current keys and the share's edit
  permission, and also: the sender is the share's recipient, an account of
  the calling server, and the frame is signed with a frame key that the
  recipient's account manifest lists for the frame's device, under the
  incarnation the share was made to (docs/plans/one-device-list.md §8). The
  home fetches that manifest through the federated manifest route and keeps
  it in `remote_account_manifests`. It fetches again when a frame names a
  newer manifest sequence or a device it doesn't list, at most once a minute
  per account, and moves only forward along the account's chain. The sender
  is kept as (domain, account, device).
- **`POST log`** `{ fileId, since }` → `{ frames, throughSeq, floor }`:
  catching up.
- **`POST versions/list`** `{ fileId }`; **`GET files/:fileId/versions/:vid`**
  (a signed stream of the sealed blob); **`POST versions/create`** `{ fileId,
  author, kind, seqAtSnapshot, docKeyId, label, keepForever, blob }` (up to
  32 MiB); **`POST versions/patch`** `{ fileId, versionId, label,
  keepForever }`; **`POST claim-seed`** `{ fileId }`.

The removed `/api/fed/users`, `/api/fed/invites/*`, `/api/fed/shares/*`,
`/api/fed-proxy/*`, `/api/collections/:id/share-federated`, and
`/api/collections/fed-pubkey` routes have no compatibility handlers and return
`404`.

---

## Feedback

"Send feedback" sits at the foot of every app's sidebar. What people send
goes to this server's administrators, not to a public page: a description of
a problem often mentions files, addresses or messages. An administrator may
forward an item to the public tracker (`FEEDBACK_GITHUB_REPOSITORY`,
`owner/repo` on GitHub, default `kutupbt/kutup`, `off` for none) by opening a
prefilled issue there themselves; the server never posts to GitHub, and the
issue never names who sent it. Before it opens, the admin page warns that a
public repository shows the issue to anyone, names the repository, and lets
the administrator edit the title and text; it opens only after they confirm
they removed personal details. The public settings advertise the tracker as
`feedback.githubRepository` (absent when off), and the form offers it to
people who want to report there in public instead.

### POST /api/feedback

**Auth:** Bearer JWT. Rate limit: 10 per hour per account
(`RATE_LIMIT_FEEDBACK_PER_HOUR`); over it, `429`.

```json
{
  "kind": "bug",
  "app": "drive",
  "message": "Uploads stop at half way since this morning.",
  "details": { "version": "index-BsTFsULO", "browser": "Mozilla/5.0 …", "language": "tr-TR", "screen": "1280×800" }
}
```

`kind` is `bug`, `feature` or `other`; `app` names the app it was sent from;
`message` is 1–5000 characters. `details` is optional and takes only those
four keys, each a string of at most 300 characters: what the form showed
before sending, never the page's address (it can name a file or a person).
`204`; `400` for anything else.

---

## Admin

All admin endpoints require the `isAdmin` flag on the JWT and share a stricter per-IP rate limit (120/min, `RATE_LIMIT_ADMIN_PER_MIN`; over-limit requests return `429`).

Every mutating admin endpoint (create / update / delete user, force-disable 2FA, settings update) writes a row to the **admin audit log** — who did what to whom, when. The log is readable via `GET /api/admin/activity` below. Audit rows have no foreign keys and outlive the accounts they reference; the human-readable identities (usernames) are snapshotted into the row's `payload` at action time.

### GET /api/admin/reports

Reports on public links: open ones oldest first (default, `?status=open`), or
the latest 100 resolved (`?status=resolved`). Each carries the report
(`id`, `reason`, `details`, `link` while open, `createdAt`, `resolvedAt`,
`resolution`: `dismissed`, `removed` or `disabled`), its link (`shareId`,
`shareType`, `shareCreatedAt`, `shareRemovedAt`), the account that made it
(`ownerUserId`, `ownerUsername`, `ownerIsActive`) and
`openReportsOnLink`.

### POST /api/admin/reports/:id/dismiss

Close an open report: nothing to do. `204`; `404` for no such open report.
Logged as `report.dismiss`.

### POST /api/admin/reports/:id/remove-link

Take the reported link down (it answers `410 link_removed` from then on) and
close every open report on it. `204`; `404` for no such open report. Logged as
`share.remove`. Disabling the owner (`PUT /api/admin/users/:id` with
`isActive: false`) takes every link of theirs down and closes their reports.

### GET /api/admin/feedback

Feedback: open items oldest first (default, `?status=open`), or the latest 100
resolved (`?status=resolved`). Each carries `id`, `kind`, `app`, `message`,
`details`, `createdAt`, who sent it (`userId`, `userUsername`;
null once the account is deleted), `resolvedAt`, `resolution` (`done`,
`dismissed` or `forwarded`) and `githubUrl`.

### POST /api/admin/feedback/:id/resolve

`{ "resolution": "done" | "dismissed" | "forwarded", "githubUrl"?: "…" }`.
`githubUrl`, only with `forwarded` and optional there, must be an issue of the
configured tracker (`https://github.com/<owner>/<repo>/issues/<n>`). `204`;
`400` for an unknown resolution or another address; `404` for no such open
item. Logged as `feedback.resolve`.

### DELETE /api/admin/feedback/:id

Delete an item for good, open or resolved. `204`; `404` for no such item.
Logged as `feedback.delete`.

### GET /api/admin/users

List all registered users.

**Auth:** Bearer JWT (admin)

**Response:** Array of user objects:
```json
[
  {
    "id": "<uuid>",
    "username": "alice",
    "storageQuotaBytes": 10737418240,
    "storageUsedBytes": 524288000,
    "isAdmin": false,
    "isActive": true,
    "totpEnabled": false,
    "createdAt": "2026-03-14T12:00:00Z",
    "isProtected": false
  }
]
```

`isProtected` is `true` for the break-glass admin (the account from the `ADMIN_ACCOUNT` env var, known by its username). Protected users cannot be demoted, disabled, or deleted — the relevant mutations below return `403`.

---

### POST /api/admin/users

Create a user account (admin-initiated, bypasses registration settings). The
administrator's client makes a temporary password and registers it with OPAQUE
under a key binding it draws (`opaque/register/start` with the
administrator's session as Bearer); the server never sees the password. The
user signs in with their username and the temporary password, and is then
forced through the first-login setup flow to generate their own key bundle,
recovery phrase and password, under a key binding of their own. No email is
asked: an account signs in with its username.

**Auth:** Bearer JWT (admin)

**Request body:**
```json
{
  "username": "newuser",
  "keyBinding": "<uuid v4>",
  "opaqueRecord": "<base64>",
  "opaqueServerKeyId": 1,
  "storageQuotaBytes": 10737418240
}
```

`storageQuotaBytes` is optional and defaults to 10 GB. Returns `201 Created` `{"message": "user created"}`. `400` for a record that is not one (a password sent as it is included), `409` if the username is already taken, `409 keyBindingTaken`, `409 opaqueKeyStale`.

---

### PUT /api/admin/users/:id

Update a user. All fields are optional; only the ones present in the request are applied.

**Auth:** Bearer JWT (admin)

**Request body:**
```json
{
  "storageQuotaBytes": 21474836480,
  "isActive": true,
  "isAdmin": false
}
```

`isAdmin` promotes/demotes the user. The change is reflected in JWT claims on the user's next token refresh.

**Response:** `200 OK` `{"message": "updated"}`. `403` if the request would demote or disable the break-glass admin; `400` if it would leave zero usable admins.

---

### DELETE /api/admin/users/:id

Delete a user and all their data.

**Auth:** Bearer JWT (admin)

**Response:** `204 No Content`. `403` if the target is the break-glass admin.

---

### DELETE /api/admin/users/:id/2fa

Force-disable a user's TOTP two-factor authentication — an admin override for users locked out of their authenticator. Clears `totp_secret` and `totp_enabled` and the recovery codes, and records `twoFactorOff` in the account's security log; the account becomes password-only until the user re-enables 2FA from their Security page. Allowed on any user, including the break-glass admin.

**Auth:** Bearer JWT (admin)

**Response:** `200 OK` `{"message": "2fa disabled"}`. `404` if the user does not exist.

---

### POST /api/admin/users/:id/rotate-temp-password

Replace the temporary password of an account still in first-login state (`isFirstLogin: true`). Such an account has no E2EE key material yet, so nothing is destroyed. For an established account this returns `409` — under E2EE the server cannot reset a password without destroying the user's data; the user self-serves with the recovery phrase (`POST /api/auth/recover/grant`), or the admin wipes (below). Design: `docs/research/10-admin-password-reset.md`.

**Auth:** Bearer JWT (admin)

**Request body:** `{"grant": "kg1_…", "keyBinding": …, "opaqueRecord": …, "opaqueServerKeyId": …}` — the administrator's reset grant for this account (`reset-grant`, below), and the new temporary password registered with it under a new key binding.

**Response:** `200 OK` `{"message": "temp password rotated"}` · `403 grantInvalid` · `409` when the user has completed setup.

---

### POST /api/admin/users/:id/reset-grant

The administrator's fresh password proof (a reauth grant `for: "adminReset"`,
from this admin session) exchanged for a grant bound to this account: what
registering its temporary password and the rotation or wipe itself take.
Single use, five minutes, this admin session only.

**Auth:** Bearer JWT (admin) · **Request body:** `{"grant": "kg1_…"}`

**Response:** `{"grant": "kg1_…", "expiresAt": "<RFC 3339>"}` · `403 grantInvalid` · `404`.

---

### POST /api/admin/users/:id/wipe

Destructive account reset for a user who lost both their password and their recovery phrase (their data is cryptographically unreachable anyway). Purges every collection the user owns — files, versions, assets, S3 blobs, share links, trash — erases the key bundle, disables TOTP, revokes collab device keys and received shares, then resets the account to first-login with the supplied temp password. Username and quota survive. **Irreversible.** Refused (`403`) for the break-glass admin.

**Auth:** Bearer JWT (admin)

**Request body:** `{"grant": "kg1_…", "keyBinding": …, "opaqueRecord": …, "opaqueServerKeyId": …}` — the administrator's reset grant for this account (`reset-grant`), used before anything is purged, and the temporary password it starts again with, registered with that grant under a new key binding.

**Response:** `200 OK` `{"message": "account wiped"}`.

---

### GET /api/admin/stats

Return aggregate server statistics.

**Auth:** Bearer JWT (admin)

**Response:**
```json
{
  "totalUsers": 42,
  "activeUsers": 39,
  "totalFiles": 1234,
  "totalStorageUsedBytes": 107374182400,
  "totalCollections": 87,
  "storageTotalBytes": 536870912000,
  "storageBackendUsedBytes": 268435456000
}
```

`totalStorageUsedBytes` is the DB sum of per-account usage (`storage_used_bytes`, one pool for Drive and Chat). `storageTotalBytes` and `storageBackendUsedBytes` are the storage backend's real total capacity and on-disk usage, probed live from the SeaweedFS master (`SEAWEEDFS_MASTER_URL`); `storageTotalBytes` falls back to the `STORAGE_TOTAL_BYTES` env var, and both are `0` when no probe or env var is configured.

---

### GET /api/admin/activity

The admin audit-log feed, newest first.

**Auth:** Bearer JWT (admin)

**Query parameters:** `limit` (1–100, default 50) · `before` (cursor: return
entries with `id` lower than this — pass the previous page's `nextBefore`) ·
`actionPrefix` (for example `federation.`) · `domain` (an exact canonical
federation domain in the structured event payload). Filters compose and the
cursor remains stable.

**Response:**
```json
{
  "entries": [
    {
      "id": 7,
      "action": "user.create",
      "adminUserId": "<uuid>",
      "adminUsername": "admin",
      "targetUserId": "<uuid>",
      "targetUsername": "newuser",
      "payload": { "username": "newuser", "storageQuotaBytes": 10737418240 },
      "occurredAt": "2026-06-11T11:22:33Z"
    }
  ],
  "nextBefore": null
}
```

Actions include user/settings changes plus `federation.policy.*`,
`federation.rule.*`, `federation.peer.*`, and `federation.identity.*`. Identity
pin, authenticated rotation, quarantine, verification, and break-glass re-pin
events retain full fingerprints, sequences, and reasons but never private
signing keys or Drive capabilities. `adminUsername`/`targetUsername` are the live
identities and become `null` once the referenced account is deleted — the
`payload` snapshot keeps the trail readable. `nextBefore` is non-null while
older pages remain.

### GET /api/admin/activity/export

Export the same filtered audit stream as spreadsheet-safe UTF-8 CSV. It accepts
`before`, `actionPrefix`, and `domain`; `limit` is clamped to 1–5000 and defaults
to 1000. Cells beginning with spreadsheet formula markers are neutralized and
the response is downloaded as `kutup-admin-audit.csv`.

---

### GET /api/admin/maps · PUT /api/admin/maps

**Auth:** Bearer JWT (admin)

```json
{
  "enabled": true,
  "providers": ["openfreemap", "openstreetmap"],
  "custom": null,
  "proxy": "available",
  "cacheMegabytes": 2048
}
```

`custom` is the server's own tile server,
`{ name, kind: "vector" | "raster", url, attribution }`: a style URL, or a
tile template with `{z}`, `{x}` and `{y}`; it must also be listed in
`providers`. Maps on with no provider, a provider listed twice, or a cache
above 102,400 MB is `400`. Saving writes the `maps.settings.update` audit
entry.

---

### GET /api/admin/rate-limits · PUT /api/admin/rate-limits/{key}

**Auth:** Bearer JWT (admin)

Every rate limit the server keeps (docs/plans/admin-rate-limits.md):

```json
{
  "limits": [
    {
      "key": "login",
      "section": "accounts",
      "per": "address",
      "unit": "events",
      "windowSeconds": 60,
      "about": "Sign-in attempts (and their second factor).",
      "value": 10,
      "firstValue": 10,
      "firstFrom": "default",
      "env": "RATE_LIMIT_LOGIN_PER_MIN",
      "set": false,
      "min": 1,
      "max": 1000
    }
  ]
}
```

`unit` is `events` (in `windowSeconds`), `attempts` or `minutes`;
`firstFrom` is `default`, `environment` or `testStack`. `PUT` takes
`{ "value": 20 }`, or `{ "value": null }` to go back to the first value, and
answers the limit as it is now. A value outside `min`–`max` is `400`, an
unknown key `404`. It applies at once on this backend and within 30 seconds
on the others; each change writes a `settings.rate_limit` audit entry.

### GET /api/admin/users/{id}/limits · PUT /api/admin/users/{id}/limits/{key}

**Auth:** Bearer JWT (admin)

The settings and rate limits that limit one account, as they stand for this
one (docs/plans/settings-registry.md):

```json
{
  "settings": [{ "key": "drive_upload_max_bytes", "field": "driveUploadMaxBytes",
    "section": "drive", "unit": "bytes", "value": 1073741824, "source": "account",
    "siteValue": 10737418240, "min": 1048576, "max": 4398046511104 }],
  "rateLimits": [{ "key": "rate_limit.feedback", "limit": "feedback",
    "section": "administration", "unit": "events", "windowSeconds": 3600,
    "value": 10, "source": "default", "siteValue": 10, "min": 1, "max": 1000 }]
}
```

`source` says where `value` comes from: `account`, `site` or `default`.
`PUT` takes a setting's key or `rate_limit.<key>`, and gives the account its
own value (`{ "value": 3 }`) or takes it back (`null`); it answers the entry
as it is now. A value outside the range is `400` (never clamped), and so is a
setting or rate limit that doesn't limit one account; an unknown key is
`404`. Lowering a value below what the account already uses only stops new
growth: nothing is removed. Each change writes a `user.setting` or
`user.rate_limit` audit entry.

### GET /api/admin/settings/registry

**Auth:** Bearer JWT (admin)

Every whole-number setting, as Server settings builds its fields from it:
`{ "settings": [{ "key", "field", "section", "unit", "default", "min", "max",
"perAccount", "value", "set" }] }`. `field` is its name in
`/api/admin/settings`, `section` one of `chatMulti`, `calendar`,
`chatLinking`, `twoFactor` and `drive`, and `perAccount` whether one account
may have its own value.

---

### GET /api/admin/settings

Return current global server settings.

**Auth:** Bearer JWT (admin)

**Response:**
```json
{
  "registrationMode": "code",
  "defaultStorageQuotaBytes": 10737418240,
  "chatMailboxRetentionDays": 30,
  "chatMediaDeliveryRetentionDays": 45,
  "nameHoldDays": 180,
  "oldAddressReceiveDays": 90,
  "chatGroupLinkJoinsPerRelayGroupPerMin": 120,
  "chatGroupLinkJoinsPerRelayPerMin": 1200,
  "chatGroupCapabilitiesPerAccount": 4096,
  "chatGroupAvatarMaxBytes": 41001,
  "chatGroupAvatarStoragePerGroupBytes": 82002,
  "chatGroupAvatarPendingSeconds": 86400,
  "passVaultMaxBytes": 67108864,
  "calendarsPerAccount": 25,
  "calendarEventsPerCalendar": 25000,
  "calendarSyncBatch": 10,
  "calendarWindowDays": 400,
  "calendarEventsPage": 1000,
  "driveUploadMaxBytes": 10737418240,
  "driveVersionMaxBytes": 2147483648,
  "driveStreamMaxBytes": 10737418240,
  "driveStreamCacheBlocks": 3,
  "driveStreamReadaheadBlocks": 1,
  "driveStreamMaxConcurrent": 3,
  "driveStreamResponseMaxBytes": 5242880,
  "driveStreamBlobFallbackMaxBytes": 1073741824
}
```

The Drive settings (docs/plans/drive-block-format.md §7; clients read them
from `GET /api/drive/limits`): `driveUploadMaxBytes` and
`driveVersionMaxBytes` (1 MiB–4 TiB) are the largest upload and saved
version; `driveStreamMaxBytes` (0–4 TiB, 0 never streams) the largest file a
player streams rather than downloads first; `driveStreamCacheBlocks` (1–16),
`driveStreamReadaheadBlocks` (0–4) and `driveStreamMaxConcurrent` (1–8) shape
a stream; `driveStreamResponseMaxBytes` (4.5 MiB–16 MiB, at least one sealed 4 MiB
block) is the most one ranged answer carries, across servers too; and
`driveStreamBlobFallbackMaxBytes` (0–4 GiB) the largest file played from
memory where no service worker can stream it.

The Calendar settings: `calendarsPerAccount` (1–1000) is how many calendars
one account may own, `calendarEventsPerCalendar` how many events one
calendar may hold, `calendarSyncBatch` (1–100) the most changes in one
events sync, `calendarWindowDays` (1–3660) the longest window an events
query may ask for, and `calendarEventsPage` (10–5000) the most events on one
page.

`passVaultMaxBytes` is the largest `.kdbx` file Kutup Pass takes in an
upload: 1 MiB to 1 GiB (`400` otherwise), 64 MiB at first.

`chatGroupAvatarMaxBytes` is the largest group avatar blob this server takes
for the groups it hosts: 8233, 16425, 32809 or 41001.
`chatGroupAvatarStoragePerGroupBytes` is the most one group's avatars (the
current blob and a pending upload) may take: at least twice the largest blob
(so a group can always swap its avatar) and at most 82002.
`chatGroupAvatarPendingSeconds` is how long an upload waits for a change to
name it, 60 to 604800. The three are checked together (`400` otherwise);
`null` resets one to its first value (41001, 82002, 86400).

The two link-join budgets limit how many joins from a group link and
requests to join one relaying server's users may make each minute: to any
one group this server hosts (`chatGroupLinkJoinsPerRelayGroupPerMin`), and to
all of them together (`chatGroupLinkJoinsPerRelayPerMin`). Each is 1 to
1000000 (`400` otherwise); `null` in a `PUT` drops the stored value, so the
first value applies again: `RATE_LIMIT_CHAT_GROUP_LINK_JOINS_RELAY_GROUP_PER_MIN`
(default 120) and `RATE_LIMIT_CHAT_GROUP_LINK_JOINS_RELAY_PER_MIN` (default
1200).

`defaultStorageQuotaBytes` is the storage quota new accounts get (registered,
created by an administrator, or the bootstrap administrator); 10 GiB until an
administrator sets another. Existing accounts keep their own quota.

---

### PUT /api/admin/settings

Update global server settings.

**Auth:** Bearer JWT (admin)

**Request body:** any of the fields, at least one.
```json
{
  "registrationMode": "code",
  "defaultStorageQuotaBytes": 21474836480
}
```

`registrationMode`: `on` (anyone), `code` (with a referral code) or `off`
(nobody). A fresh database starts in `REGISTRATION_MODE` (default `off`).

`defaultStorageQuotaBytes` must be positive (`400` otherwise).

**Response:** Same shape as `GET /api/admin/settings`.

---

### Referral codes (admin)

Codes that admit a sign-up when the registration mode asks for one
(docs/plans/registration-codes.md). A code is 20 Crockford base32 characters
(100 random bits) shown once, when it is made; the server keeps only its HMAC
under a key of its own, so a database dump gives no usable code. Each change is
in the audit log (`registration_code.created`, `registration_code.revoked`).

- `POST /api/admin/registration-codes` with `{ "note": "beta testers",
  "expiresAt": "2026-11-01T00:00:00Z" | null, "maxUses": 5 | null }` (a note of
  at most 200 characters; an expiry in the future or none; 1 to 100000 uses or
  unlimited) → `201` with the code's row and `code`, the text, never returned
  again.
- `GET /api/admin/registration-codes` → every code, newest first: `{ id, hint
  (its last 4 characters), note, createdBy, createdAt, expiresAt, maxUses,
  uses, revokedAt, state }`, `state` one of `active`, `expired`, `usedUp`,
  `revoked`.
- `POST /api/admin/registration-codes/{id}/revoke` → the row, revoked at once
  (also "expire now").
- `GET /api/admin/registration-codes/{id}/uses` → `[{ userId, username,
  usedAt }]`, the accounts that signed up with it.
- `GET /api/admin/users/{id}/registration-code` → `{ codeId, hint, note,
  createdBy, usedAt }`, the code an account signed up with, or `null`.

**Auth:** Bearer JWT (admin)

---

### GET /api/admin/federation

Return the unified federation identity, feature policies, domain rules, and
persisted peer trust/discovery state. Rules remain visible while inactive.

**Auth:** Bearer JWT (admin)

```json
{
  "configured": true,
  "serverName": "chat.example.com",
  "fingerprint": "64-lowercase-hex-characters",
  "fingerprintDisplay": "grouped full fingerprint",
  "identitySequence": 0,
  "capabilities": ["chat.v2", "drive.v1", "identity.v1"],
  "globalEnabled": true,
  "features": [
    { "feature": "chat", "mode": "allowlist", "minimumTrust": "verified" },
    { "feature": "drive", "mode": "allowlist", "minimumTrust": "verified" }
  ],
  "rules": [
    {
      "domain": "friend.example",
      "feature": "chat",
      "inbound": "allow",
      "outbound": "allow",
      "trustRequirement": "inherit",
      "createdAt": "2026-07-20T10:00:00Z",
      "updatedAt": "2026-07-20T10:00:00Z"
    }
  ],
  "peers": [
    {
      "domain": "friend.example",
      "trust": "tofu",
      "sequence": 0,
      "fingerprint": "64-lowercase-hex-characters",
      "fingerprintDisplay": "grouped full fingerprint",
      "apiBase": "https://friend.example",
      "capabilities": ["chat.v2", "drive.v1", "identity.v1"],
      "firstSeenAt": "2026-07-20T10:00:00Z",
      "lastSeenAt": "2026-07-20T10:00:00Z",
      "verifiedAt": null,
      "discoveryExpiresAt": "2026-07-20T11:00:00Z",
      "quarantineReason": null,
      "pendingFingerprint": null,
      "lastDiscoveryError": null,
      "diagnostics": {
        "chatPendingTransactions": 0,
        "chatMismatchTransactions": 0,
        "driveIncomingShares": 1,
        "driveOutgoingShares": 0
      }
    }
  ],
  "operational": {
    "peerTotal": 1,
    "tofuPeers": 1,
    "verifiedPeers": 0,
    "quarantinedPeers": 0,
    "chatPendingTransactions": 0,
    "chatMismatchTransactions": 0,
    "oldestChatPendingAt": null,
    "driveIncomingShares": 1,
    "driveOutgoingShares": 0,
    "activeReplayReservations": 0
  }
}
```

`configured` reports whether the persistent v2 identity exists. Fingerprints
are always returned in full; the grouped form is display-only.

### PUT /api/admin/federation

Update the emergency stop and one feature policy:

```json
{
  "globalEnabled": true,
  "feature": "chat",
  "mode": "disabled|allowlist|blocklist|open",
  "minimumTrust": "tofu|verified"
}
```

Returns the full control-plane response, wakes the Chat outbox, and audits
`federation.policy.update`. The global stop denies every feature. A disabled
Chat feature also hides public discovery. `allowlist` requires an explicit
directional allow, `blocklist` permits inherited directions except explicit
blocks, and `open` permits every admitted direction. Admission never bypasses
the effective trust requirement.

### PUT /api/admin/federation/rules/:feature/:domain

Create or replace a rule for `chat` or `drive` and a canonical lowercase DNS
domain. The local domain cannot be added.

```json
{
  "inbound": "inherit|allow|block",
  "outbound": "inherit|allow|block",
  "trustRequirement": "inherit|tofu|verified"
}
```

Returns the full response, wakes pending Chat delivery for the domain, and
audits `federation.rule.upsert`.

### DELETE /api/admin/federation/rules/:feature/:domain

Delete the feature-scoped rule. Returns the full response, or `404` when the
rule does not exist, wakes pending Chat delivery, and audits
`federation.rule.delete`.

### POST /api/admin/federation/peers/:domain/verify

Promote the current TOFU pin to verified trust after comparing its full
fingerprint through an independent channel. Body:

```json
{ "fingerprint": "64-lowercase-hex-characters" }
```

### POST /api/admin/federation/peers/:domain/retry

Evict positive and negative discovery caches, retry authenticated discovery
through either enabled Chat or Drive capability, and wake pending Chat
delivery. The returned control-plane state exposes the new discovery result or
`lastDiscoveryError`. The outcome is audited as `federation.peer.retry`.

### POST /api/admin/federation/peers/retry

Retry up to 100 selected canonical domains independently. One failed peer does
not abort the others.

```json
{ "domains": ["one.example", "two.example"] }
```

The response contains `{domain, refreshed, error}` per peer and the complete
batch result is retained in `federation.peer.retry-bulk` audit evidence.

### GET /api/admin/federation/peers/:domain/evidence

Return the immutable accepted, superseded, and quarantined signed identity
documents preserved by the generic trust store. Each entry includes sequence,
document hash, full fingerprint, acceptance state, recorded time, and the exact
public signed document. The response also identifies the current and pending
document hashes and quarantine reason. Results are newest-first and bounded to
200 documents with `truncated: true` when older history exists. This endpoint
does not expose federation private keys or Drive capabilities.

### POST /api/admin/federation/peers/:domain/repin

Break-glass replacement for a quarantined competing identity only. It requires
the exact old fingerprint, pending new fingerprint, and domain:

```json
{
  "oldFingerprint": "64-lowercase-hex-characters",
  "newFingerprint": "64-lowercase-hex-characters",
  "confirmDomain": "friend.example"
}
```

The re-pin is persisted with administrator identity and old/new evidence; it
is not an automatic fallback for failed rotation.

---

## Devices

One device list per account (docs/plans/one-device-list.md): every app
installation is a device of the account, an entry of its signed manifest
(`AccountManifestV3`, Chat above), with a server-issued id (1..127), a
credential sent as `X-Kutup-Device: <deviceId>.<credential>`, and, for an
editing app (Drive, Office, Maps, Pass) or the CLI, the Ed25519 frame key
that signs its collaborative-edit frames. On the web, one device per sign-in
per app origin, shared by its tabs; the CLI keeps one per profile. A device's
frames count while its row and sign-in are live and the account's head
manifest lists it with its frame key; otherwise the collaboration routes
answer `403 deviceNotAuthorized` (the client registers again, it does not
sign out). A device is removed by publishing the account's next manifest
without it: its row and open sockets go. A row not yet listed is dropped
by a publication, or by the account's next device registration, after
`deviceListingGraceSeconds` (default 600). Until then it holds its id, and
it counts toward `devicesPerAccount` (a per-account setting) and the Chat
cap.

### POST /api/devices
Register an editor or CLI device of the caller's account (a Chat device
registers with `POST /api/chat/device`).
**Auth:** Bearer JWT.
**Body:** `RegisterDeviceRequestV1` `{kind: "editor"|"cli", name?, frameKey,
credential}`: the frame key (canonical base64 of an Ed25519 public key, not
a small-order point) and the device's credential (unpadded base64url of 32
random bytes; the server keeps a salted hash).
**Response 200:** `{deviceId, session}`: the lowest id no row of the account
holds, and the `session` hash its manifest entry lists. A retry with the
same credential answers the row it made. The device then lists itself in the
account's next manifest (`POST /api/chat/manifest`, with its
`X-Kutup-Device`); an account with no manifest yet gets its first, with no
Chat identity. **409 `deviceLimit`**: the account has `devicesPerAccount`
devices. **429**: `RATE_LIMIT_DEVICE_REGISTRATIONS_PER_MIN` (default 20) per
account.

### GET /api/devices
Every device of the account, of every kind: `{devices: [{deviceId, kind,
name, session, thisSignIn, listed, expired, createdAt, lastSeenAt}]}`.
`listed`: the head manifest lists it. `thisSignIn`: of the caller's sign-in.
`expired`: idle too long, dropped by the next manifest.

### GET /api/device-session
`{session}`: the hash a device of the caller's sign-in lists in its manifest
entry (Chat, above).

### POST /api/device-ticket
A single-use WebSocket ticket for the device `X-Kutup-Device` names, of any
kind, valid 60 seconds: `{ticket, expiresAt}`. Browsers can't set headers on
a socket, so the Chat socket (`?ticket=`, a Chat device's only) and the
collaboration sockets (a device with a frame key) take it.

---

## Collaborative Editing

### GET /api/files/:fileId/collab/ws
WebSocket upgrade. Auth via `?ticket=` (a device ticket, `POST /api/device-ticket`: browsers can't set custom headers on the handshake) **or** `Authorization: Bearer …` with `X-Kutup-Device`.

PreUpgrade validates: the device (a live row with a frame key, of a live sign-in, listed in the account's head manifest with that key: `403 deviceNotAuthorized` otherwise) and file access (owner OR collection-share recipient). Failures return HTTP 401/403/404 BEFORE the WS handshake completes.

A view-only recipient joins to follow edits: the server relays its presence
frames (awareness and cursors) and drops everything else it sends. Edits are
checked against the sender's rights frame by frame, and every open socket
re-checks its session and file access every 15 s, closing when either is
gone (share narrowed or removed, file or folder trashed, session signed out).
A message is at most one frame (1 MiB of plaintext plus framing); a client
sending edits faster than 50 frames/s or 1 MiB/s sustained (bursts of 500
frames / 16 MiB) is disconnected. Office edit frames stay in the log for a
day, as a buffer for peers resuming after a dropped connection.

On accept the server sends a JSON `hello` `{type, fileId, currentDocKeyId, headSeq, peers: [{account, deviceId, userId}]}` (a device id is its account's: a peer is `account` and `deviceId` together). Every binary message the server sends is a delivered frame: the sender account (`AccountRef` bytes) then the packed frame (`envelope::deliver`); a client sends bare frames, and the server names it. Client replies with JSON `{type: "resume", lastSeenSeq: K}`. Server replays binary `CollabFrame`s from seq `K+1` to head, then sends `{type: "replayed", throughSeq, floor}` (the last position replayed, and how far saved versions have trimmed the log: a client that resumed below `floor` merges the latest saved version), then enters bidirectional binary mode. After storing each document frame it sends `{type: "stored", seq}` to everyone in the file, the sender included, after the frame itself. Messages are handled in order, so a client knows every frame up to a position it has seen is applied; positions only ever go up. A saved version records the highest contiguous position its client had applied; a note's version trims the log up to it, a whole-file (office) version does not. Office editors also send `{type: "base", versionId, seq, reset}` on connect, before `resume`: the version they loaded (null: the original upload) and its position. The first claim in an empty room sets the editing session's base (and trims the log up to it); later claims get `{type: "base", versionId, seq, yours, reset: false}` back, and a tab whose claim is not `yours` reopens from the returned base; `reset: true` (after a restore) replaces the base and the server sends the other tabs `{type: "base", …, reset: true}` so they reopen. A claim must name a `kind = file` version of the file at its recorded position (or null at 0); anything else is ignored. `CollabFrameSuiteId = 1` is the canonical Rust-owned `KUTPCF3\0` format (`kutup-crypto::envelope`: the header names the sender's device id and manifest sequence; the signature covers the sender account too); the server rejects an unknown suite, malformed length, a frame of another device or naming a manifest sequence the account doesn't have, an invalid signature under the device's listed frame key, or any file/collection/epoch/document-generation mismatch.

### GET /api/files/:fileId/collab/frames and POST /api/files/:fileId/collab/frames

The collaboration log over HTTP, for a peer that does not hold a socket open:
the CLI editing notes, code files and place lists as a Yjs peer
(docs/plans/cli-yjs-sync.md). **Auth:** Bearer JWT and `X-Kutup-Device` (a
device whose frames count, as the socket's).

- `GET …?after=K&limit=` (a reader of the file) → `{ frames: [{ seq, sender,
  frame }], headSeq, floor, currentDocKeyId, mySenderSeqHigh, more }`: the
  sealed frames after position `K`, oldest first, at most 500 (`more` when
  others follow), the log's head, how far saved versions have trimmed it (a
  reader below `floor` starts from the latest saved version), the current
  document key, and this device's highest sender sequence (its next frame goes
  above it).
- `POST …` (an editor) with one sealed frame as
  `application/octet-stream` → `{ seq }`. It passes the same gate as a socket's
  frame (this device's signature, the exact file, its current key generation
  and document key, write access, a key the folder still holds) and is kept and
  sent to everyone with the file open, who merge it like any peer's edit. Only
  kept kinds: presence and scene frames are refused. `409 frameRefused` when
  the gate drops it (read the log again and rebuild), `403` without write
  access, `429` past `RATE_LIMIT_COLLAB_FRAME_POSTS_PER_MIN` (600) per device.

### PUT /api/files/:fileId/assets/:assetId

Upload one whiteboard image as multipart field `file`. The part must be a
complete `DriveEnvelopeV1` purpose-6 asset envelope for the exact live file,
collection, current collection-key epoch and path `assetId`. Asset IDs are
1–128 bytes and may not contain slash, backslash or `..`. Plaintext is capped
at 25 MiB; oversized or invalid public envelopes are rejected before quota or
object-storage mutation. **Auth:** Bearer JWT and write access. **Response:**
`204`. Assets are content-addressed and immutable: once an id is stored a
re-upload changes nothing (neither bytes nor charge) and returns `204`.

### GET /api/files/:fileId/assets/:assetId

Return the stored opaque asset envelope as `application/octet-stream`. The
client opens it with the current collection key and the same exact context;
key, file, collection, epoch, asset-ID relocation and tampering fail closed.
**Auth:** Bearer JWT and file access.

### PUT /api/files/:fileId/thumbnails/:variant

Store the file's `sm` (≤ 512 px) or `lg` (≤ 1920 px) thumbnail, replacing any
previous one of that variant. **Body:** the raw `DriveEnvelopeV1` purpose-7
thumbnail envelope (`application/octet-stream`), sealed under the file key
by the client; the server checks its public header against the exact file,
variant and current key epoch and its size against the variant cap
(64 KiB / 1 MiB plaintext) before any quota or storage change.
**Query:** `source` — the version id it was drawn from, or `original`
(default); a version of another file is refused. The size is charged to the
uploader; replacing your own thumbnail charges only the difference.
**Auth:** Bearer JWT and write access. **Response:** `204`; `400` invalid
envelope or source; `404` unknown variant; `413` too large or over quota.

### GET /api/files/:fileId/thumbnails/:variant

The stored envelope as `application/octet-stream`, with
`Cache-Control: private, max-age=31536000, immutable` — clients add
`?v={thumbnails.<variant>}` from the listing, so a URL never changes meaning
and caches hold only ciphertext. **Auth:** Bearer JWT and file access.
**Response:** `200`; `404` when there is none.

### DELETE /api/files/:fileId/thumbnails

Remove both variants and release their bytes to whoever was charged.
**Auth:** Bearer JWT and write access. **Response:** `204`.

---

## Version History

### GET /api/files/:fileId/versions
List all versions newest-first.
**Response:** array of `{id, storagePath, seqAtSnapshot, docKeyId, authorUserId, sizeBytes, label, keepForever, createdAt, kind, keyGeneration, remoteAuthor?, parentVersionId}`.
`parentVersionId` is, for a whole-file version, the version it replaced (the
file's current content when it was stored); `null` for the original upload,
for notes' states and for versions stored before it was recorded. Whole-file
saves of a file are serialized, so each version replaces the one before it;
with conditional saves (`basedOn`, below) no edit is overwritten unseen
(docs/plans/pass.md).

### GET /api/files/:fileId/versions/:vid/download
Get the encrypted snapshot bytes for a specific version. Returns
`application/octet-stream`. Headers: `X-Kutup-Doc-Key-Id`, `X-Kutup-Seq`. The snapshot uses the same typed,
file/collection/epoch-bound Drive file-blob format as an original file. There
is no snapshot-specific legacy decoder.

### PATCH /api/files/:fileId/versions/:vid
**Body:** `{label?: string, keepForever?: boolean}` — set or unset; a label
is at most 200 characters. **Auth:** write access (it changes what retention
keeps). **Response:** updated version row.

### DELETE /api/files/:fileId/versions/:vid
Delete one earlier version for good: the row and its charge go together, then
the stored object, and the author's storage is freed. **Auth:** the file's
owner or the version's author (`403` for anyone else who can see the file,
`404` otherwise). The file's newest version is its current content and cannot
be deleted (`409`), whether or not it is kept forever; a kept-forever earlier
version can be. **Response:** `204`.

`original` as the version id deletes the file's first upload (KeePass vaults
after a key change, so no earlier copy opens with the old key). Allowed for
the file's owner or the original's uploader (`403` for anyone else who can
see the file, `404` otherwise, as for a version), once a whole-file version
replaced it: `409` while it is still the current content, `404` once it is
gone. Decided under the file row's lock; the upload is marked gone and its
uploader's storage freed in one transaction, then the stored object is
deleted. Retention removes it the same way, so a delete racing retention, or
another delete, frees the storage once. **Response:** `204`.

### POST /api/files/:fileId/versions
Store a version in one request (docs/plans/drive-versions-v2.md). Multipart:
`file` — a complete typed Drive file blob, validated against the exact file,
collection and current epoch; `kind` — `file` (the whole file: office
documents, whiteboards, restored copies) or `yjs` (a note's collaboration
state); `seqAtSnapshot`, `docKeyId`; optional `label`, `keepForever`, and
`basedOn` (below).

The server measures the body and charges **that** size to the author's
quota (a client's size claim is not read), stores it as an object of its own
(`files/{id}/versions/{versionId}`), records the row, truncates
`file_update_log` up to `seqAtSnapshot` and sets the file's `updatedAt` (and
so its folder's) — one transaction; the object is removed again if the
commit fails. Under the relay's per-file lock, `seqAtSnapshot` is clamped
to the log's head before the row is stored; truncation happens only when
`docKeyId` is the file's current document key, and raises the file's log
floor to that position so the next frame continues after it. **Auth:** write access (`403` for a view-only recipient).

**Conditional saves** (`basedOn`, docs/plans/pass.md, "Saving without
overwriting"): a whole-file save made from a known version names it, as a
version id or `original`. Whole-file saves of one file are serialized; if
the file's current content is no longer that version, nothing is stored or
charged and the answer is `409 {"code": "version_conflict", "current":
"<version id | original>"}`: the client fetches the current content, merges
and saves again with `basedOn` set to it. Without `basedOn` a save is stored
as before. `basedOn` on a `yjs` state is a `400`. Federated saves pass it on
to the file's server, and its `409` back. Kutup Pass and `kutup sync` save
KeePass vaults this way.

**Response 201:** the version row, including `kind` and `parentVersionId`.
`409 version_conflict` as above. `413` over quota.

Versions are kept by the file owner's `versionRetentionDays` (see
`PATCH /api/user/me`): the last day whole, the last week one per hour, then
one per day; the newest version and `keepForever` ones always. Earlier
versions can also be deleted by hand (`DELETE` above) or in bulk by age
(`POST /api/user/storage/versions/prune`).
