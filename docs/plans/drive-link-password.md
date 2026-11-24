# Drive: link password and expiry

**Status:** built on `feat/drive-link-password` (2026-11-23). Item 1 of
[`drive-parity.md`](drive-parity.md)'s gaps ("Link password" ❌, "Link
expiry" 🟡) and item 3 of [`photos-parity.md`](photos-parity.md)'s: one
design for Drive folder links, file links (Office documents too) and album
links. Follows Proton Drive (`PublicLinkSettingsModal.tsx`,
`publicPage/PublicPagePassword.tsx`, `store/_shares/useShareUrl.ts`).

## What Proton does

- A link's **password** is the 12-character generated part in the URL
  fragment, plus the custom password when one is set
  (`SharedURLFlags.GeneratedPasswordIncluded | CustomPassword`). The URL
  never changes when a password is added, changed or removed.
- The share's session key is encrypted with a key derived (bcrypt,
  `computeKeyPassword`) from that whole password and a per-link salt
  (`SharePasswordSalt`, `SharePassphraseKeyPacket`). Changing the password
  re-encrypts it; the content keys stay.
- The server gates everything behind **SRP** on the whole password
  (`UrlPasswordSalt`, `SRPVerifier`): without the proof a viewer gets
  nothing, so guesses are online and the server can limit them.
- The whole password is also encrypted to the creator (`Password`), so the
  owner's settings dialog shows the current custom password.
- The **settings dialog**: an expiry toggle with a date (end of that day,
  at most 90 days ahead) and a "Require password" toggle with a password
  field (at most 50 characters); "Save changes" sends both; closing with
  changes asks "Discard changes?".
- The **public page** asks "This link is password protected" with one
  password field before anything is shown.

## Kutup today

- `drive_public_shares` holds the target key (folder key at
  `collection_key_epoch`, or a file key at that generation) sealed under the
  **link key** (`collection_key_envelope`, Drive envelope purposes 5/11),
  and the link key sealed for the owner under their Drive root
  (`owner_link_key_envelope`, purpose 9). The URL is `/s/<token>#v1.<link
  key>`: the token is the server's capability, the fragment never reaches it.
- A folder or file re-key re-wraps the new key under each link's key
  (`POST /drive/collections/{id}/rotate`, `POST /drive/files/{id}/rotate`,
  `PUT /drive/files/{id}/shares`), the owner opening the link key from
  purpose 9.
- `expires_at` is stored and enforced on every read; `POST
  /api/v1/drive/public-links` takes `expiresInHours` (1 hour to 10 years, a
  constant); no dialog sets it and nothing changes it later.

## Design

### Keys (`kutup-crypto::link_password`)

The fragment value becomes the link's **secret** `S` (32 bytes, unchanged
format `#v1.`); the key the target is sealed under is the **link key**
`L`. Without a password `L = S`, exactly as today, so every existing link
keeps working. With a password:

- `stretched = Argon2id(NFC(password), salt, params)`: 16-byte random salt
  per password, parameters stored per link (V1: 64 MiB, 3 passes, one lane,
  the account password's cost); an opener refuses parameters outside
  8 MiB–256 MiB and 1–10 passes, so a server can't make a page allocate
  without bound.
- `HKDF-SHA256(salt = kutup/drive-link-password/v1, ikm = S ‖ stretched)`
  expands to a **wrap key** (info `wrap` ‖ link id) and a **proof** (info
  `proof` ‖ link id). Both need the URL *and* the password, as Proton's
  generated + custom password.
- `L` is a fresh random key, sealed under the wrap key as Drive envelope
  purpose 14 `PublicLinkPasswordKey` (object = link id, parent = owner,
  revision = the link's key revision).
- The server stores `verifier = SHA-256(kutup/drive-link-password/verifier/v1 ‖ proof)`.
  The server never sees the password or `S`, so it can't test a guess
  against the verifier; someone with the URL can't get the verifier or the
  purpose-14 envelope, so every guess is a request the server counts.
- The owner keeps `S ‖ password` sealed under their Drive root as purpose 15
  `PublicLinkSecret` (padded like names), to copy the URL and show the
  password in the dialog as Proton does; purpose 9 keeps holding `L`, so
  every re-key path stays as it is.

Setting or changing a password picks a new `L` and re-seals the target key
under it at the current epoch/generation; removing it sets `L = S` again.
Each change raises the link's **key revision**; the re-key routes take each
link's `keyRevision` (absent = 1) and refuse a stale one with 409, so a
re-key sealed under an old `L` (another device, the CLI) can't put the
target back under the public `S`.

### Server

One additive migration (`20261203000000_drive_link_password`) on
`drive_public_shares`: `key_revision` (default 1), `password_salt`,
`password_operations`, `password_memory`, `password_verifier`,
`password_link_key_envelope`, `owner_secret_envelope`, with a CHECK that
they are all set or all null.

- `PUT /api/v1/drive/public-links/{id}/password` (owner): `fromKeyRevision`,
  `keyEpoch`, the target key under the new `L`, purpose 9 for `L`, and
  `password` (`salt`, `operations`, `memory`, `verifier`, `linkKeyEnvelope`,
  `ownerSecretEnvelope`) or null to remove. In one transaction, the target
  row locked; the envelope must be at the current epoch/generation.
- `PUT /api/v1/drive/public-links/{id}/expiry` (owner): `expiresAt`
  (RFC 3339) or null. Expiry must be in the future and at most the site
  setting `drive.public_link_max_expiry_days` ahead (see "Expiry cap");
  `expiresInHours` on create uses the same setting.
- `GET /api/v1/drive/public-links/{token}/password` (anonymous): the link
  id, salt and parameters, or 404 for a link without one.
- Every anonymous read through a password link needs `X-Kutup-Link-Proof`,
  as Proton gates every read behind its SRP session: the link itself, its
  files, its key history, its album, and its files' content (download,
  ranges, streams), state, whiteboard pictures and thumbnails. None answers
  `401 linkPassword`, a wrong one `401 linkPasswordWrong`, too many `429
  linkPasswordLocked` with `Retry-After`. The web sends the proof through
  an API-client interceptor (every `/drive/public-links/{token}…` call of an
  unlocked link) and, for content, through the block reader's request
  headers (`DriveBlockSource.headers`), which downloads, the Office and
  Photos pages and the service-worker streams all go through.
- Wrong proofs: see "Wrong passwords" below.
- The owner's listings (folder access, file access) add `keyRevision`,
  `hasPassword` and `ownerSecretEnvelope`; `GET /api/v1/drive/limits` adds
  `publicLinkMaxExpiryDays` and `publicLinkPasswordMaxChars` (site setting
  `drive.public_link_password_max_chars`, default 50 as Proton).

### Web

- `drive-ui/LinkSettingsDialog.tsx`: Proton's dialog (expiry toggle + date,
  password toggle + field with show/hide, Save, discard confirmation),
  opened from a link's row in the folder access list, the file share dialog
  (Drive, Office, Photos selection, Maps) and the album share dialog.
- `drive-core/linkSettings.ts`: set/change/remove the password, set the
  expiry, and the link's URL (from purpose 15 when it has a password).
- Public pages (`editors/public/share.ts` for Drive and Office,
  `photos/public/publicAlbum.ts`): on `linkPassword` they show
  `PublicLinkPassword` (Proton's page: "This link is password protected"),
  derive in WASM, and send the proof with the gated reads.

### CLI

The CLI's folder re-key sends each link's `keyRevision`. `kutup share
--password/--expires` and opening a password link from `kutup pubshare` are
on the roadmap.

## Wrong passwords: what Proton does, what Kutup does

**Proton** (WebClients, `usePublicAuth.ts`, `usePublicLink.ts`,
`api/helpers/withApiHandlers.ts`, `retryHandler.ts`): a wrong password is
the SRP error `2026`, shown as the notification "Incorrect password. Please
try again." with the form kept. Throttling is the server's (closed source):
a `429` is handled by the shared API layer, which waits `Retry-After` and
retries when the wait is short, else fails; abuse can also bring the human
verification challenge (`9001`). Nothing in the client locks a link for
everyone.

**Kutup:** no lock on the link itself (anyone with the URL could set one off
for every viewer). Wrong proofs count per link and address in
`rate_counters` (`drive.rate.link_password_failures`, `Per::LinkAndAddress`,
10 an hour) and per address over every link in memory
(`drive.rate.link_password_address_failures`, 30 an hour), both editable.
Past either, that address gets `429 linkPasswordLocked` with `Retry-After`
(and `retryAfterSeconds`) until its window ends; other addresses still open
the link. Every try is reserved in both counts before its proof is checked
(the link and address's row in its own short transaction, the address
limiter in memory), so a parallel burst gets no more checks than the
limits; a right proof gives its reservations back, a wrong one keeps them. The page says Proton's "Incorrect password. Please try again."
and, locked, "Too many attempts. Please try again in N minutes." from
`Retry-After`; the session client neither refreshes on the link's `401`s nor
retries its `429`. No human-verification step: Kutup has no CAPTCHA.

## Expiry cap

`drive.public_link_max_expiry_days` is 0 at first: no cap, links may never
expire, as Proton's. Above 0 it caps the expiry and every link expires: one
made without an expiry gets the cap, `PUT …/expiry` refuses null
(`expiryRequired`), and the dialog keeps the expiry on with the cap as its
last day. The cap applies to links made or changed from then on: setting or
lowering it leaves existing links' expiry (or none) as it is until their
owner changes it.

## Reports on password links

As Proton's report form, the reporter may give the link's password with the
link; it is stored like the link (`drive_public_link_reports.link_password`,
only with the link, only while the report is open, erased on every
resolution) and shown to administrators beside it.

## Rolling back

The down migration drops the columns but cannot put a protected link's
target back under its URL secret: the target stays sealed under the separate
link key L, and the owner's copy (purpose 9) holds L, so "copy link" after a
rollback builds `#v1.<L>`, a link that opens without the password. Before
rolling back, owners remove passwords (or the links); after it, every link
that had one is unprotected. Not engineered around.

## Not changed: the content key

Setting a password re-seals the target's key under a new link key but does
not rotate the folder or file key itself, as Proton's password change keeps
the share's session key. Someone who opened the link before the password
keeps what they downloaded and the key; with every read gated they get no
new bytes through the link.

## Where Kutup differs from Proton

- Argon2id (Kutup's password KDF) instead of bcrypt, and a verifier bound
  to the URL secret instead of SRP: the URL secret already keeps the
  verifier out of the server's reach, which is what SRP's zero-knowledge
  step buys Proton, so Kutup needs no SRP group or second round trip.
- Expiry has no cap by default (Proton's links may also never expire; its
  date picker stops at 90 days); an administrator can set one.
- No human-verification challenge after repeated wrong passwords.

## Security review (2026-11-24)

An independent review read the branch twice before it merged (#434). It
found no route that gives a URL holder names, keys or the verifier, and no
offline guessing for the server. What it did find, all fixed before merge:

First round:
- **Medium.** Clearing the password field and pressing Save, with
  "Require password" still on, sent an empty password, which the client
  treated as "remove": the link became open to anyone with the URL. An empty
  field is now invalid; only the toggle removes a password.
- **Low.** Setting a password locked the link row, then the target; folder
  and file re-keys lock the target, then the link. Two at once could
  deadlock (a 500). Setting a password now locks the target first.
- A correct password took the per-link counter's row lock and rolled it
  back, so every viewer of a busy link queued on one row; the count is now
  read first and written only for a wrong password.
- The maximum expiry did not stop "never"; 0 now means no cap, and any cap
  also refuses links that never expire, for links made or changed after it
  is set.
- If the owner's copy of the password failed to open, the dialog showed the
  link as having none; it now shows an error.

Decided by the operator after that round: every read is gated, as Proton
(downloads, ranges, streams, state, assets, thumbnails), and wrong
passwords follow Proton (no lock on the link itself, which a URL holder
could use to shut out every viewer; per link and address, then per address,
with Retry-After).

Second round, on those changes:
- **Medium.** The wrong-password counters were checked before the proof and
  added to after it, so many parallel wrong guesses from one address all got
  checked. A try is now reserved first and given back when the password was
  right, in the database and in the address limiter; a live test fires 40
  parallel wrong proofs at a limit of 2 and sees at most 2 checked.
- **Low-medium.** Blocking a reported link kept the report's link and
  password, which the table's CHECK refuses: the block failed with a 500 and
  the password stayed stored. Blocking now erases both, as every other
  resolution does.
