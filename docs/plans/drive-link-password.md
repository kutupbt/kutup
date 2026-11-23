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

One additive migration (`20261201000000_drive_link_password`) on
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
  setting `drive.public_link_max_expiry_days` (default 3660, the old
  constant) ahead; `expiresInHours` on create uses the same setting.
- `GET /api/v1/drive/public-links/{token}/password` (anonymous): the link
  id, salt and parameters, or 404 for a link without one.
- The anonymous reads that reveal what a link holds — the link itself, its
  files, its key history, its album — need `X-Kutup-Link-Proof` on a
  password link: none answers `401 linkPassword`, a wrong one `401
  linkPasswordWrong`, and too many wrong ones `429 linkPasswordLocked`.
  The blob routes (download, state, assets, thumbnails) stay as they are:
  they need a file id, which only those gated reads give, and serve
  ciphertext under keys only the password opens.
- Wrong proofs are counted in `rate_counters` per link
  (`drive.rate.link_password_failures`, default 30 an hour, `Per::Link`) and
  per address in memory (`drive.rate.link_password_address_failures`,
  default 10 an hour), both admin-editable like every rate limit.
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

## Where Kutup differs from Proton

- Argon2id (Kutup's password KDF) instead of bcrypt, and a verifier bound
  to the URL secret instead of SRP: the URL secret already keeps the
  verifier out of the server's reach, which is what SRP's zero-knowledge
  step buys Proton, so Kutup needs no SRP group or second round trip.
- The blob routes are not gated (see above); Proton gates every read.
- Expiry keeps the site's maximum (10 years by default) rather than
  Proton's fixed 90 days; an administrator can lower it.
