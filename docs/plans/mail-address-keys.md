# Mail address keys (Phase A)

**Status:** planned 2026-10-09. Phase A of
[`../research/17-mail-calendar-contacts.md`](../research/17-mail-calendar-contacts.md).
Branch `feat/mail-address-keys`.

## Goal

Every Kutup account gets an email address, `username@<server name>`, with an
OpenPGP key that other Kutup users can trust through the account they already
verify, and that the rest of the world can find through WKD. Nothing sends or
receives mail yet: this phase lays the keys Mail, Contacts and Calendar build
on.

## What Proton does

From WebClients (`packages/shared/lib/keys/`, `interfaces/Address.ts`,
`constants.ts`):

| Proton | Meaning |
|---|---|
| **Address** | an email address of the user (`Email`, `Type`, `Status`, `Receive`, `Send`, `Order`), with a list of keys |
| **Address key** | an OpenPGP key per address. v4 Curve25519 (EdDSA primary, ECDH Curve25519 subkey); v6 keys can sit beside it |
| **Primary** | exactly one key per address is primary: it signs and receives new mail. Older keys stay to decrypt old mail |
| **Token** | each address key's private part is locked with a random passphrase, the token, encrypted to the user key and signed |
| **Flags** | `NOT_COMPROMISED = 1` (may verify), `NOT_OBSOLETE = 2` (may encrypt to), `EMAIL_NO_ENCRYPT = 4`, `EMAIL_NO_SIGN = 8` |
| **Signed key list** | per address, JSON `[{Primary, Flags, Fingerprint, SHA256Fingerprints}]`, signed by the primary address key and committed to Key Transparency |
| **Key lookup** | `GET /core/v4/keys/all?Email=` for Proton users; WKD for the world |
| **Settings** | Settings → Encryption and keys: addresses, their keys (fingerprint, algorithm, created, primary, flags), export, import, mark obsolete or compromised |

## How Kutup maps it

| Proton | Kutup |
|---|---|
| user key | the account master key (random, wrapped by password and recovery phrase) |
| token, encrypted to the user key | a typed `AccountEnvelopeV1` under the master key, new purpose `MailAddressPrivateKey = 5`; its plaintext binds the address and fingerprint (below) |
| OpenPGP private key locked with the token | the same OpenPGP secret key, unlocked inside the envelope (the envelope is the lock; no second S2K passphrase) |
| signed key list, committed to Key Transparency | **`MailKeyListV1`**, one per address, hash-chained and signed by the **account authority**, the key the `AccountManifestV1` already binds. Kutup's existing pins (gray, green, red shields) therefore cover mail keys, with no second verification and no transparency log in V1 |
| flags | the same bits and meanings, so imported Proton habits and docs carry over |
| key lookup | `GET /api/mail/keys?email=` for Kutup users (local and, later, federated); WKD for the world |

## Address

- One address per account in Phase A: `username@<server name>` (the Chat
  `serverName`, `kutup.dev` in production). This is the same string as the
  Chat and Drive address, so one identifier means one person in every app.
- The login email is separate and unchanged. An account may log in as
  `admin@kutup.dev` while its address is `admin@kutup.dev` or anything else;
  the two are not tied.
- An account without a username has no address until it picks one.
- Aliases and custom domains are Phase E. The model holds several addresses
  from the start so they need no migration.

## Keys

Generated in `kutup-crypto` with rPGP (`pgp = "=0.21.0"`), the exact shape
Proton uses for v4 keys so every OpenPGP client reads them:

- primary: Ed25519 (`EdDSALegacy`), certify and sign;
- subkey: Curve25519 ECDH (`Curve25519Legacy`), encrypt communications and
  storage;
- user ID: `username <username@kutup.dev>`;
- preferences: AES-256, AES-128 / SHA-512, SHA-256 / no compression, ZLIB;
  features: MDC (SEIPDv1). SEIPDv2 and v6 keys wait until common clients
  read them.

Spike, 2026-10-09: rPGP generated this shape, encrypted and signed, and built
for `wasm32-unknown-unknown`. GnuPG 2.4.7 decrypted rPGP's message and
reported a good signature, and rPGP decrypted GnuPG's reply. GnuPG warned
that AES-256 was missing from the key's preferences, hence the preference
list above.

### Envelope payload

`MailAddressPrivateKeyV1`, canonical binary, sealed in
`AccountEnvelopeV1 { purpose: MailAddressPrivateKey }`:

```text
"kutup/mail-address-key/v1\0" ‖ len‖address ‖ fingerprint (20 bytes, v4) ‖ len‖secret key (binary OpenPGP TSK)
```

Opening checks that the address and fingerprint match the row it came from
and that the parsed key's fingerprint equals the bound one. A server that
swaps envelopes between addresses or keys is caught.

### Signed key list

`MailKeyListV1`, one chain per address, canonical binary like the account
manifest, signed with Ed25519 by the account authority:

```text
"kutup/mail-key-list/v1\0" ‖ account ‖ incarnation id ‖ authority key id ‖ address ‖ sequence ‖ previous hash? ‖ issued at
  ‖ count ‖ [ fingerprint (v4, 20 bytes) ‖ sha256 (32 bytes) ‖ primary (u8) ‖ flags (u32) ] sorted by fingerprint
```

- Exactly one primary per list; flags use Proton's bits.
- A reader takes the account's verified manifest chain (already pinned for
  Chat and Drive), checks the list is signed by that manifest's authority
  and incarnation, and checks the list's own chain: sequence + 1, previous
  hash, no rollback, no fork. An unexpected authority means the existing red
  shield.
- **Why not a manifest V2:** `AccountManifestV1` belongs to Chat's core
  (devices build it, `/api/chat/manifest` publishes it, federated servers
  verify it). A new version would make every Chat client and every
  federated server change in lockstep, and an un-upgraded peer would refuse
  the account. A separate list signed by the same authority gives the same
  trust and leaves Chat and federation untouched, as Proton keeps its signed
  key lists apart from the account.

## Server

- `mail_addresses`: id, user id, address (unique, lowercase), status,
  created at.
- `mail_address_keys`: id, address id, fingerprint (unique), SHA-256
  fingerprint, binary public key, private-key envelope, primary, flags,
  created at. One primary per address (partial unique index).
- `mail_key_lists`: address id, sequence, canonical bytes, signature, hash;
  the full history, append-only.
- Migration: one address row per account that has a username, with no key.
  Keys come from clients (the server never holds a private key).
- API:
  - `GET /api/mail/addresses`: the caller's addresses with keys and
    envelopes.
  - `POST /api/mail/addresses/{id}/keys`: add a key `{ publicKey, envelope,
    primary, keyList }`. The server parses the public key (rPGP, public
    operations only), checks the user ID and fingerprint, checks that the key
    list chains onto the stored one and lists exactly the stored keys plus
    this one, verifies its signature against the account's authority key,
    and stores key and list in one transaction.
  - `GET /api/mail/keys?email=`: the public keys of a Kutup address with
    its signed key list (and its history, for clients catching up).
  - **WKD**, direct method on the server name:
    `/.well-known/openpgpkey/hu/{z-base-32 of SHA-1 of the local part}?l=…`
    returns the binary public keys of that address, and
    `/.well-known/openpgpkey/policy` exists. nginx routes `/.well-known/openpgpkey/`
    on `kutup.dev` to the backend.

## Client

- **Sign-up** generates the address key with the other keys and sends
  public key, envelope and the first signed key list in the registration
  bundle.
- **Existing accounts** are upgraded once, on the next sign-in in any app:
  if the account has an address without a primary key, the client generates
  one, seals it, signs the first key list and uploads them. The upgrade is
  idempotent and safe in two tabs at once (the server accepts the first
  list for a sequence; the loser reloads and finds the key present).
- **Account → Settings → Addresses and keys** (Proton's "Encryption and
  keys"): the address, its keys with fingerprint, algorithm, created date,
  primary and flags, a QR-free fingerprint display for out-of-band checks,
  and "Download public key" (armored). Key import, rotation, and marking
  obsolete or compromised come with Mail (C3), not as unwired buttons now.
- The fork list gains `mail`, `calendar` and `contacts` with their app
  origins when those apps exist, not before.

## Tests and gates

- `kutup-crypto`: unit tests and checked-in vectors
  (`tests/vectors/mail-address-key-v1.json`): a fixed key, its envelope
  opening, wrong-address and wrong-fingerprint refusals, key-list signing
  bytes and chain checks, and a fixed encrypt/decrypt pair. The same vectors run in WASM.
- GnuPG interop test in CI where `gpg` exists: import the public key, encrypt
  to it, and decrypt in Rust; decrypt a Rust message in GnuPG.
- Server: API tests, including a swapped envelope, a mismatched user ID, a
  second primary, a key list that does not chain, and one signed by
  another account's authority.
- Browser specs: a new account shows its address and key in Account; an
  existing account gets its key on sign-in; WKD returns a key whose
  fingerprint matches.
- [`../cryptographic-dependencies.md`](../cryptographic-dependencies.md)
  records rPGP, its audits (Radically Open Security 2024-12, ETH analysis
  2024-03, Open Tech Fund 2019), and that RSA appears only on public
  operations with outside keys (the known Marvin side channel needs a private
  RSA key, which Kutup never holds).

## Slices

1. **A1 crypto:** rPGP in `kutup-crypto`, address-key generation, the
   envelope payload, the signed key list, WASM bindings, vectors, GnuPG
   interop, dependency record.
2. **A2 server:** tables, migration, the three endpoints, key-list
   verification and storage, WKD and its nginx route.
3. **A3 client:** sign-up and upgrade, Account → Addresses and keys, browser
   specs.
