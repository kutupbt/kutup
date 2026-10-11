# Contacts: keys for outside addresses, as Proton's

**Status:** planned 2026-10-11, handed over from the third session; the user
asked to follow Proton directly for automatic lookup, key history and trust
([`mail-parity.md`](mail-parity.md), [`mail.md`](mail.md) C3).

## What is missing

A contact's outside address shows only "Add OpenPGP key", even when Kutup
finds a key for it (WKD, Proton, keys.openpgp.org; `GET
/api/mail/keys/outside`), and a contact keeps one pinned key per address,
replaced on change, with no history. Mail already encrypts to a found key
without asking, as Proton does with its untrusted WKD keys.

## Proton's model

WebClients `packages/components/containers/contacts/email/`:

- `ContactEmailSettingsModal` ("Edit email settings", per address): fetches
  the address's keys from the API (`getPublicKeysEmailHelper`; WKD and
  keys.openpgp.org for outside addresses) and merges them with the keys
  pinned in the vCard (`getKeyInfoFromProperties`).
- Saving keeps only **trusted** keys, each as `ITEMn.KEY` with `PREF` 1…n;
  the first is "Used for sending". `ITEMn.X-PM-ENCRYPT` when keys are
  pinned, `ITEMn.X-PM-ENCRYPT-UNTRUSTED` when only found keys exist,
  `ITEMn.X-PM-SIGN` (encryption forces signing), `ITEMn.X-PM-SCHEME`.
  Found keys nobody trusted are never stored; they are looked up again.
- `ContactKeysTable`: Fingerprint, Created, Expires, Type, Status; badges
  WKD / KOO (source), Trusted, Used for sending, Expired, Revoked. Actions:
  Download; Use for sending (uploaded keys); Trust (found keys); Untrust
  (found and trusted); Remove (uploaded keys). Expired and revoked keys stay
  at the bottom until removed: the history.
- `ContactPGPSettings`: Encrypt (on forces Sign), Sign, PGP scheme; "trust
  one of the available keys" when found and pinned keys disagree; upload
  only when nothing was found (`canUploadKeys`).
- Mail's `ExtraPinKey` / `TrustPublicKeyModal`: "Trust key" on a received
  message adds the key.

## Kutup

- **Model:** a contact keeps several keys per address, in order (the first
  is used for sending). Encrypt, Sign and scheme move from the key to the
  address (`ContactEmail.pgp`), as Proton keeps them per email group. Old
  vCards (one key, its own `X-PM-ENCRYPT`/`X-PM-SIGN`) read the same way.
- **vCard:** written as Proton writes it, above; read in `PREF` order.
- **Signed summary:** `pinnedKeys` lists every trusted key, each with its
  address's Encrypt and Sign (the shape is unchanged).
- **Found keys:** `GET /api/mail/keys/outside` answers every usable key the
  first source that has any returns (a WKD file may hold several), each
  checked in the browser again. `docs/plans/mail.md` names the endpoint.
- **Key details:** `kutup-crypto` describes a key without refusing it
  (fingerprint, created, expires, algorithm, revoked, expired, can
  encrypt), so expired and revoked keys show in the table.
- **Contacts:** each email gets "Email settings" (Proton's modal): the key
  table with found and pinned keys together, Encrypt, Sign and, with the
  PGP settings on master, scheme; upload only when nothing was found.
- **Mail:** encrypt to the first trusted key that can encrypt (a pinned key
  wins; if all pinned keys are unusable, sending waits as now), else to a
  found key unless the address says not to (`X-PM-ENCRYPT-UNTRUSTED:false`).
  Signatures verify against every trusted key. "Trust key" on a message
  puts the key first, keeping the others as history.

## Slices

1. Crypto: describe a key; WASM; tests.
2. Server: the lookup answers all keys of its source; the plan's endpoint
   name fixed.
3. contacts-core: the model, vCard read and write, the summary, pinning
   that adds.
4. Contacts: "Email settings" with the key table and the per-address
   switches.
5. Mail: protection and verification with several keys; Trust key adds;
   per-recipient Sign and scheme.
6. Tests: crypto, vCard round trips (Proton's own cards), a live test of the
   lookup, a browser spec.
