# Contacts (Phase B)

**Status:** B1–B3 done 2026-10-09; B4 (pickers in Chat, Drive and Photos) next. Phase B of
[`../research/17-mail-calendar-contacts.md`](../research/17-mail-calendar-contacts.md),
after [`mail-address-keys.md`](mail-address-keys.md).

## Goal

One address book for the whole account, at `contacts.kutup.dev`, that every
app reads: Mail's recipient field, Chat's people, Drive's and Photos' share
pickers, and later Calendar's invitees. Names and email addresses are
readable by the server (decision 1 of the design); everything else about a
person is end-to-end encrypted.

## What Proton does

From WebClients (`packages/shared/lib/contacts/`, `interfaces/contacts/`,
`packages/components/containers/contacts/`):

| Proton | Meaning |
|---|---|
| **Contact** | `{ ID, Name, UID, CreateTime, ModifyTime, ContactEmails, LabelIDs, Cards }` |
| **Cards** | a contact is split into vCard parts: type `3` encrypted and signed (phones, addresses, notes, everything else), type `2` signed but readable (`FN`, `UID`, `EMAIL`, pinned keys `KEY` with `X-PM-ENCRYPT`, `X-PM-SIGN`, `X-PM-SCHEME`), type `0` clear (`CATEGORIES`) |
| **ContactEmails** | the server's readable index of each address: `Email`, `Name`, `LabelIDs`, `Order`, `LastUsedTime`. Autocomplete, groups and spam allow-lists run on it |
| **Groups** | labels with a name and colour, attached to contact emails |
| **Screens** | no separate Contacts website: a contacts widget inside Mail (search, list, groups) and a details modal / edit modal (name, emails with keys, phones, addresses, other fields), import and export of `.vcf`, merge of duplicates |
| **vCard library** | `ical.js` |

## How Kutup maps it

| Proton | Kutup |
|---|---|
| cards encrypted to and signed with the user's PGP key | Kutup-owned formats in `kutup-crypto` (`contact_card`): the private part sealed with XChaCha20-Poly1305 under a **contacts key** derived from the master key; the readable part signed with Ed25519 by the **account authority**. Kutup's rule is that Rust owns persistent formats, and contacts never leave the account, so there is no OpenPGP interoperability to keep. Import and export stay standard vCard |
| type 2 signed vCard | **`ContactSummaryV1`**, canonical JSON: `uid`, `name`, `emails[]` (address, label), `groups[]`, pinned keys. Canonical JSON (like `file_metadata`) lets the server check exactly what it indexes instead of parsing vCard |
| type 3 encrypted vCard | **`ContactCardV1`**: the full vCard 4.0 (RFC 6350) text, sealed and bound to the account and contact UID |
| ContactEmails | `contact_emails` rows the server writes from the verified summary |
| labels as groups | `contact_groups` (name, colour) and memberships per contact |
| widget inside Mail | its own app at `contacts.kutup.dev`, with Proton's screens; Mail later embeds the same list as a picker |

### Why the summary is signed

A server could otherwise rewrite a contact's readable part (swap an address,
add a pinned key) and the client would believe it. The account authority
signs the summary bytes; every client checks the signature against the
account's own authority before showing or using a contact, as Proton checks
the type 2 card.

### Verified people

For Kutup users, verification already exists: a pin on the account authority
(gray, green and red shields) kept by Chat and Drive. Phase B shows a contact's
Kutup address with that account's state where the app holds the pin. A
contact-held copy of the pin, so every app sees the same shield without asking
Chat, is part of slice B4. For outside PGP users, the summary pins their key
fingerprint (`pinnedKeys`), as Proton's `KEY` field does. Mail (C3) uses it.

## Data

- `contacts`: id, user id, uid (unique per user), name, summary (canonical
  JSON), summary signature, sealed card, revision, created, updated. Charged
  to the storage pool.
- `contact_emails`: contact id, user id, address (lowercase), label,
  position, last used. Indexed by user and address prefix for autocomplete.
- `contact_groups`: id, user id, name, colour, position.
- `contact_group_members`: contact id, group id.

## API

- `GET /api/contacts?cursor=&limit=`: summaries, signatures and sealed cards,
  ordered by name, paged.
- `POST /api/contacts`: create `{ summary, signature, card }`; the server
  verifies the signature with the account authority, checks the canonical
  summary and its limits, and writes the emails index.
- `PUT /api/contacts/{id}`: replace, with the expected revision (409 on
  conflict, as Drive's edits are).
- `DELETE /api/contacts/{id}`; `POST /api/contacts/delete` for many.
- `POST /api/contacts/import`: up to 500 at once, all or nothing.
- `GET /api/contacts/emails?q=&limit=`: autocomplete over name and address,
  for Mail, Chat, Drive and Calendar pickers.
- Groups: `GET/POST/PUT/DELETE /api/contacts/groups`, membership through the
  contact's summary (`groups[]`), so it is signed too.

## App

`contacts.kutup.dev` joins the app family: its own origin, the app switcher,
one sign-in through the session fork, the shared design system, English and
Turkish. Screens follow Proton's contact widget and modals:

- a list with search (name and address), letter grouping, group filter and
  multi-select;
- a person page: name, photo, emails (with the Kutup or PGP key state),
  phones, addresses, organisation, birthday, notes, other fields;
- create and edit in one form, with repeatable fields;
- groups: create, rename, colour, delete, add and remove people;
- import `.vcf` (one or many cards, with a preview and duplicate warning) and
  export all or selected as `.vcf`;
- "Add to contacts" from Chat, Drive sharing and later Mail, always by the
  user's action.

vCard text is read and written with `ical.js`, as Proton does, in the
browser only.

## Slices

1. **B1 crypto:** `contact_card` in `kutup-crypto`: contacts key derivation,
   canonical summary encode/decode with limits, authority signature, sealed
   card bound to account and UID; WASM; vectors.
2. **B2 server:** migration, the API above with verification, revision
   conflicts, autocomplete, groups, pool accounting.
3. **B3 app:** the `contacts` app (hosts, compose, fork, switcher), list,
   person page, editor, groups, import and export; browser specs.
4. **B4 everywhere:** the pickers in Chat, Drive and Photos read contacts and
   offer "Add to contacts"; the shield shared through contacts.
