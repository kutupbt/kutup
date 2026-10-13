# Revisions of sealed values

**Status:** built (clean-slate item (j), October 2026); the cross-device part
below is a follow-up, not built.

Some values the account keeps on the server are replaced over time, and the
server can read none of them: contact cards, mail folder, label and filter
names, and the identity pin list. Kutup Pass vault secrets join them in the
Pass follow-up of the same release. The server could still hand back an
older copy (one it kept), or store one device's edit over another's. Each of
these values therefore carries a revision.

## The revision

- **Where:** in the sealed value's header, in clear, and covered by the AEAD's
  associated data, so the server can read it but not change it. Opening a
  value returns its revision.
  - Contact cards (`KUTCC2`), mail names (`KUTMN2`) and identity pin lists
    (`KUTIP2`): `magic ‖ suite ‖ revision ‖ nonce ‖ ciphertext`.
  - A contact's summary signature binds the card's revision too, so the
    server cannot pair a summary with another card.
  - Account envelopes of a mutable purpose carry it after the object id.
- **What:** a time in unix milliseconds. A new value is sealed at
  `max(now, highest seen + 1, base + 1)`. A value that is deleted and later
  made again with the same id is newer than anything seen before it: a
  contact imported again keeps its vCard UID, and Mail chooses folder ids
  itself. A tombstone kept by the server would not do here, because the
  server could drop it.
- **Padding:** cards and names are padded to a multiple of 256 bytes (`0x80`
  then zeros), so a name's length no longer shows.

## The server: compare-and-swap

The server reads the revision from the sealed value and never from a second
field. It stores a new value only on top of the revision the writer started
from:

- contacts and the pin list take `baseRevision`;
- folder, label and filter renames take `baseNameRevision`.

The new revision must be above the base. A write that started from another
revision gets `409` with `code: "revision_conflict"` and the current
revision. The web apps then read the value again and apply the edit once
more (`kutup-server` `revisions.rs`). The Contacts editor does not retry:
the person sees that the contact changed elsewhere, so their form is never
laid over another device's change.

## The client: highest seen

Every client remembers the highest revision it has seen of each value and
refuses an older one:

- on the web, `RevisionGuard` in `@kutup/crypto`, kept per account in
  IndexedDB;
- in the CLI, a file per profile;
- in the Chat core, in memory.

Revisions are not secret (the server stores them in clear), so the web store
keeps them unencrypted.

## Limits

These are the same limits identity pins always had:

- **A device with no history** trusts the first revision it reads: a new
  browser, site data cleared, or a private window that refuses IndexedDB. It
  protects from then on.
- **A clock that runs behind** cannot overwrite a value another device wrote
  with a later time until it has read that value; then it writes above it.
  A write that started from an older read gets the `409` and reads again.
- **A clock that runs ahead** writes high revisions. Every device that reads
  them continues above them. A device that never read the value would write
  with its own clock, but the compare-and-swap refuses that write because it
  started from an older base, so the device reads first.

## Follow-up: protection across devices

Each device knows only what it has seen. A server could still show a device
that has never seen a newer value an older one, or show two devices
different histories, as long as it stays consistent towards each device.

The next step is a revision index for the whole account:

- a list of (value, revision) pairs signed by the account authority and
  stored by the server;
- every device checks a value against the index, and writes the index on
  top of the index revision it read (the same compare-and-swap);
- a device keeps the highest index revision it has seen, so the server
  cannot roll the index back to it.

Two parts are still open:

- Refusing a server that forks the index between two devices that never
  compare notes. Options are devices gossiping the index head through Chat
  (Note to Self), or a transparency log in the style of Signal's Key
  Transparency.
- The cost of signing the index on every change.

Both belong to the key hierarchy work ("NOT TODAY" in the clean-slate list),
and the index will be designed with it.
