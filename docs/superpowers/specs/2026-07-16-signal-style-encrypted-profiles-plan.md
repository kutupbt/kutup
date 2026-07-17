# Signal-style encrypted profiles

## Goal

Add changeable, non-unique display names and optional avatars without turning
either into an account identifier or exposing profile plaintext to Kutup
servers. Profile sharing follows Signal's relationship rules rather than a
manual visibility matrix.

## Reference behavior

The design follows the current Signal Desktop and Server implementations:

- a device-generated random 32-byte profile key;
- AES-256-GCM profile encryption with a fresh 12-byte nonce per item;
- display-name padding to the first fitting Signal bucket (53 or 257 bytes);
- a separately encrypted avatar;
- an opaque, versioned server profile selected with a value derived from the
  profile key;
- profile-key harvesting from ordinary E2EE messages and explicit invisible
  profile-key update messages;
- automatic sharing with people the user messages or accepts, and later with
  accepted encrypted groups.

Kutup accounts use canonical `username@server` addresses rather than Signal
ACIs. Consequently, Kutup domain-separates its profile version and access-key
derivations with HKDF-SHA-256 instead of claiming Signal wire compatibility.

## Wire and server contract

`ChatContent` gains an optional `profileKey` containing the sender's current
32-byte key inside the existing Signal-protocol ciphertext. A
`profileKeyUpdate` content kind carries no visible message body and is never
rendered. Normal outgoing messages include the key whenever profile sharing is
allowed.

The server stores versioned profile rows per account with one owner-visible
current head. Old ciphertext versions remain capability-readable during key
distribution, matching Signal's rotation safety:

- derived profile version;
- revision and source device for deterministic convergence;
- padded encrypted display name;
- optional encrypted avatar;
- account-master-key-wrapped profile key for the owner's linked devices;
- SHA-256 verifier for the derived profile access capability.

The owner may read and advance that head while authenticated. Peers fetch only
the public ciphertext fields by presenting both the derived version and access
key. Federated reads use the existing signed server-to-server channel and pass
the access key as a capability; neither server receives the profile key or
plaintext.

## Durable client state

The shared chat database stores one local profile and one cached peer profile
per canonical address. Local edits, key rotations, publication state, and the
need to redistribute the key are committed before networking. A failed upload
or profile-key update is retried by normal reconciliation.

A new linked device unwraps the random profile key with a key derived from the
account master key, then decrypts the owner's server profile. This preserves a
random Signal-style profile key while keeping the server unable to recover it.

## Sharing and revocation rules

- The first outgoing message/request includes the sender's profile key.
- Accepting an incoming request sends an invisible profile-key update back.
- Replies and normal messages continue to harvest the current key.
- Profile edits publish first, then send profile-key updates to accepted and
  pending-outgoing conversations.
- Blocking commits the block locally, rotates and republishes the profile key,
  and redistributes the new key only to remaining authorized contacts.
- Rejected, blocked, and merely pending-incoming peers do not receive the key.
- A pending first upload, edit, or rotation key is never attached to messages;
  publication must complete before distribution.
- Old version ciphertext remains readable with its old capability, but rotation
  prevents fetching future changes; it cannot erase names or images a peer
  previously received or copied.

Encrypted group state will call the same profile-key distribution primitive
for accepted members. No plaintext directory or alias layer is introduced.

## Web milestone

The chat header exposes a profile editor with a required display name and an
optional resized avatar. Conversation lists, requests, and headers prefer the
decrypted profile while retaining the canonical address as secondary identity.
Avatar inputs are normalized in the browser and bounded before entering the
shared core.

## Verification

- protocol serialization and crypto/padding tests;
- SQLite and IndexedDB round trips/migrations;
- server owner, capability, rotation, and federation tests;
- shared-engine request/accept/update/block-rotation tests;
- frontend service/component tests;
- live Playwright coverage for editing a profile, viewing it in a request,
  accepting, updating it, and preventing blocked peers from receiving updates.
