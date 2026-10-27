# Chat's own crypto into kutup-crypto (proposed)

Code-only items 1 and 2 of [wipe-unification.md](wipe-unification.md): the
last large body of crypto outside the canonical crate moves into it, and the
apps that aren't Chat stop loading the Chat runtime. No format changes, and no
wipe.

## Today

`crates/kutup-chat-core` (a separate Cargo root, with its own lockfile and
RustCrypto versions) builds formats of its own on `chacha20poly1305`,
`hkdf` and `sha2` directly:

- `profile.rs` (1,285 lines): profile keys, the `KUTPPE1` profile envelope
  (the encoder; the parser is in chat-proto), the account profile sealed under
  the master key, and peer profile lookups.
- `call_link.rs` (838 lines): call-link keys, the sealed link name, info and
  messages, and joined meetings sealed under the master key.
- `group_link.rs` and `group_invite.rs`: the group link's sealed fields.
- `db/store_cipher.rs` (407 lines): the Chat store's own sealing at rest.

The web apps that aren't Chat load the whole Chat WASM (11 MB, 3.35 MB gzip)
only for five profile calls:
- `accountProfileKey`, `profileLookup` and `profileOpenPeer` in drive-core's
  `people.ts`, which Drive, Maps, Photos and Office use;
- `accountProfileOpen` and `accountProfileSeal` in the Account app's settings.

## Proposal

1. **Vectors first.** Before any code moves, record today's output of each
   format as a vector in `crates/kutup-crypto/tests/vectors/`: profile
   envelope and keys, account profile, call-link name/info/message, joined
   meeting, group link fields, store cipher. They're made with fixed keys and
   nonces from the current chat-core code. The moved code must reproduce them
   byte for byte; that is what "no format change" means here.
2. **Move, on the primitives.** Each format becomes a kutup-crypto module
   (`profile`, `call_link`, `group_link`, `store_cipher`) built on
   `kutup_crypto::primitives` (`Aead`, `Kdf`, `Hasher`, the one RNG), not on
   RustCrypto types. Labels stay as they are, byte for byte. W6.3's registry
   (the second session's `labels.rs`) picks them up when it lands.
   - chat-core keeps its types and engine, and calls kutup-crypto for the
     crypto. Its direct `chacha20poly1305`/`hkdf`/`sha2` dependencies go
     where nothing else uses them.
   - The `KUTPPE1` encoder and parser end up together, in kutup-crypto, with
     chat-proto re-exporting what the protocol types need.
3. **The profile calls from the crypto WASM.** kutup-crypto-wasm exports the
   five profile calls with the same arguments and results. `people.ts` and
   the Account app's settings switch to `@kutup/crypto`, so Drive, Account,
   Maps, Photos and Office no longer import `@kutup/chat-core/wasm`.
   - Checked by the build: no `chat-wasm` in those apps' `dist/`.
   - The crypto WASM's size budget (`check-wasm-size`) grows by the profile
     code, a few tens of KB.

## Slices

Two PRs into master, each with its own vectors:

1. **Profiles** (items 1 and 2's win): `profile` into kutup-crypto, the five
   WASM calls, the apps switched. Size M.
2. **Links and the store cipher:** `call_link`, `group_link`/`group_invite`,
   `store_cipher`. Size M. Only chat-core and the Chat app see it.

## Tests

- Vectors: Rust (kutup-crypto) and WASM (`test-crypto-wasm.mjs`) for every
  moved format, made before the move.
- chat-core's own tests unchanged and green, including the WASM Chat tests.
- Web gate. The Account profile and Drive people specs (and the Chat
  specs, which still use the moved code through chat-core) in the browser.
- Bundle check: the non-Chat apps' builds hold no Chat WASM.

## Decisions wanted

(a) Two PRs as above, profiles first, so the 11 MB win lands early.
(b) Labels move unchanged now; renaming any of them to W6.3's grammar is
    the second session's W6.3, not this move (a renamed label is a format
    change).
