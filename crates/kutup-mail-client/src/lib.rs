//! Kutup Mail's client core (docs/plans/mail-bridge.md, B0): the rules the
//! web app's `mail-core` applies in TypeScript, in Rust for the desktop
//! bridge (`kutup mail-bridge`) and, later, the native Mail apps.
//!
//! It does no I/O. A caller fetches what the server answers and what this
//! device remembers (its identity pins, the highest key-list sequence it has
//! seen), and these functions decide. The rules and their fixtures
//! (`tests/fixtures/*.json`) are shared with `mail-core`'s tests, so the two
//! cannot drift apart.
//!
//! - [`keys`]: a Kutup address's keys, trusted only as far as its signed
//!   key lists (and the pin list) say (`mail-core/keys.ts`).
//! - [`protection`]: how mail to one recipient is protected
//!   (`mail-core/protection.ts`).
//! - [`send`]: who gets which copy of a message (`sendDraft`).
//! - [`open`]: a stored message opened, byte-exact (`storedMessage`).
//! - [`meta`]: a send's readable fields, read from a message an app built.
//! - [`cache`]: the bridge's on-disk cache of opened messages, sealed block
//!   by block.

pub mod cache;
pub mod keys;
pub mod meta;
pub mod open;
pub mod protection;
pub mod send;
