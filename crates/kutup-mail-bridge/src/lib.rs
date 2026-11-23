//! Kutup's desktop mail bridge (docs/plans/mail-bridge.md): IMAP and SMTP on
//! this machine for desktop mail apps, mail kept end-to-end encrypted. The
//! CLI's `kutup mail-bridge` runs it; this crate holds its parts, testable
//! without a server.
//!
//! - [`index`]: the mailboxes, UIDs and flags an app sees, in one SQLCipher
//!   database under the bridge's local key.
//! - [`imap`]: one IMAP session, sans I/O, answered from a backend.

pub mod fuzzing;
pub mod imap;
#[cfg(feature = "index")]
pub mod index;
pub mod model;
