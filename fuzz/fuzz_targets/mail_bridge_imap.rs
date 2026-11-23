#![no_main]

//! A mail app's bytes through the desktop bridge's IMAP session
//! (docs/plans/mail-bridge.md, B1): imap-next's framing and parsing, then the
//! bridge's command handling. Whatever comes, nothing panics and the session
//! keeps answering (kutup_mail_bridge::fuzzing, which `cargo test` also runs
//! briefly).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    kutup_mail_bridge::fuzzing::session_bytes(data);
});
