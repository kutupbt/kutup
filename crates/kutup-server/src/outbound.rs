//! `OUTBOUND_DELIVERY` (on by default): whether this server sends anything
//! to another host under its own identity. Off, a restored copy of a server
//! (scripts/restore-drill.sh) runs and answers, but delivers nothing to the
//! outside world: no federation request (every kind goes through
//! `federation::transport`), no mail handed to Stalwart for sending
//! (`mail::submit`), no push notification (`web_push`); and the workers that
//! would send (the federation and mail outboxes, forwarding, the Drive digest
//! backfill, the custom-domain DNS sweep) do not start, so what they had
//! queued stays queued instead of failing.

use std::sync::atomic::{AtomicBool, Ordering};

static ENABLED: AtomicBool = AtomicBool::new(true);

/// Set once at startup from the configuration.
pub fn set_enabled(on: bool) {
    ENABLED.store(on, Ordering::SeqCst);
}

/// Whether outbound delivery is on.
pub fn enabled() -> bool {
    ENABLED.load(Ordering::SeqCst)
}

/// A send refused because outbound delivery is off.
#[derive(Debug, thiserror::Error)]
#[error("outbound delivery is off (OUTBOUND_DELIVERY=false): {0} not sent")]
pub struct Held(pub &'static str);

/// `Ok` when outbound delivery is on; otherwise names what was held.
pub fn check(what: &'static str) -> Result<(), Held> {
    if enabled() {
        Ok(())
    } else {
        Err(Held(what))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The switch itself is process-wide, and other tests send while this
    // one runs, so only the refusal's wording is tested here.
    #[test]
    fn a_held_send_names_the_setting() {
        let held = Held("a test send").to_string();
        assert!(held.contains("OUTBOUND_DELIVERY=false"), "{held}");
        assert!(held.contains("a test send"), "{held}");
    }
}
