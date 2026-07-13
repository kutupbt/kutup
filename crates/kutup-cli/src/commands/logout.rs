//! `kutup logout` — mirrors `cmd/logout.go`.

use anyhow::Result;

use crate::session::Store;

pub fn run(profile: &str, json: bool) -> Result<()> {
    let store = Store::open(profile)?;
    store.clear_session()?;
    if json {
        crate::output::print_json(&serde_json::json!({
            "loggedOut": true,
            "profile": profile,
        }))?;
    } else {
        println!("Logged out.");
    }
    Ok(())
}
