//! `kutup logout` — mirrors `cmd/logout.go`.

use anyhow::Result;

use crate::session::Store;

pub fn run(profile: &str) -> Result<()> {
    let store = Store::open(profile)?;
    store.clear_session()?;
    println!("Logged out.");
    Ok(())
}
