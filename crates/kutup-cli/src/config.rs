//! Per-profile data directory resolution. Mirrors the Go CLI's use of
//! `xdg.DataFile("kutup/<profile>")` (`$XDG_DATA_HOME/kutup/<profile>` on Linux,
//! the platform-appropriate data dir elsewhere).

use std::path::PathBuf;

use anyhow::{Context, Result};

/// Returns (creating if necessary) the data directory for `profile`.
pub fn data_dir(profile: &str) -> Result<PathBuf> {
    let base = dirs::data_dir().context("could not determine the user data directory")?;
    let dir = base.join("kutup").join(profile);
    std::fs::create_dir_all(&dir).with_context(|| format!("create data dir {}", dir.display()))?;
    restrict_dir_perms(&dir);
    Ok(dir)
}

#[cfg(unix)]
fn restrict_dir_perms(dir: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn restrict_dir_perms(_dir: &std::path::Path) {}
