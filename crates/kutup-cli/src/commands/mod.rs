//! CLI command implementations. Each module mirrors the matching `cmd/*.go`.

pub mod color;
pub mod devices;
pub mod download;
pub mod login;
pub mod logout;
pub mod ls;
pub mod mkdir;
pub mod mv;
pub mod pubshare;
pub mod register;
pub mod rm;
pub mod share;
pub mod sync;
pub mod upload;
pub mod version;
pub mod versions;
pub mod whoami;

use std::io::{self, Write};

use anyhow::Result;

/// Prints `prompt` (no newline) and reads a trimmed line from stdin.
pub(crate) fn prompt_line(prompt: &str) -> Result<String> {
    print!("{prompt}");
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}
