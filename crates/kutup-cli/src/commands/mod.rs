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
pub mod recover;
pub mod register;
pub mod rm;
pub mod share;
pub mod sync;
pub mod trash;
pub mod twofa;
pub mod upload;
pub mod version;
pub mod versions;
pub mod whoami;

use std::io::{self, IsTerminal, Write};

use anyhow::Result;

/// Prints `prompt` (no newline) to stderr — keeping stdout data-only for
/// piping — and reads a trimmed line from stdin.
pub(crate) fn prompt_line(prompt: &str) -> Result<String> {
    eprint!("{prompt}");
    io::stderr().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

/// Asks `<prompt> [y/N]` unless `yes` is set. With a non-interactive stdin
/// and no `--yes` it fails immediately (usage error) instead of hanging.
pub(crate) fn confirm(prompt: &str, yes: bool) -> Result<()> {
    if yes {
        return Ok(());
    }
    if !io::stdin().is_terminal() {
        return Err(crate::errors::UsageError(
            "confirmation required — pass --yes to run non-interactively".to_string(),
        )
        .into());
    }
    let ans = prompt_line(&format!("{prompt} [y/N]: "))?;
    confirm_answer(&ans)
}

fn confirm_answer(ans: &str) -> Result<()> {
    match ans.trim().to_lowercase().as_str() {
        "y" | "yes" => Ok(()),
        _ => Err(anyhow::anyhow!("aborted")),
    }
}

#[cfg(test)]
mod tests {
    use super::confirm_answer;

    #[test]
    fn confirm_accepts_yes_variants_only() {
        for ok in ["y", "Y", "yes", "YES", " yes "] {
            assert!(confirm_answer(ok).is_ok(), "{ok:?}");
        }
        for no in ["", "n", "no", "nope", "q"] {
            assert!(confirm_answer(no).is_err(), "{no:?}");
        }
    }
}
