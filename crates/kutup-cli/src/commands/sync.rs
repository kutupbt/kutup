//! `kutup sync` — bidirectional dir↔collection sync, with optional `--watch`.
//! Mirrors `cmd/sync.go`.

use std::path::Path;
use std::sync::mpsc::{channel, RecvTimeoutError};
use std::time::Duration;

use anyhow::{Context, Result};
use notify::{RecursiveMode, Watcher};

use crate::context::require_session;
use crate::syncengine;

pub fn run(
    profile: &str,
    json: bool,
    local_dir: &str,
    collection_id: &str,
    watch: bool,
) -> Result<()> {
    if watch && json {
        return Err(crate::errors::UsageError(
            "--json is not supported with --watch (watch mode runs indefinitely)".to_string(),
        )
        .into());
    }
    std::fs::create_dir_all(local_dir).context("create local dir")?;

    if !watch {
        return do_sync(profile, json, local_dir, collection_id);
    }

    // Initial sync before entering the watch loop.
    if let Err(e) = do_sync(profile, false, local_dir, collection_id) {
        eprintln!("sync error: {e:#}");
    }

    let (tx, rx) = channel();
    let mut watcher = notify::recommended_watcher(move |res| {
        let _ = tx.send(res);
    })?;
    watcher
        .watch(Path::new(local_dir), RecursiveMode::NonRecursive)
        .context("watch dir")?;

    eprintln!("Watching {local_dir} for changes… (Ctrl+C to stop)");

    loop {
        let ev = match rx.recv() {
            Ok(Ok(ev)) => ev,
            Ok(Err(e)) => {
                eprintln!("watcher error: {e}");
                continue;
            }
            Err(_) => return Ok(()), // channel closed
        };
        if !relevant(&ev) {
            continue;
        }
        // Debounce: wait until 2s pass with no further events.
        loop {
            match rx.recv_timeout(Duration::from_secs(2)) {
                Ok(_) => continue,
                Err(RecvTimeoutError::Timeout) => break,
                Err(RecvTimeoutError::Disconnected) => return Ok(()),
            }
        }
        eprintln!("\nChange detected, syncing…");
        if let Err(e) = do_sync(profile, false, local_dir, collection_id) {
            eprintln!("sync error: {e:#}");
        }
    }
}

/// Skips events that only touch hidden (`.`-prefixed) or temp (`~`-suffixed) files.
fn relevant(ev: &notify::Event) -> bool {
    ev.paths.iter().any(|p| {
        p.file_name()
            .and_then(|n| n.to_str())
            .map(|b| !b.starts_with('.') && !b.ends_with('~'))
            .unwrap_or(false)
    })
}

fn do_sync(profile: &str, json: bool, local_dir: &str, collection_id: &str) -> Result<()> {
    let ctx = require_session(profile)?;
    let result = syncengine::sync(
        &ctx.client,
        &ctx.store,
        &ctx.session,
        local_dir,
        collection_id,
    )?;
    if json {
        crate::output::print_json(&serde_json::json!({
            "uploaded": result.uploaded,
            "downloaded": result.downloaded,
            "conflicts": result.conflicts,
            "errors": result.errors,
        }))?;
    } else {
        println!(
            "Sync complete: ↑ {} uploaded, ↓ {} downloaded, ⚠ {} conflicts",
            result.uploaded, result.downloaded, result.conflicts
        );
        for e in &result.errors {
            eprintln!("  error: {e}");
        }
    }
    if !result.errors.is_empty() {
        anyhow::bail!("sync finished with {} error(s)", result.errors.len());
    }
    Ok(())
}
