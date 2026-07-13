//! `kutup sync` — bidirectional dir↔collection sync, with optional `--watch`.

use std::path::Path;
use std::sync::mpsc::{channel, RecvTimeoutError};
use std::time::Duration;

use anyhow::{Context, Result};
use notify::{RecursiveMode, Watcher};

use crate::context::require_session;
use crate::errors::UsageError;
use crate::syncengine::{self, SyncOptions};

#[allow(clippy::too_many_arguments)]
pub fn run(
    profile: &str,
    json: bool,
    local_dir: &str,
    collection_id: &str,
    watch: bool,
    delete: bool,
    dry_run: bool,
    poll: Option<u64>,
) -> Result<()> {
    if watch && json {
        return Err(UsageError(
            "--json is not supported with --watch (watch mode runs indefinitely)".to_string(),
        )
        .into());
    }
    if watch && dry_run {
        return Err(UsageError("--dry-run cannot be combined with --watch".to_string()).into());
    }
    if poll.is_some() && !watch {
        return Err(UsageError("--poll only applies to --watch mode".to_string()).into());
    }
    let opts = SyncOptions { delete, dry_run };

    std::fs::create_dir_all(local_dir).context("create local dir")?;

    if !watch {
        return do_sync(profile, json, local_dir, collection_id, &opts);
    }

    // Initial sync before entering the watch loop.
    if let Err(e) = do_sync(profile, false, local_dir, collection_id, &opts) {
        eprintln!("sync error: {e:#}");
    }

    let (tx, rx) = channel();
    let mut watcher = notify::recommended_watcher(move |res| {
        let _ = tx.send(res);
    })?;
    watcher
        .watch(Path::new(local_dir), RecursiveMode::Recursive)
        .context("watch dir")?;

    match poll {
        Some(secs) => eprintln!(
            "Watching {local_dir} for changes (+ polling the server every {secs}s)… (Ctrl+C to stop)"
        ),
        None => eprintln!("Watching {local_dir} for changes… (Ctrl+C to stop)"),
    }

    loop {
        // Wait for a local fs event — or, with --poll, a timeout that
        // triggers a pass so remote-only changes are picked up too.
        let ev = match poll {
            Some(secs) => match rx.recv_timeout(Duration::from_secs(secs)) {
                Ok(ev) => Some(ev),
                Err(RecvTimeoutError::Timeout) => None,
                Err(RecvTimeoutError::Disconnected) => return Ok(()),
            },
            None => match rx.recv() {
                Ok(ev) => Some(ev),
                Err(_) => return Ok(()), // channel closed
            },
        };
        if let Some(ev) = ev {
            let ev = match ev {
                Ok(ev) => ev,
                Err(e) => {
                    eprintln!("watcher error: {e}");
                    continue;
                }
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
        } else {
            eprintln!("\nPolling for remote changes…");
        }
        if let Err(e) = do_sync(profile, false, local_dir, collection_id, &opts) {
            eprintln!("sync error: {e:#}");
        }
    }
}

/// Skips events that only touch names the sync engine itself ignores
/// (dotfiles — including our own `.kutup-tmp-*` — and `~` backups).
fn relevant(ev: &notify::Event) -> bool {
    ev.paths.iter().any(|p| {
        p.file_name()
            .and_then(|n| n.to_str())
            .map(syncengine::keep_local_name)
            .unwrap_or(false)
    })
}

fn do_sync(
    profile: &str,
    json: bool,
    local_dir: &str,
    collection_id: &str,
    opts: &SyncOptions,
) -> Result<()> {
    let ctx = require_session(profile)?;
    let result = syncengine::sync(
        &ctx.client,
        &ctx.store,
        &ctx.session,
        local_dir,
        collection_id,
        opts,
    )?;
    if json {
        crate::output::print_json(&serde_json::json!({
            "dryRun": opts.dry_run,
            "uploaded": result.uploaded,
            "downloaded": result.downloaded,
            "conflicts": result.conflicts,
            "deletedLocal": result.deleted_local,
            "deletedRemote": result.deleted_remote,
            "skippedDeletions": result.skipped_deletions,
            "errors": result.errors,
        }))?;
    } else {
        let prefix = if opts.dry_run {
            "Dry run (nothing changed)"
        } else {
            "Sync complete"
        };
        let mut line = format!(
            "{prefix}: ↑ {} uploaded, ↓ {} downloaded, ⚠ {} conflicts",
            result.uploaded, result.downloaded, result.conflicts
        );
        if result.deleted_local + result.deleted_remote > 0 {
            line.push_str(&format!(
                ", ✗ {} deleted",
                result.deleted_local + result.deleted_remote
            ));
        }
        if result.skipped_deletions > 0 {
            line.push_str(&format!(
                ", – {} deletions skipped (use --delete)",
                result.skipped_deletions
            ));
        }
        println!("{line}");
        for e in &result.errors {
            eprintln!("  error: {e}");
        }
    }
    if !result.errors.is_empty() {
        anyhow::bail!("sync finished with {} error(s)", result.errors.len());
    }
    Ok(())
}
