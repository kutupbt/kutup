//! `kutup pass` commands on a vault's groups, attachments and the vault as a
//! whole (docs/plans/pass-parity.md, "CLI"), as `keepassxc-cli` has them:
//! `mkdir`, `rmdir`, `mv`, `attachment-export`, `attachment-import`,
//! `attachment-rm`, `db-info`, `export` and `import`. Each change goes
//! through `kutup_pass::edit` and is saved as a Drive version based on the
//! one read, merged with a save that landed first, as the website's.

use std::fs;
use std::io::{IsTerminal, Read as _, Write as _};
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use base64::Engine as _;
use kutup_pass::edit::{apply, KdfInput, Op};
use kutup_pass::import::Provider;
use kutup_pass::keepass::db::GroupId;
use kutup_pass::view::{attachment, group_in_recycle_bin};
use serde::Serialize;

use crate::commands::login::{current_password, reauth_grant};
use crate::commands::pass_entries::{find_entry, find_group, group_path, now, open_vault, Opened};
use crate::errors::{NotFound, UsageError};
use crate::output::print_json;

fn applied(opened: &mut Opened, op: &Op) -> Result<Option<String>> {
    apply(&mut opened.db, op, now())
        .map(|a| a.id)
        .map_err(|e| anyhow!("{e}"))
}

fn said(json: bool, value: serde_json::Value, text: &str) -> Result<()> {
    if json {
        print_json(&value)
    } else {
        eprintln!("{text}");
        Ok(())
    }
}

/// A group's path, for messages.
fn path_of(opened: &Opened, group: GroupId) -> String {
    group_path(&opened.db, Some(group)).join("/")
}

// ------------------------------------------------------------ groups

/// `mkdir`: a new group at `path` (`Group/Sub/New`); its parent must be there.
pub fn mkdir(profile: &str, json: bool, vault: &str, path: &str) -> Result<()> {
    let mut opened = open_vault(profile, vault)?;
    let trimmed = path.trim_matches('/');
    let (parent, name) = match trimmed.rsplit_once('/') {
        Some((parent, name)) => (parent, name),
        None => ("", trimmed),
    };
    if name.is_empty() {
        return Err(UsageError("give the group's name, as Group/Sub/New".into()).into());
    }
    let parent = find_group(&opened.db, parent)?;
    if find_group(&opened.db, trimmed).is_ok() {
        return Err(UsageError(format!("{trimmed} is there already")).into());
    }
    let id = applied(
        &mut opened,
        &Op::CreateGroup {
            parent_id: parent.uuid().to_string(),
            name: name.to_owned(),
        },
    )?;
    opened.save()?;
    said(
        json,
        serde_json::json!({ "uuid": id, "path": trimmed }),
        &format!("Added group {trimmed}."),
    )
}

/// `rmdir`: a group (with what it holds) to the recycle bin; for good, with
/// `force`, inside the bin or with it off.
pub fn rmdir(profile: &str, json: bool, vault: &str, path: &str, force: bool) -> Result<()> {
    let mut opened = open_vault(profile, vault)?;
    let group = find_group(&opened.db, path)?;
    if group == opened.db.root {
        return Err(UsageError("the top group can't be removed".into()).into());
    }
    let bin_on = opened.db.meta.recyclebin_enabled.unwrap_or(true);
    let for_good = !bin_on || group_in_recycle_bin(&opened.db, group);
    if for_good && !force {
        return Err(UsageError(
            "this deletes the group and all it holds for good (it is in the recycle bin, or the bin is off): add --force"
                .into(),
        )
        .into());
    }
    applied(
        &mut opened,
        &Op::DeleteGroup {
            id: group.uuid().to_string(),
        },
    )?;
    opened.save()?;
    said(
        json,
        serde_json::json!({ "uuid": group.uuid().to_string(), "forGood": for_good }),
        if for_good {
            "Deleted for good."
        } else {
            "Moved to the recycle bin."
        },
    )
}

/// `mv`: an entry, or a group (with what it holds), into the group
/// `to` (`Group/Sub`; empty for the top group).
pub fn mv(profile: &str, json: bool, vault: &str, what: &str, to: &str) -> Result<()> {
    let mut opened = open_vault(profile, vault)?;
    let target = find_group(&opened.db, to)?;
    let entry = find_entry(&opened.db, what).ok();
    let group = find_group(&opened.db, what)
        .ok()
        .filter(|g| *g != opened.db.root);
    let (op, uuid) = match (entry, group) {
        (Some(_), Some(_)) => {
            return Err(UsageError(format!(
                "{what} names an entry and a group: give the entry's UUID"
            ))
            .into())
        }
        (Some(entry), None) => (
            Op::MoveEntry {
                id: entry.uuid().to_string(),
                group_id: target.uuid().to_string(),
            },
            entry.uuid().to_string(),
        ),
        (None, Some(group)) => {
            // Never into itself or below itself.
            let mut at = Some(target);
            while let Some(id) = at {
                if id == group {
                    return Err(UsageError("a group can't move into itself".into()).into());
                }
                at = opened.db.groups.get(&id).and_then(|g| g.parent);
            }
            (
                Op::MoveGroup {
                    id: group.uuid().to_string(),
                    parent_id: target.uuid().to_string(),
                },
                group.uuid().to_string(),
            )
        }
        (None, None) => return Err(NotFound(format!("no entry or group {what}")).into()),
    };
    applied(&mut opened, &op)?;
    opened.save()?;
    let into = path_of(&opened, target);
    said(
        json,
        serde_json::json!({ "uuid": uuid, "to": into }),
        &format!(
            "Moved to {}.",
            if into.is_empty() {
                "the top group"
            } else {
                &into
            }
        ),
    )
}

// ------------------------------------------------------------ attachments

/// Where a command's file output goes: a file (created 0600), or stdout
/// only when asked for or not a terminal.
fn write_out(bytes: &[u8], out: Option<&Path>, stdout: bool, what: &str) -> Result<()> {
    match out {
        Some(path) => {
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options.mode(0o600);
            }
            let mut file = options
                .open(path)
                .with_context(|| format!("create {} (it must not exist yet)", path.display()))?;
            file.write_all(bytes)?;
            eprintln!("Wrote {what} to {}.", path.display());
            Ok(())
        }
        None => {
            let mut handle = std::io::stdout().lock();
            if handle.is_terminal() && !stdout {
                return Err(UsageError(format!(
                    "{what} would go to the terminal: give --out FILE, or --stdout to print it"
                ))
                .into());
            }
            handle.write_all(bytes)?;
            handle.flush()?;
            Ok(())
        }
    }
}

/// `attachment-export`: an entry's attachment, to a file or stdout.
pub fn attachment_export(
    profile: &str,
    vault: &str,
    entry: &str,
    name: &str,
    out: Option<&Path>,
    stdout: bool,
) -> Result<()> {
    let opened = open_vault(profile, vault)?;
    let id = find_entry(&opened.db, entry)?;
    let bytes = attachment(&opened.db, &opened.db.entries[&id], name)
        .ok_or_else(|| NotFound(format!("no attachment {name} on {entry}")))?;
    write_out(bytes, out, stdout, &format!("attachment {name}"))
}

/// `attachment-import`: a file as an entry's attachment; replacing one of
/// the same name only with `force`.
pub fn attachment_import(
    profile: &str,
    json: bool,
    vault: &str,
    entry: &str,
    name: &str,
    file: &Path,
    force: bool,
) -> Result<()> {
    let mut opened = open_vault(profile, vault)?;
    let id = find_entry(&opened.db, entry)?;
    if opened.db.entries[&id].attachments.contains_key(name) && !force {
        return Err(UsageError(format!(
            "{entry} has an attachment {name} already: add --force to replace it"
        ))
        .into());
    }
    let size = fs::metadata(file)
        .with_context(|| format!("read {}", file.display()))?
        .len();
    if size > kutup_pass::edit::MAX_ATTACHMENT_BYTES as u64 {
        return Err(UsageError("an attachment is at most 50 MiB".into()).into());
    }
    let bytes = fs::read(file).with_context(|| format!("read {}", file.display()))?;
    applied(
        &mut opened,
        &Op::AddAttachment {
            entry_id: id.uuid().to_string(),
            name: name.to_owned(),
            data: base64::engine::general_purpose::STANDARD.encode(&bytes),
        },
    )?;
    opened.save()?;
    said(
        json,
        serde_json::json!({ "uuid": id.uuid().to_string(), "attachment": name, "bytes": bytes.len() }),
        &format!("Attached {name} ({} bytes).", bytes.len()),
    )
}

/// `attachment-rm`: removes an entry's attachment (kept in the entry's history).
pub fn attachment_rm(
    profile: &str,
    json: bool,
    vault: &str,
    entry: &str,
    name: &str,
) -> Result<()> {
    let mut opened = open_vault(profile, vault)?;
    let id = find_entry(&opened.db, entry)?;
    if !opened.db.entries[&id].attachments.contains_key(name) {
        return Err(NotFound(format!("no attachment {name} on {entry}")).into());
    }
    applied(
        &mut opened,
        &Op::RemoveAttachment {
            entry_id: id.uuid().to_string(),
            name: name.to_owned(),
        },
    )?;
    opened.save()?;
    said(
        json,
        serde_json::json!({ "uuid": id.uuid().to_string(), "removed": name }),
        &format!("Removed {name}."),
    )
}

// ------------------------------------------------------------ the vault

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Info {
    file_id: String,
    file_name: String,
    name: String,
    description: String,
    cipher: String,
    kdf: Option<KdfInput>,
    entries: usize,
    groups: usize,
    recycle_bin: bool,
    in_recycle_bin: usize,
}

/// `db-info`: the vault's name, encryption and size.
pub fn db_info(profile: &str, json: bool, vault: &str) -> Result<()> {
    let opened = open_vault(profile, vault)?;
    let db = &opened.db;
    let in_bin = db
        .entries
        .values()
        .filter(|e| group_in_recycle_bin(db, e.parent))
        .count();
    let info = Info {
        file_id: opened.file_id.clone(),
        file_name: opened.name.clone(),
        name: db.meta.database_name.clone().unwrap_or_default(),
        description: db.meta.database_description.clone().unwrap_or_default(),
        cipher: format!("{:?}", db.config.outer_cipher_config),
        kdf: KdfInput::of(&db.config.kdf_config),
        entries: db.entries.len() - in_bin,
        groups: db.groups.len().saturating_sub(1),
        recycle_bin: db.meta.recyclebin_enabled.unwrap_or(true),
        in_recycle_bin: in_bin,
    };
    if json {
        return print_json(&info);
    }
    println!("File:          {} ({})", info.file_name, info.file_id);
    println!("Name:          {}", info.name);
    if !info.description.is_empty() {
        println!("Description:   {}", info.description);
    }
    println!("Cipher:        {}", info.cipher);
    match &info.kdf {
        Some(KdfInput::Argon2id {
            memory_mib,
            iterations,
            parallelism,
        }) => {
            println!("Key derivation: Argon2id, {memory_mib} MiB, {iterations} iterations, {parallelism} lanes")
        }
        Some(KdfInput::Argon2d {
            memory_mib,
            iterations,
            parallelism,
        }) => {
            println!("Key derivation: Argon2d, {memory_mib} MiB, {iterations} iterations, {parallelism} lanes")
        }
        Some(KdfInput::AesKdf { rounds }) => println!("Key derivation: AES-KDF, {rounds} rounds"),
        None => println!("Key derivation: unknown"),
    }
    println!("Entries:       {}", info.entries);
    println!("Groups:        {}", info.groups);
    println!(
        "Recycle bin:   {}",
        if info.recycle_bin {
            format!("on ({} entries in it)", info.in_recycle_bin)
        } else {
            "off".into()
        }
    );
    Ok(())
}

/// The formats `export` writes.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum ExportFormat {
    /// KeePassXC's CSV columns.
    Csv,
    /// An unencrypted KeePass XML file (the whole tree, history and attachments).
    Xml,
}

/// `export`: the vault unencrypted, as the website's export: the account's
/// password proved again first, and a warning; never to a terminal unless
/// `--stdout`.
pub fn export(
    profile: &str,
    vault: &str,
    format: ExportFormat,
    out: Option<&Path>,
    stdout: bool,
) -> Result<()> {
    if out.is_none() && std::io::stdout().is_terminal() && !stdout {
        return Err(UsageError(
            "the export is unencrypted and would go to the terminal: give --out FILE, or --stdout to print it".into(),
        )
        .into());
    }
    let opened = open_vault(profile, vault)?;
    eprintln!(
        "The export holds every password in {} unencrypted. Anyone who reads the file can read them: keep it safe and delete it when done.",
        opened.name
    );
    // As the website: the account's password, proved again.
    let password = current_password()?;
    reauth_grant(&opened.ctx.client, &password, "verify")
        .context("prove the account's password")?;
    let bytes = match format {
        ExportFormat::Csv => kutup_pass::export::csv(&opened.db).into_bytes(),
        ExportFormat::Xml => {
            kutup_pass::export::keepass_xml(&opened.db).map_err(|e| anyhow!("{e}"))?
        }
    };
    write_out(&bytes, out, stdout, "the unencrypted export")
}

/// `import`: another password manager's export (or `-` for stdin) into a
/// new group `group` under the top group, as the website's import; all or
/// nothing.
pub fn import(
    profile: &str,
    json: bool,
    vault: &str,
    file: &str,
    format: Option<&str>,
    group: Option<&str>,
) -> Result<()> {
    let provider = match format {
        None | Some("auto") => None,
        Some(id) => Some(Provider::from_id(id).ok_or_else(|| {
            let ids: Vec<&str> = Provider::ALL.iter().map(|p| p.id()).collect();
            UsageError(format!("no format {id}: one of auto, {}", ids.join(", ")))
        })?),
    };
    let bytes = if file == "-" {
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf)?;
        buf
    } else {
        fs::read(file).with_context(|| format!("read {file}"))?
    };
    // Read first: a file that doesn't parse changes nothing, and the group
    // is named after what it came from.
    let parsed = kutup_pass::import::parse(&bytes, provider).map_err(|e| anyhow!("{e}"))?;
    let group_name = group
        .map(str::to_owned)
        .unwrap_or_else(|| format!("Imported from {}", parsed.provider.name()));
    let mut opened = open_vault(profile, vault)?;
    if find_group(&opened.db, &group_name).is_ok() {
        return Err(UsageError(format!(
            "there is a group {group_name} already: give another with --group"
        ))
        .into());
    }
    applied(
        &mut opened,
        &Op::ImportCsv {
            data: base64::engine::general_purpose::STANDARD.encode(&bytes),
            provider: Some(parsed.provider.id().to_owned()),
            group_name: group_name.clone(),
        },
    )?;
    opened.save()?;
    for skipped in &parsed.skipped {
        eprintln!("Not imported: {skipped}");
    }
    for warning in &parsed.warnings {
        eprintln!("Note: {warning}");
    }
    said(
        json,
        serde_json::json!({
            "group": group_name,
            "entries": parsed.entries.len(),
            "skipped": parsed.skipped,
            "warnings": parsed.warnings,
        }),
        &format!(
            "Imported {} entries into {group_name}.",
            parsed.entries.len()
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_output_is_new_and_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.csv");
        write_out(b"secret", Some(&path), false, "x").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"secret");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        // Never over a file that is there.
        assert!(write_out(b"again", Some(&path), false, "x").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"secret");
    }

    #[test]
    fn every_import_format_has_an_id_the_flag_takes() {
        for provider in Provider::ALL {
            assert_eq!(Provider::from_id(provider.id()), Some(provider));
        }
    }
}
