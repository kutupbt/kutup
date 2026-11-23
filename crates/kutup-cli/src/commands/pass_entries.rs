//! `kutup pass ls|search|show|clip|add|edit|rm|generate`: a vault's entries
//! from the command line (docs/plans/pass-gaps-3.md, B2), after
//! `keepassxc-cli`. A vault is named by its file id or its name; it opens
//! with the key the account keeps (as `kutup sync`), `KUTUP_VAULT_PASSWORD`
//! / `KUTUP_VAULT_KEY_FILE`, or a prompt. Edits are the website's
//! operations (`kutup_pass::edit::Op`), saved as a new Drive version based
//! on the one read; another device's save meanwhile is merged.

use std::io::{IsTerminal, Write as _};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use clap::Args;
use kutup_pass::edit::{apply, EntryInput, Op};
use kutup_pass::generate::{self, PassphraseSpec, PasswordSpec, WordCase};
use kutup_pass::keepass::db::{Entry, EntryId, GroupId};
use kutup_pass::keepass::Database;
use kutup_pass::view::{group_in_recycle_bin, FieldView, STANDARD_FIELDS};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::context::{require_session, Ctx};
use crate::cryptohelpers::{decrypt_collection_key, decrypt_file_meta};
use crate::errors::{NotFound, UsageError};
use crate::keyring::Keyring;
use crate::output::print_json;
use crate::vaultsync::{
    fetch_current, merge_and_save, recorded, save_version, VaultFile, VaultKeys,
};

/// The generator's options, for `generate` and `--generate`.
#[derive(Args, Debug, Clone)]
pub struct GenerateOpts {
    /// Length of a password (4–128).
    #[arg(long, short = 'L', default_value_t = 20)]
    pub length: usize,
    /// A passphrase of this many words (3–20) from the EFF list instead.
    #[arg(long, short = 'w')]
    pub words: Option<usize>,
    /// Between the words.
    #[arg(long, default_value = "-")]
    pub separator: String,
    /// Words capitalised: none, first, random.
    #[arg(long, default_value = "none")]
    pub word_case: String,
    #[arg(long)]
    pub no_lower: bool,
    #[arg(long)]
    pub no_upper: bool,
    #[arg(long)]
    pub no_digits: bool,
    #[arg(long)]
    pub no_symbols: bool,
    /// KeePassXC's finer groups, each its own set: ( ) [ ] { }.
    #[arg(long)]
    pub braces: bool,
    /// . , : ;
    #[arg(long)]
    pub punctuation: bool,
    /// " '
    #[arg(long)]
    pub quotes: bool,
    /// - / \ _ |
    #[arg(long)]
    pub dashes: bool,
    /// ! * + < = > ?
    #[arg(long)]
    pub math: bool,
    /// # $ % & @ ^ ` ~
    #[arg(long)]
    pub logograms: bool,
    /// Extended ASCII (Latin-1 letters and signs), as keepassxc-cli's -e.
    #[arg(long, short = 'e')]
    pub extended: bool,
    /// Leave out 0/O, 1/l/I and the like.
    #[arg(long)]
    pub avoid_look_alikes: bool,
    /// Also use these characters.
    #[arg(long, default_value = "")]
    pub custom: String,
    /// Never use these characters.
    #[arg(long, default_value = "")]
    pub exclude: String,
}

impl GenerateOpts {
    fn make(&self) -> Result<Zeroizing<String>> {
        if let Some(words) = self.words {
            let case = match self.word_case.as_str() {
                "none" | "lower" => WordCase::Lower,
                "first" => WordCase::First,
                "random" => WordCase::Random,
                other => {
                    return Err(UsageError(format!(
                        "--word-case is none, first or random, not {other}"
                    ))
                    .into())
                }
            };
            return Ok(Zeroizing::new(generate::passphrase(&PassphraseSpec {
                words,
                separator: self.separator.clone(),
                case,
                add_number: false,
                add_symbol: false,
            })));
        }
        generate::password(&PasswordSpec {
            length: self.length,
            lower: !self.no_lower,
            upper: !self.no_upper,
            digits: !self.no_digits,
            symbols: !self.no_symbols,
            braces: self.braces,
            punctuation: self.punctuation,
            quotes: self.quotes,
            dashes: self.dashes,
            math: self.math,
            logograms: self.logograms,
            extended: self.extended,
            avoid_look_alikes: self.avoid_look_alikes,
            custom: self.custom.clone(),
            exclude: self.exclude.clone(),
        })
        .map(Zeroizing::new)
        .ok_or_else(|| UsageError("no characters are left to choose from".into()).into())
    }
}

/// An open vault and where it came from.
pub(crate) struct Opened {
    pub(crate) ctx: Ctx,
    pub(crate) file_id: String,
    pub(crate) name: String,
    pub(crate) collection_id: String,
    pub(crate) folder_epoch: u32,
    pub(crate) keys: Keyring,
    pub(crate) vault_keys: VaultKeys,
    pub(crate) db: Database,
    pub(crate) key_index: usize,
    /// The version read, as the base records it.
    pub(crate) version: String,
}

impl Opened {
    /// Saves the vault as it is now; merges with a save that landed first.
    pub(crate) fn save(&mut self) -> Result<()> {
        let key = self
            .vault_keys
            .key(&self.name, self.key_index)
            .ok_or_else(|| anyhow!("vault key went missing"))?
            .clone();
        let contents = kutup_pass::save(&self.db, &key).context("save vault")?;
        let file_id = self.file_id.clone();
        let version = self.version.clone();
        let vault = VaultFile {
            file_id: &file_id,
            collection_id: &self.collection_id,
            folder_epoch: self.folder_epoch,
            keys: &self.keys,
        };
        if save_version(&self.ctx.client, &vault, &contents, &version)?.is_some() {
            return Ok(());
        }
        match merge_and_save(
            &self.ctx.client,
            &mut self.vault_keys,
            &self.name,
            &vault,
            Some((file_id.as_str(), version.as_str())),
            &contents,
        )? {
            Some(saved) => {
                let merged = crate::vaultsync::describe(&saved.report);
                if !merged.is_empty() {
                    eprintln!("Merged with another device's save: {merged}.");
                }
                Ok(())
            }
            None => Err(anyhow!(
                "the vault changed on Drive and no key opens the new version"
            )),
        }
    }
}

/// The vault named `name` (a file id, or a `.kdbx` file's name with or
/// without the extension), opened.
pub(crate) fn open_vault(profile: &str, name: &str) -> Result<Opened> {
    let ctx = require_session(profile)?;
    let roots = ctx.session.roots()?;
    let mut found = Vec::new();
    for col in ctx.client.list_collections()? {
        let Ok(col_key) = decrypt_collection_key(&col, &roots, &ctx.session) else {
            continue;
        };
        let Ok(files) = ctx.client.list_files(&col.id) else {
            continue;
        };
        let mut keys: Option<Keyring> = None;
        for file in files {
            if keys.is_none() {
                keys = Some(Keyring::load(&ctx.client, &col, &col_key, &ctx.session)?);
            }
            let Some(ring) = keys.as_ref() else { continue };
            let (file_name, _) = decrypt_file_meta(&file, ring);
            let is_vault = crate::vaultsync::is_vault(&file_name);
            let stem = file_name
                .rsplit_once('.')
                .map_or(file_name.as_str(), |(s, _)| s);
            if is_vault && (file.id == name || file_name == name || stem == name) {
                found.push((
                    file.id.clone(),
                    file_name,
                    col.clone(),
                    Zeroizing::new(col_key.clone()),
                ));
            }
        }
    }
    let (file_id, file_name, col, col_key) = match found.len() {
        0 => return Err(NotFound(format!("no vault named {name}")).into()),
        1 => found.remove(0),
        _ => {
            let ids: Vec<String> = found
                .iter()
                .map(|(id, n, _, _)| format!("{id} ({n})"))
                .collect();
            return Err(UsageError(format!(
                "{name} names several vaults; give a file id: {}",
                ids.join(", ")
            ))
            .into());
        }
    };
    let keys = Keyring::load(&ctx.client, &col, &col_key, &ctx.session)?;
    let mut vault_keys = VaultKeys::from_env()?;
    vault_keys.sign_in(&ctx.session, profile)?;
    let vault = VaultFile {
        file_id: &file_id,
        collection_id: &col.id,
        folder_epoch: col.key_epoch,
        keys: &keys,
    };
    let (contents, version) = fetch_current(&ctx.client, &vault)?;
    let (db, key_index) = vault_keys
        .open(&ctx.client, &file_name, &file_id, &contents, true)
        .ok_or_else(|| anyhow!("no key opens {file_name}: keep it with `kutup pass keep`, or set KUTUP_VAULT_PASSWORD"))?;
    Ok(Opened {
        ctx,
        file_id,
        name: file_name,
        collection_id: col.id,
        folder_epoch: col.key_epoch,
        keys,
        vault_keys,
        db,
        key_index,
        version: recorded(&version),
    })
}

/// The names of the groups from below the top group down to `group`.
pub(crate) fn group_path(db: &Database, mut group: Option<GroupId>) -> Vec<String> {
    let mut names = Vec::new();
    while let Some(id) = group {
        if id == db.root {
            break;
        }
        let Some(g) = db.groups.get(&id) else { break };
        names.push(g.name.clone());
        group = g.parent;
    }
    names.reverse();
    names
}

pub(crate) fn field<'a>(entry: &'a Entry, key: &str) -> &'a str {
    entry.fields.get(key).map_or("", |v| v.get().as_str())
}

/// The entry `name` names: its UUID (with or without dashes) or its path
/// (`Group/Sub/Title`, below the top group), outside the recycle bin.
pub(crate) fn find_entry(db: &Database, name: &str) -> Result<EntryId> {
    let compact = name.replace('-', "").to_lowercase();
    if compact.len() == 32 && compact.chars().all(|c| c.is_ascii_hexdigit()) {
        if let Some(entry) = db
            .entries
            .values()
            .find(|e| e.id.uuid().simple().to_string() == compact)
        {
            return Ok(entry.id);
        }
    }
    let matches: Vec<&Entry> = db
        .entries
        .values()
        .filter(|e| !group_in_recycle_bin(db, e.parent))
        .filter(|e| {
            let mut path = group_path(db, Some(e.parent));
            path.push(field(e, "Title").to_owned());
            path.join("/") == name.trim_matches('/')
        })
        .collect();
    match matches.len() {
        0 => Err(NotFound(format!("no entry {name}")).into()),
        1 => Ok(matches[0].id),
        _ => {
            let ids: Vec<String> = matches.iter().map(|e| e.id.uuid().to_string()).collect();
            Err(UsageError(format!(
                "{name} names several entries; give one's UUID: {}",
                ids.join(", ")
            ))
            .into())
        }
    }
}

/// The group a path names (below the top group; empty is the top group).
pub(crate) fn find_group(db: &Database, path: &str) -> Result<GroupId> {
    let mut group = db.root;
    for part in path.split('/').filter(|p| !p.is_empty()) {
        group = db.groups[&group]
            .groups
            .iter()
            .copied()
            .find(|g| db.groups.get(g).is_some_and(|g| g.name == part))
            .ok_or_else(|| NotFound(format!("no group {path}")))?;
    }
    Ok(group)
}

fn resolve_context() -> kutup_pass::resolve::Context {
    let utc = Utc::now();
    kutup_pass::resolve::Context {
        local: chrono::Local::now().naive_local(),
        utc: utc.naive_utc(),
        unix_seconds: utc.timestamp().max(0) as u64,
    }
}

fn resolved(db: &Database, entry: &Entry, key: &str) -> String {
    kutup_pass::resolve::resolve(db, entry, field(entry, key), &resolve_context())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Listed {
    uuid: String,
    path: String,
    title: String,
    user_name: String,
    url: String,
}

fn listed(db: &Database, entry: &Entry) -> Listed {
    let mut path = group_path(db, Some(entry.parent));
    path.push(field(entry, "Title").to_owned());
    Listed {
        uuid: entry.id.uuid().to_string(),
        path: path.join("/"),
        title: resolved(db, entry, "Title"),
        user_name: resolved(db, entry, "UserName"),
        url: resolved(db, entry, "URL"),
    }
}

/// `ls`: a group's subgroups and entries (all below it with `recursive`).
pub fn ls(
    profile: &str,
    json: bool,
    vault: &str,
    group: Option<&str>,
    recursive: bool,
) -> Result<()> {
    let opened = open_vault(profile, vault)?;
    let db = &opened.db;
    let start = find_group(db, group.unwrap_or(""))?;
    let mut groups = Vec::new();
    let mut entries = Vec::new();
    let mut stack = vec![start];
    while let Some(id) = stack.pop() {
        let g = &db.groups[&id];
        if Some(id) != Some(start) && group_in_recycle_bin(db, id) {
            continue;
        }
        for child in g.groups.iter().rev() {
            if !group_in_recycle_bin(db, *child) || group_in_recycle_bin(db, start) {
                groups.push(group_path(db, Some(*child)).join("/"));
                if recursive {
                    stack.push(*child);
                }
            }
        }
        entries.extend(
            g.entries
                .iter()
                .filter_map(|e| db.entries.get(e))
                .map(|e| listed(db, e)),
        );
    }
    groups.sort();
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    if json {
        print_json(&serde_json::json!({ "groups": groups, "entries": entries }))?;
    } else {
        for g in &groups {
            println!("{g}/");
        }
        for e in &entries {
            println!("{}", e.path);
        }
    }
    Ok(())
}

/// `search`: the website's search (fields, `-`, quotes, `*`).
pub fn search(profile: &str, json: bool, vault: &str, query: &str) -> Result<()> {
    let opened = open_vault(profile, vault)?;
    let db = &opened.db;
    let context = kutup_pass::search::Context {
        weak: &std::collections::HashSet::new(),
        now: Utc::now().naive_utc(),
    };
    let mut found: Vec<Listed> = kutup_pass::search::search(db, query, &context)
        .iter()
        .filter_map(|id| uuid::Uuid::parse_str(id).ok())
        .filter_map(|id| db.entries.get(&EntryId::from(id)))
        .filter(|e| !group_in_recycle_bin(db, e.parent))
        .map(|e| listed(db, e))
        .collect();
    found.sort_by(|a, b| a.path.cmp(&b.path));
    if json {
        print_json(&found)?;
    } else if found.is_empty() {
        eprintln!("No entries match.");
    } else {
        for e in &found {
            println!("{}", e.path);
        }
    }
    Ok(())
}

/// `show`: the entry's fields, protected ones hidden unless asked.
pub fn show(
    profile: &str,
    json: bool,
    vault: &str,
    entry: &str,
    show_protected: bool,
    attributes: &[String],
    totp: bool,
) -> Result<()> {
    let opened = open_vault(profile, vault)?;
    let db = &opened.db;
    let entry = &db.entries[&find_entry(db, entry)?];
    if totp {
        let settings =
            kutup_pass::otp::settings(entry).ok_or_else(|| NotFound("no one-time code".into()))?;
        let code = kutup_pass::otp::code(&settings, resolve_context().unix_seconds);
        if json {
            print_json(&serde_json::json!({ "totp": code }))?;
        } else {
            println!("{code}");
        }
        return Ok(());
    }
    let mut keys: Vec<String> = if attributes.is_empty() {
        let mut keys: Vec<String> = STANDARD_FIELDS.iter().map(|k| (*k).to_owned()).collect();
        let mut custom: Vec<String> = entry
            .fields
            .keys()
            .filter(|k| !STANDARD_FIELDS.contains(&k.as_str()) && k.as_str() != "otp")
            .cloned()
            .collect();
        custom.sort();
        keys.extend(custom);
        keys
    } else {
        attributes.to_vec()
    };
    keys.dedup();
    let mut out: Vec<FieldView> = Vec::new();
    for key in keys {
        let Some(value) = entry.fields.get(&key) else {
            if !attributes.is_empty() {
                return Err(NotFound(format!("no attribute {key}")).into());
            }
            continue;
        };
        // Asked for by name, an attribute is shown whatever it is.
        let hidden = value.is_protected() && !show_protected && attributes.is_empty();
        out.push(FieldView {
            key: key.clone(),
            value: if hidden {
                String::new()
            } else {
                resolved(db, entry, &key)
            },
            protected: value.is_protected(),
        });
    }
    if json {
        print_json(&out)?;
    } else if !attributes.is_empty() {
        for f in &out {
            println!("{}", f.value);
        }
    } else {
        for f in &out {
            let value = if f.protected && !show_protected {
                "PROTECTED".to_owned()
            } else {
                f.value.clone()
            };
            println!("{}: {value}", f.key);
        }
    }
    Ok(())
}

/// The platform's clipboard tool, with how to read the clipboard back.
struct Clipboard {
    copy: (&'static str, &'static [&'static str]),
    paste: Option<(&'static str, &'static [&'static str])>,
}

fn on_path(program: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|paths| {
        std::env::split_paths(&paths).any(|dir| {
            let candidate = dir.join(program);
            candidate.is_file() || dir.join(format!("{program}.exe")).is_file()
        })
    })
}

fn clipboard() -> Option<Clipboard> {
    if cfg!(target_os = "macos") && on_path("pbcopy") {
        return Some(Clipboard {
            copy: ("pbcopy", &[]),
            paste: Some(("pbpaste", &[])),
        });
    }
    if cfg!(windows) && on_path("clip") {
        return Some(Clipboard {
            copy: ("clip", &[]),
            paste: Some(("powershell", &["-NoProfile", "-Command", "Get-Clipboard"])),
        });
    }
    if std::env::var_os("WAYLAND_DISPLAY").is_some() && on_path("wl-copy") {
        return Some(Clipboard {
            copy: ("wl-copy", &[]),
            paste: Some(("wl-paste", &["--no-newline"])),
        });
    }
    if std::env::var_os("DISPLAY").is_some() {
        if on_path("xclip") {
            return Some(Clipboard {
                copy: ("xclip", &["-selection", "clipboard"]),
                paste: Some(("xclip", &["-selection", "clipboard", "-o"])),
            });
        }
        if on_path("xsel") {
            return Some(Clipboard {
                copy: ("xsel", &["--clipboard", "--input"]),
                paste: Some(("xsel", &["--clipboard", "--output"])),
            });
        }
    }
    None
}

fn copy_with(tool: (&str, &[&str]), text: &str) -> Result<()> {
    let mut child = Command::new(tool.0)
        .args(tool.1)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("run {}", tool.0))?;
    child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("no stdin for {}", tool.0))?
        .write_all(text.as_bytes())?;
    let status = child.wait()?;
    if !status.success() {
        return Err(anyhow!("{} failed", tool.0));
    }
    Ok(())
}

/// `clip`: copies the password (or an attribute, or the code) and clears it
/// after `clear_after` seconds if it is still there (0: never).
pub fn clip(
    profile: &str,
    vault: &str,
    entry: &str,
    attribute: Option<&str>,
    totp: bool,
    clear_after: u64,
) -> Result<()> {
    let Some(tool) = clipboard() else {
        return Err(UsageError(
            "no clipboard tool found: install wl-clipboard (Wayland), xclip or xsel (X11); macOS has pbcopy, Windows clip. Or use `kutup pass show`".into(),
        )
        .into());
    };
    let opened = open_vault(profile, vault)?;
    let db = &opened.db;
    let entry = &db.entries[&find_entry(db, entry)?];
    let value = Zeroizing::new(if totp {
        let settings =
            kutup_pass::otp::settings(entry).ok_or_else(|| NotFound("no one-time code".into()))?;
        kutup_pass::otp::code(&settings, resolve_context().unix_seconds)
    } else {
        let key = attribute.unwrap_or("Password");
        if !entry.fields.contains_key(key) {
            return Err(NotFound(format!("no attribute {key}")).into());
        }
        resolved(db, entry, key)
    });
    copy_with(tool.copy, &value)?;
    let what = if totp {
        "One-time code"
    } else {
        attribute.unwrap_or("Password")
    };
    if clear_after == 0 {
        eprintln!("{what} copied.");
        return Ok(());
    }
    eprintln!("{what} copied; clearing the clipboard in {clear_after} seconds (Ctrl+C leaves it).");
    std::thread::sleep(Duration::from_secs(clear_after));
    // Only what this copied is cleared.
    let still = match tool.paste {
        Some((program, args)) => Command::new(program)
            .args(args)
            .stderr(Stdio::null())
            .output()
            .map(|out| {
                String::from_utf8_lossy(&out.stdout).trim_end_matches(['\r', '\n'])
                    == value.as_str()
            })
            .unwrap_or(true),
        None => true,
    };
    if still {
        copy_with(tool.copy, "")?;
        eprintln!("Clipboard cleared.");
    }
    Ok(())
}

/// What `add` and `edit` change.
#[derive(Args, Debug, Clone)]
pub struct EntryOpts {
    #[arg(long, short = 'u')]
    pub username: Option<String>,
    #[arg(long)]
    pub url: Option<String>,
    #[arg(long)]
    pub notes: Option<String>,
    /// Ask for the password (or read KUTUP_ENTRY_PASSWORD).
    #[arg(long, short = 'p')]
    pub password_prompt: bool,
    /// Generate the password (the generator's options apply).
    #[arg(long, short = 'g')]
    pub generate: bool,
    #[command(flatten)]
    pub generator: GenerateOpts,
}

fn new_password(opts: &EntryOpts) -> Result<Option<Zeroizing<String>>> {
    if opts.generate {
        return opts.generator.make().map(Some);
    }
    if !opts.password_prompt {
        return Ok(None);
    }
    if let Ok(password) = std::env::var("KUTUP_ENTRY_PASSWORD") {
        return Ok(Some(Zeroizing::new(password)));
    }
    if !std::io::stdin().is_terminal() {
        return Err(UsageError(
            "set KUTUP_ENTRY_PASSWORD, or run in a terminal to be asked".into(),
        )
        .into());
    }
    let first = Zeroizing::new(rpassword::prompt_password("Entry password: ")?);
    let again = Zeroizing::new(rpassword::prompt_password("Again: ")?);
    if first != again {
        return Err(UsageError("the passwords don't match".into()).into());
    }
    Ok(Some(first))
}

/// The entry's fields as `EntryInput` keeps them, with `changes` applied.
fn input_of(entry: &Entry, changes: &[(&str, String)]) -> EntryInput {
    let mut fields: Vec<FieldView> = kutup_pass::view::fields(entry);
    for (key, value) in changes {
        match fields.iter_mut().find(|f| f.key == *key) {
            Some(f) => f.value = value.clone(),
            None => fields.push(FieldView {
                key: (*key).to_owned(),
                value: value.clone(),
                protected: *key == "Password",
            }),
        }
    }
    EntryInput {
        fields,
        tags: entry.tags.clone(),
        icon: None,
        foreground_color: entry.foreground_color.as_ref().map(|c| c.to_string()),
        background_color: entry.background_color.as_ref().map(|c| c.to_string()),
        override_url: entry.override_url.clone().unwrap_or_default(),
        quality_check: entry.quality_check,
        expires: entry.times.expires.unwrap_or(false),
        expiry: entry.times.expiry.map(kutup_pass::view::format_time),
    }
}

pub(crate) fn now() -> chrono::NaiveDateTime {
    Utc::now().naive_utc()
}

/// `add`: a new entry at `path` (`Group/Sub/Title`).
pub fn add(profile: &str, json: bool, vault: &str, path: &str, opts: &EntryOpts) -> Result<()> {
    let mut opened = open_vault(profile, vault)?;
    let (group_path, title) = match path.trim_matches('/').rsplit_once('/') {
        Some((group, title)) => (group, title),
        None => ("", path.trim_matches('/')),
    };
    if title.is_empty() {
        return Err(UsageError("give the entry's title, as Group/Title".into()).into());
    }
    let group = find_group(&opened.db, group_path)?;
    let password = new_password(opts)?;
    let field = |key: &str, value: &str| FieldView {
        key: key.into(),
        value: value.into(),
        protected: key == "Password",
    };
    let default_user = opened.db.meta.default_username.clone().unwrap_or_default();
    let input = EntryInput {
        fields: vec![
            field("Title", title),
            field(
                "UserName",
                opts.username.as_deref().unwrap_or(&default_user),
            ),
            field(
                "Password",
                password.as_deref().map(String::as_str).unwrap_or(""),
            ),
            field("URL", opts.url.as_deref().unwrap_or("")),
            field("Notes", opts.notes.as_deref().unwrap_or("")),
        ],
        ..EntryInput::default()
    };
    let applied = apply(
        &mut opened.db,
        &Op::CreateEntry {
            group_id: group.uuid().to_string(),
            entry: input,
        },
        now(),
    )
    .map_err(|e| anyhow!("{e}"))?;
    opened.save()?;
    let uuid = applied.id.unwrap_or_default();
    if json {
        print_json(&serde_json::json!({ "uuid": uuid, "path": path.trim_matches('/') }))?;
    } else {
        eprintln!("Added {}.", path.trim_matches('/'));
    }
    Ok(())
}

/// `edit`: changes only what is given.
pub fn edit(
    profile: &str,
    json: bool,
    vault: &str,
    entry: &str,
    title: Option<&str>,
    move_to: Option<&str>,
    opts: &EntryOpts,
) -> Result<()> {
    let mut opened = open_vault(profile, vault)?;
    let id = find_entry(&opened.db, entry)?;
    let password = new_password(opts)?;
    let mut changes: Vec<(&str, String)> = Vec::new();
    if let Some(title) = title {
        changes.push(("Title", title.to_owned()));
    }
    if let Some(user) = &opts.username {
        changes.push(("UserName", user.clone()));
    }
    if let Some(password) = &password {
        changes.push(("Password", password.as_str().to_owned()));
    }
    if let Some(url) = &opts.url {
        changes.push(("URL", url.clone()));
    }
    if let Some(notes) = &opts.notes {
        changes.push(("Notes", notes.clone()));
    }
    if changes.is_empty() && move_to.is_none() {
        return Err(UsageError(
            "nothing to change: give --title, --username, --url, --notes, -p, -g or --move-to"
                .into(),
        )
        .into());
    }
    let uuid = id.uuid().to_string();
    if !changes.is_empty() {
        let input = input_of(&opened.db.entries[&id], &changes);
        apply(
            &mut opened.db,
            &Op::UpdateEntry {
                id: uuid.clone(),
                entry: input,
            },
            now(),
        )
        .map_err(|e| anyhow!("{e}"))?;
    }
    if let Some(target) = move_to {
        let group = find_group(&opened.db, target)?;
        apply(
            &mut opened.db,
            &Op::MoveEntry {
                id: uuid.clone(),
                group_id: group.uuid().to_string(),
            },
            now(),
        )
        .map_err(|e| anyhow!("{e}"))?;
    }
    opened.save()?;
    if json {
        print_json(&serde_json::json!({ "uuid": uuid, "edited": true }))?;
    } else {
        eprintln!("Saved.");
    }
    Ok(())
}

/// `rm`: to the recycle bin; for good (with `force`) inside it or with it off.
pub fn rm(profile: &str, json: bool, vault: &str, entry: &str, force: bool) -> Result<()> {
    let mut opened = open_vault(profile, vault)?;
    let id = find_entry(&opened.db, entry).or_else(|_| {
        // Inside the bin, by UUID only.
        let compact = entry.replace('-', "").to_lowercase();
        opened
            .db
            .entries
            .values()
            .find(|e| e.id.uuid().simple().to_string() == compact)
            .map(|e| e.id)
            .ok_or_else(|| anyhow::Error::from(NotFound(format!("no entry {entry}"))))
    })?;
    let bin_on = opened.db.meta.recyclebin_enabled.unwrap_or(true);
    let for_good = !bin_on || group_in_recycle_bin(&opened.db, opened.db.entries[&id].parent);
    if for_good && !force {
        return Err(UsageError("this deletes the entry for good (it is in the recycle bin, or the bin is off): add --force".into()).into());
    }
    apply(
        &mut opened.db,
        &Op::DeleteEntry {
            id: id.uuid().to_string(),
        },
        now(),
    )
    .map_err(|e| anyhow!("{e}"))?;
    opened.save()?;
    if json {
        print_json(&serde_json::json!({ "uuid": id.uuid().to_string(), "forGood": for_good }))?;
    } else if for_good {
        eprintln!("Deleted for good.");
    } else {
        eprintln!("Moved to the recycle bin.");
    }
    Ok(())
}

/// `generate`: a password or passphrase, no vault needed.
pub fn generate(json: bool, opts: &GenerateOpts) -> Result<()> {
    let value = opts.make()?;
    if json {
        print_json(&serde_json::json!({ "value": value.as_str() }))?;
    } else {
        println!("{}", value.as_str());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kutup_pass::edit::new_vault;

    fn vault() -> (Database, String) {
        let now = chrono::NaiveDate::from_ymd_opt(2026, 11, 17)
            .unwrap()
            .and_hms_opt(9, 0, 0)
            .unwrap();
        let mut db = new_vault("V", now).unwrap();
        let root = db.root.uuid().to_string();
        let work = apply(
            &mut db,
            &Op::CreateGroup {
                parent_id: root.clone(),
                name: "İş".into(),
            },
            now,
        )
        .unwrap()
        .id
        .unwrap();
        let field = |key: &str, value: &str| FieldView {
            key: key.into(),
            value: value.into(),
            protected: false,
        };
        for (group, title) in [(&work, "Banka"), (&root, "Posta"), (&work, "Posta")] {
            apply(
                &mut db,
                &Op::CreateEntry {
                    group_id: group.clone(),
                    entry: EntryInput {
                        fields: vec![field("Title", title)],
                        ..EntryInput::default()
                    },
                },
                now,
            )
            .unwrap();
        }
        (db, work)
    }

    #[test]
    fn entries_are_named_by_path_or_uuid() {
        let (db, _) = vault();
        let bank = find_entry(&db, "İş/Banka").unwrap();
        assert_eq!(field(&db.entries[&bank], "Title"), "Banka");
        assert_eq!(find_entry(&db, "/İş/Banka/").unwrap(), bank);
        assert_eq!(find_entry(&db, &bank.uuid().to_string()).unwrap(), bank);
        assert_eq!(
            find_entry(&db, &bank.uuid().simple().to_string().to_uppercase()).unwrap(),
            bank
        );
        assert_ne!(
            find_entry(&db, "Posta").unwrap(),
            find_entry(&db, "İş/Posta").unwrap()
        );
        assert!(find_entry(&db, "Yok").is_err());
    }

    #[test]
    fn groups_are_named_by_path() {
        let (db, work) = vault();
        assert_eq!(find_group(&db, "").unwrap(), db.root);
        assert_eq!(find_group(&db, "İş").unwrap().uuid().to_string(), work);
        assert!(find_group(&db, "İş/Yok").is_err());
    }

    #[test]
    fn edits_keep_what_is_not_given() {
        let (db, _) = vault();
        let bank = find_entry(&db, "İş/Banka").unwrap();
        let input = input_of(
            &db.entries[&bank],
            &[("UserName", "ayse".into()), ("Password", "p".into())],
        );
        let get = |k: &str| input.fields.iter().find(|f| f.key == k).unwrap();
        assert_eq!(get("Title").value, "Banka");
        assert_eq!(get("UserName").value, "ayse");
        assert!(get("Password").protected);
    }

    #[test]
    fn the_generator_options_reach_the_core() {
        let opts = GenerateOpts {
            length: 30,
            words: None,
            separator: "-".into(),
            word_case: "none".into(),
            no_lower: false,
            no_upper: true,
            no_digits: true,
            no_symbols: true,
            braces: false,
            punctuation: false,
            quotes: false,
            dashes: false,
            math: false,
            logograms: false,
            extended: false,
            avoid_look_alikes: false,
            custom: String::new(),
            exclude: "aeiou".into(),
        };
        let p = opts.make().unwrap();
        assert_eq!(p.chars().count(), 30);
        assert!(p
            .chars()
            .all(|c| c.is_ascii_lowercase() && !"aeiou".contains(c)));
        let words = GenerateOpts {
            words: Some(5),
            separator: " ".into(),
            word_case: "first".into(),
            ..opts.clone()
        }
        .make()
        .unwrap();
        assert_eq!(words.split(' ').count(), 5);
        assert!(GenerateOpts {
            word_case: "shout".into(),
            words: Some(4),
            ..opts
        }
        .make()
        .is_err());
    }
}
