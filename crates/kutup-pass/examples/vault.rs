//! A small vault tool for scripts and manual checks
//! (`scripts/verify-pass-sync.sh`): creates a vault and edits entries as a
//! KeePass app does (the previous state into history first).
//!
//! ```text
//! VAULT_PASSWORD=… cargo run -p kutup-pass --example vault -- new FILE
//! VAULT_PASSWORD=… cargo run -p kutup-pass --example vault -- set FILE TITLE FIELD VALUE
//! VAULT_PASSWORD=… cargo run -p kutup-pass --example vault -- get FILE TITLE FIELD
//! VAULT_PASSWORD=… cargo run -p kutup-pass --example vault -- history FILE TITLE FIELD
//! VAULT_PASSWORD=… cargo run -p kutup-pass --example vault -- review FILE TITLE
//! VAULT_PASSWORD=… cargo run -p kutup-pass --example vault -- ssh-key FILE TITLE KEY_FILE PASSPHRASE
//! ```
//!
//! `ssh-key` adds an entry in KeePassXC's KeeAgent form: the OpenSSH private
//! key file attached, its passphrase as the entry's password.

use std::process::ExitCode;

use base64::Engine as _;

use kutup_pass::keepass::db::{CustomDataValue, Entry, EntryId, Value};
use kutup_pass::keepass::Database;
use kutup_pass::{open, save, VaultKey, REVIEW_KEY};

fn find(db: &Database, title: &str) -> Option<EntryId> {
    let mut ids: Vec<&Entry> = db
        .entries
        .values()
        .filter(|entry| entry.fields.get("Title").map(|v| v.get().as_str()) == Some(title))
        .collect();
    ids.sort_by_key(|entry| entry.id.uuid());
    ids.first().map(|entry| entry.id)
}

fn run(args: &[String]) -> Result<String, String> {
    let password = std::env::var("VAULT_PASSWORD").map_err(|_| "set VAULT_PASSWORD")?;
    let key = VaultKey::new().with_password(&password);
    let load = |file: &str| -> Result<Database, String> {
        let contents = std::fs::read(file).map_err(|e| format!("{file}: {e}"))?;
        open(&contents, &key).map_err(|e| e.to_string())
    };
    let store = |file: &str, db: &Database| -> Result<(), String> {
        let contents = save(db, &key).map_err(|e| e.to_string())?;
        std::fs::write(file, contents).map_err(|e| format!("{file}: {e}"))
    };
    let now = chrono::Utc::now().naive_utc();
    match args {
        [cmd, file] if cmd == "new" => {
            let mut db = Database::new();
            db.meta.database_name = Some("Kutup Pass check".into());
            store(file, &db)?;
            Ok(String::new())
        }
        [cmd, file, title, field, value] if cmd == "set" => {
            let mut db = load(file)?;
            match find(&db, title) {
                Some(id) => {
                    let entry = db.entries.get_mut(&id).ok_or("entry vanished")?;
                    let mut previous = entry.clone();
                    previous.history = None;
                    entry
                        .history
                        .get_or_insert_with(Default::default)
                        .entries
                        .push(previous);
                    let value = if field == "Password" {
                        Value::protected(value.clone())
                    } else {
                        Value::unprotected(value.clone())
                    };
                    entry.fields.insert(field.clone(), value);
                    entry.times.last_modification = Some(now);
                }
                None => {
                    let mut root = db.root_mut();
                    let mut entry = root.add_entry();
                    entry.set_unprotected("Title", title.clone());
                    if field == "Password" {
                        entry.set_protected(field.clone(), value.clone());
                    } else {
                        entry.set_unprotected(field.clone(), value.clone());
                    }
                    entry.times.creation = Some(now);
                    entry.times.last_modification = Some(now);
                }
            }
            store(file, &db)?;
            Ok(String::new())
        }
        [cmd, file, title, field] if cmd == "get" => {
            let db = load(file)?;
            let id = find(&db, title).ok_or("no such entry")?;
            Ok(db.entries[&id]
                .fields
                .get(field)
                .map(|v| v.get().clone())
                .unwrap_or_default())
        }
        [cmd, file, title, field] if cmd == "history" => {
            let db = load(file)?;
            let id = find(&db, title).ok_or("no such entry")?;
            let entry = &db.entries[&id];
            let values: Vec<String> = entry
                .history
                .iter()
                .flat_map(|history| &history.entries)
                .filter_map(|item| item.fields.get(field).map(|v| v.get().clone()))
                .collect();
            Ok(values.join("\n"))
        }
        [cmd, file, title] if cmd == "review" => {
            let db = load(file)?;
            let id = find(&db, title).ok_or("no such entry")?;
            Ok(
                match db.entries[&id]
                    .custom_data
                    .get(REVIEW_KEY)
                    .and_then(|item| item.value.as_ref())
                {
                    Some(CustomDataValue::String(fields)) => fields.clone(),
                    _ => String::new(),
                },
            )
        }
        [cmd, file, title, key_file, passphrase] if cmd == "ssh-key" => {
            let mut db = load(file)?;
            let key = std::fs::read(key_file).map_err(|e| format!("{key_file}: {e}"))?;
            let settings = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<EntrySettings><AllowUseOfSshKey>true</AllowUseOfSshKey><AddAtDatabaseOpen>true</AddAtDatabaseOpen><RemoveAtDatabaseClose>true</RemoveAtDatabaseClose><UseConfirmConstraintWhenAdding>false</UseConfirmConstraintWhenAdding><UseLifetimeConstraintWhenAdding>false</UseLifetimeConstraintWhenAdding><LifetimeConstraintDuration>600</LifetimeConstraintDuration><Location><SelectedType>attachment</SelectedType><AttachmentName>id_key</AttachmentName><SaveAttachmentToTempFile>false</SaveAttachmentToTempFile><FileName/></Location></EntrySettings>";
            let root = kutup_pass::view::view(&db).root_group_id;
            let b64 = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
            let fields = vec![
                kutup_pass::view::FieldView {
                    key: "Title".into(),
                    value: title.clone(),
                    protected: false,
                },
                kutup_pass::view::FieldView {
                    key: "Password".into(),
                    value: passphrase.clone(),
                    protected: true,
                },
            ];
            let id = kutup_pass::edit::apply(
                &mut db,
                &kutup_pass::edit::Op::CreateEntry {
                    group_id: root,
                    entry: kutup_pass::edit::EntryInput {
                        fields,
                        ..Default::default()
                    },
                },
                now,
            )
            .map_err(|e| e.to_string())?
            .id
            .ok_or("no id")?;
            for (name, data) in [
                ("id_key", key.as_slice()),
                ("KeeAgent.settings", settings.as_bytes()),
            ] {
                kutup_pass::edit::apply(
                    &mut db,
                    &kutup_pass::edit::Op::AddAttachment {
                        entry_id: id.clone(),
                        name: name.into(),
                        data: b64(data),
                    },
                    now,
                )
                .map_err(|e| e.to_string())?;
            }
            store(file, &db)?;
            Ok(String::new())
        }
        _ => Err("usage: vault new|set|get|history|review|ssh-key FILE …".into()),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(out) => {
            if !out.is_empty() {
                println!("{out}");
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("vault: {error}");
            ExitCode::FAILURE
        }
    }
}
