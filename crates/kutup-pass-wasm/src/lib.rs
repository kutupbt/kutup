//! Kutup Pass in the browser (docs/plans/pass.md, K2b): a [`Vault`] holds one
//! open KeePass vault in WASM memory. The website reads its view, changes it
//! with operations (`kutup_pass::edit::Op`, as JSON objects), saves it as
//! KDBX 4.1 and merges it with another version, all with the same Rust code
//! `kutup sync` uses. Key derivation is slow on purpose: run it in a worker.

use chrono::{DateTime, NaiveDateTime};
use kutup_pass::edit::{self, Op};
use kutup_pass::keepass::db::EntryId;
use kutup_pass::keepass::Database;
use kutup_pass::{view, VaultKey};
use serde::Serialize;
use wasm_bindgen::prelude::*;

fn js_error(message: impl std::fmt::Display) -> JsValue {
    JsError::new(&message.to_string()).into()
}

fn to_js<T: Serialize>(value: &T) -> Result<JsValue, JsValue> {
    // `null`, not `undefined`, for what is missing.
    value
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(js_error)
}

fn time(unix_ms: f64) -> Result<NaiveDateTime, JsValue> {
    DateTime::from_timestamp((unix_ms / 1000.0).floor() as i64, 0)
        .map(|t| t.naive_utc())
        .ok_or_else(|| js_error("invalid time"))
}

fn key(password: Option<String>, key_file: Option<Vec<u8>>) -> Result<VaultKey, JsValue> {
    if password.is_none() && key_file.is_none() {
        return Err(js_error("a vault needs a password or a key file"));
    }
    let mut key = VaultKey::new();
    if let Some(password) = password {
        key = key.with_password(&password);
    }
    if let Some(file) = key_file {
        key = key.with_key_file(&file);
    }
    Ok(key)
}

/// What a merge did, and whether its result differs from what the other
/// side holds (then it needs saving).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MergeOutcome {
    report: kutup_pass::MergeReport,
    differs_from_theirs: bool,
}

/// One open vault.
#[wasm_bindgen]
pub struct Vault {
    db: Database,
    key: VaultKey,
}

#[wasm_bindgen]
impl Vault {
    /// A new, empty vault with KeePassXC's defaults.
    pub fn create(
        name: &str,
        password: Option<String>,
        key_file: Option<Vec<u8>>,
        now_ms: f64,
    ) -> Result<Vault, JsValue> {
        let key = key(password, key_file)?;
        let db = edit::new_vault(name, time(now_ms)?).map_err(js_error)?;
        Ok(Vault { db, key })
    }

    /// Opens a vault's file contents. Fails with a wrong key or a file that
    /// is not a KeePass vault. The password may be given as its SHA-256
    /// (`password_hash`, what Kutup Pass keeps), which opens and saves the
    /// vault as the password does.
    pub fn open(
        contents: &[u8],
        password: Option<String>,
        password_hash: Option<Vec<u8>>,
        key_file: Option<Vec<u8>>,
    ) -> Result<Vault, JsValue> {
        let key = match password_hash {
            Some(hash) if password.is_none() => {
                let hash: [u8; 32] = hash
                    .try_into()
                    .map_err(|_| js_error("a password hash is 32 bytes"))?;
                let mut key = VaultKey::new().with_password_hash(hash);
                if let Some(file) = key_file {
                    key = key.with_key_file(&file);
                }
                key
            }
            Some(_) => return Err(js_error("give the password or its hash, not both")),
            None => key(password, key_file)?,
        };
        let db = kutup_pass::open(contents, &key).map_err(js_error)?;
        Ok(Vault { db, key })
    }

    /// The whole vault: `kutup_pass::view::VaultView`.
    pub fn view(&self) -> Result<JsValue, JsValue> {
        to_js(&view::view(&self.db))
    }

    /// Applies one operation (`kutup_pass::edit::Op` as an object, e.g.
    /// `{ op: "updateEntry", id, entry }`); returns `{ id, changed }`. A
    /// refused operation throws and changes nothing.
    pub fn apply(&mut self, op: JsValue, now_ms: f64) -> Result<JsValue, JsValue> {
        let op: Op = serde_wasm_bindgen::from_value(op).map_err(js_error)?;
        let applied = edit::apply(&mut self.db, &op, time(now_ms)?).map_err(js_error)?;
        to_js(&applied)
    }

    fn entry(&self, id: &str) -> Result<&kutup_pass::keepass::db::Entry, JsValue> {
        uuid::Uuid::parse_str(id)
            .ok()
            .and_then(|id| self.db.entries.get(&EntryId::from(id)))
            .ok_or_else(|| js_error("no such entry"))
    }

    /// An entry's earlier states, oldest first.
    pub fn history(&self, entry_id: &str) -> Result<JsValue, JsValue> {
        to_js(&view::history(&self.db, self.entry(entry_id)?))
    }

    /// The contents of an entry's attachment.
    pub fn attachment(&self, entry_id: &str, name: &str) -> Result<Vec<u8>, JsValue> {
        view::attachment(&self.db, self.entry(entry_id)?, name)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| js_error("no such attachment"))
    }

    /// The entry's one-time code now (`{ code, period, remaining }`), or
    /// `null` without a readable TOTP secret.
    pub fn otp(&self, entry_id: &str, now_ms: f64) -> Result<JsValue, JsValue> {
        let seconds = (now_ms / 1000.0).floor().max(0.0) as u64;
        to_js(&view::otp(self.entry(entry_id)?, seconds))
    }

    /// The vault as KDBX 4.1 file contents.
    pub fn save(&self) -> Result<Vec<u8>, JsValue> {
        kutup_pass::save(&self.db, &self.key).map_err(js_error)
    }

    /// Merges this vault (ours) with `theirs` against `base` (the version
    /// ours started from; `null` when unknown) and keeps the result here.
    /// Both open with this vault's key, or `theirs` with the key given (a
    /// key changed elsewhere, then adopted). Returns `{ report,
    /// differsFromTheirs }`.
    #[wasm_bindgen(js_name = mergeWith)]
    pub fn merge_with(
        &mut self,
        base: Option<Vec<u8>>,
        theirs: &[u8],
        theirs_password: Option<String>,
        theirs_key_file: Option<Vec<u8>>,
    ) -> Result<JsValue, JsValue> {
        let base = match base {
            // A base under an older key is merged without (KeePassXC's rules).
            Some(contents) => kutup_pass::open(&contents, &self.key).ok(),
            None => None,
        };
        let (theirs_db, theirs_key) = match kutup_pass::open(theirs, &self.key) {
            Ok(db) => (db, None),
            Err(_) if theirs_password.is_some() || theirs_key_file.is_some() => {
                let other = key(theirs_password, theirs_key_file)?;
                let db = kutup_pass::open(theirs, &other).map_err(js_error)?;
                (db, Some(other))
            }
            Err(error) => return Err(js_error(error)),
        };
        let (merged, report) = kutup_pass::merge(base.as_ref(), &self.db, &theirs_db);
        let mut a = merged.clone();
        a.config = theirs_db.config.clone();
        let differs_from_theirs = a != theirs_db;
        self.db = merged;
        if let Some(key) = theirs_key {
            self.key = key;
        }
        to_js(&MergeOutcome {
            report,
            differs_from_theirs,
        })
    }

    /// Changes the vault's key (saved with the next `save`).
    #[wasm_bindgen(js_name = changeKey)]
    pub fn change_key(
        &mut self,
        password: Option<String>,
        key_file: Option<Vec<u8>>,
        now_ms: f64,
    ) -> Result<(), JsValue> {
        self.key = key(password, key_file)?;
        self.db.meta.master_key_changed = Some(time(now_ms)?);
        Ok(())
    }
}

/// A key file as a vault secret keeps it (`kutup_pass::key_file_secret`).
#[wasm_bindgen(js_name = keyFileSecret)]
pub fn key_file_secret(contents: &[u8]) -> Vec<u8> {
    kutup_pass::key_file_secret(contents)
}

/// An import read but not applied: what it would make.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ImportPreview {
    provider: &'static str,
    provider_name: &'static str,
    count: usize,
    /// The group paths it would make, `a/b`.
    groups: Vec<String>,
    /// The first entries, to show.
    sample: Vec<ImportSample>,
    skipped: Vec<String>,
    warnings: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ImportSample {
    title: String,
    username: String,
    url: String,
    group: String,
}

/// Why a file cannot be imported, as a code the page translates.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ImportFailure {
    error: &'static str,
    detail: String,
}

/// The formats an import can be read as: `[{ id, name }]`.
#[wasm_bindgen(js_name = importFormats)]
pub fn import_formats() -> Result<JsValue, JsValue> {
    #[derive(Serialize)]
    struct Format {
        id: &'static str,
        name: &'static str,
    }
    let formats: Vec<Format> = kutup_pass::import::Provider::ALL
        .iter()
        .map(|p| Format {
            id: p.id(),
            name: p.name(),
        })
        .collect();
    to_js(&formats)
}

/// Reads another password manager's export without changing any vault:
/// `ImportPreview`, or `{ error, detail }` (`empty`, `tooLarge`, `unreadable`,
/// `unknownFormat`, `missingColumns`, `tooMany`). `provider`: a format id, or
/// null to detect it.
#[wasm_bindgen(js_name = importPreview)]
pub fn import_preview(data: &[u8], provider: Option<String>) -> Result<JsValue, JsValue> {
    use kutup_pass::import::{parse, ImportError, Provider};
    let provider = match provider {
        Some(id) => Some(Provider::from_id(&id).ok_or_else(|| js_error("no such import format"))?),
        None => None,
    };
    match parse(data, provider) {
        Ok(parsed) => {
            let mut groups: Vec<String> = parsed
                .entries
                .iter()
                .filter(|e| !e.group.is_empty())
                .map(|e| e.group.join("/"))
                .collect();
            groups.sort();
            groups.dedup();
            to_js(&ImportPreview {
                provider: parsed.provider.id(),
                provider_name: parsed.provider.name(),
                count: parsed.entries.len(),
                groups,
                sample: parsed
                    .entries
                    .iter()
                    .take(50)
                    .map(|e| ImportSample {
                        title: e.title.clone(),
                        username: e.username.clone(),
                        url: e.urls.first().cloned().unwrap_or_default(),
                        group: e.group.join("/"),
                    })
                    .collect(),
                skipped: parsed.skipped,
                warnings: parsed.warnings,
            })
        }
        Err(error) => {
            let (code, detail) = match &error {
                ImportError::Empty => ("empty", String::new()),
                ImportError::TooLarge => ("tooLarge", String::new()),
                ImportError::Unreadable(why) => ("unreadable", why.clone()),
                ImportError::UnknownFormat => ("unknownFormat", String::new()),
                ImportError::MissingColumns(_, columns) => ("missingColumns", columns.clone()),
                ImportError::TooMany => ("tooMany", String::new()),
            };
            to_js(&ImportFailure {
                error: code,
                detail,
            })
        }
    }
}
