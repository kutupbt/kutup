//! Importing from other password managers (docs/plans/pass.md, "Import"):
//! their CSV exports, read into vault entries. Each app's export is known by
//! its header row (Proton Pass's and KeePassXC's importers were the models);
//! a CSV that is none of them is read by its column names. Nothing is
//! dropped silently: columns without a KeePass field become custom fields,
//! values that cannot be read (a one-time code secret, say) are kept as
//! hidden fields, and what was not imported is reported with why.

use chrono::{DateTime, NaiveDateTime};
use serde::Serialize;

use crate::view::FieldView;

/// The largest file read (a CSV of tens of thousands of entries is far less).
pub const MAX_IMPORT_BYTES: usize = 20 * 1024 * 1024;
/// The most entries one import makes.
pub const MAX_IMPORT_ENTRIES: usize = 50_000;

/// Where an export came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Provider {
    KeePassXc,
    Bitwarden,
    OnePassword,
    LastPass,
    ProtonPass,
    NordPass,
    Dashlane,
    Chrome,
    Firefox,
    Safari,
    Generic,
}

impl Provider {
    /// Every format, in the order the import dialog offers them.
    pub const ALL: [Provider; 11] = [
        Provider::KeePassXc,
        Provider::Bitwarden,
        Provider::OnePassword,
        Provider::LastPass,
        Provider::ProtonPass,
        Provider::NordPass,
        Provider::Dashlane,
        Provider::Chrome,
        Provider::Firefox,
        Provider::Safari,
        Provider::Generic,
    ];

    pub fn id(self) -> &'static str {
        match self {
            Provider::KeePassXc => "keepassxc",
            Provider::Bitwarden => "bitwarden",
            Provider::OnePassword => "onepassword",
            Provider::LastPass => "lastpass",
            Provider::ProtonPass => "protonpass",
            Provider::NordPass => "nordpass",
            Provider::Dashlane => "dashlane",
            Provider::Chrome => "chrome",
            Provider::Firefox => "firefox",
            Provider::Safari => "safari",
            Provider::Generic => "generic",
        }
    }

    /// The app's own name (not translated).
    pub fn name(self) -> &'static str {
        match self {
            Provider::KeePassXc => "KeePassXC",
            Provider::Bitwarden => "Bitwarden",
            Provider::OnePassword => "1Password",
            Provider::LastPass => "LastPass",
            Provider::ProtonPass => "Proton Pass",
            Provider::NordPass => "NordPass",
            Provider::Dashlane => "Dashlane",
            Provider::Chrome => "Chrome, Edge or Brave",
            Provider::Firefox => "Firefox",
            Provider::Safari => "Safari or Apple Passwords",
            Provider::Generic => "CSV",
        }
    }

    pub fn from_id(id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.id() == id)
    }

    /// The columns an export of this app always has (lower case).
    fn required(self) -> &'static [&'static str] {
        match self {
            Provider::KeePassXc => &["group", "title", "username", "password", "url", "notes"],
            Provider::Bitwarden => &["name", "login_uri", "login_username", "login_password"],
            Provider::OnePassword => &["title", "username", "password", "archived"],
            Provider::LastPass => &["url", "username", "password", "extra", "name", "grouping"],
            Provider::ProtonPass => &["name", "url", "username", "password", "note", "totp"],
            Provider::NordPass => &[
                "name", "url", "username", "password", "note", "folder", "type",
            ],
            Provider::Dashlane => &["username", "username2", "title", "password", "note", "url"],
            Provider::Chrome => &["name", "url", "username", "password"],
            Provider::Firefox => &["url", "username", "password", "timepasswordchanged"],
            Provider::Safari => &["title", "url", "username", "password"],
            Provider::Generic => &[],
        }
    }
}

/// One entry to make.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportedEntry {
    /// The group path inside the import's own group.
    pub group: Vec<String>,
    pub title: String,
    pub username: String,
    pub password: String,
    /// The first is the entry's URL; the others go in KeePass's extra URL
    /// fields (`KP2A_URL_1`…).
    pub urls: Vec<String>,
    pub notes: String,
    /// An `otpauth://` URI (KeePassXC's `otp` field).
    pub otp: Option<String>,
    pub tags: Vec<String>,
    /// Everything else, by name.
    pub fields: Vec<FieldView>,
    #[serde(skip)]
    pub created: Option<NaiveDateTime>,
    #[serde(skip)]
    pub modified: Option<NaiveDateTime>,
}

/// A file read.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Parsed {
    pub provider: Provider,
    pub entries: Vec<ImportedEntry>,
    /// What was not imported: `"<kind>: <title>"`.
    pub skipped: Vec<String>,
    /// What was imported with a change (an unreadable code kept aside…).
    pub warnings: Vec<String>,
}

/// Why a file could not be read. Nothing is imported then.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ImportError {
    #[error("the file is empty")]
    Empty,
    #[error("the file is larger than 20 MB")]
    TooLarge,
    #[error("the file is not a CSV this can read: {0}")]
    Unreadable(String),
    #[error("the columns do not look like a password export")]
    UnknownFormat,
    #[error("the file lacks columns {0} expects: {1}")]
    MissingColumns(String, String),
    #[error("the file holds more than 50000 entries")]
    TooMany,
}

/// The text of a file: UTF-8 or UTF-16 (by its byte-order mark).
fn decode(bytes: &[u8]) -> Result<String, ImportError> {
    if let Some(rest) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        return String::from_utf8(rest.to_vec())
            .map_err(|_| ImportError::Unreadable("not UTF-8".into()));
    }
    let utf16 = |rest: &[u8], le: bool| -> Result<String, ImportError> {
        let units: Vec<u16> = rest
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| {
                if le {
                    u16::from_le_bytes(*c)
                } else {
                    u16::from_be_bytes(*c)
                }
            })
            .collect();
        String::from_utf16(&units).map_err(|_| ImportError::Unreadable("not UTF-16".into()))
    };
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        return utf16(rest, true);
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        return utf16(rest, false);
    }
    String::from_utf8(bytes.to_vec())
        .map_err(|_| ImportError::Unreadable("not UTF-8 (export it as UTF-8)".into()))
}

/// The separator of the header line: comma, semicolon or tab, the most
/// frequent outside quotes.
fn separator(text: &str) -> u8 {
    let mut counts = [(b',', 0usize), (b';', 0), (b'\t', 0)];
    let mut quoted = false;
    for c in text.bytes() {
        match c {
            b'"' => quoted = !quoted,
            b'\n' | b'\r' if !quoted => break,
            _ if !quoted => {
                for (sep, count) in counts.iter_mut() {
                    if c == *sep {
                        *count += 1;
                    }
                }
            }
            _ => {}
        }
    }
    counts
        .iter()
        .max_by_key(|(_, n)| *n)
        .filter(|(_, n)| *n > 0)
        .map_or(b',', |(s, _)| *s)
}

/// One data row by lower-case column name, with the columns' own names.
struct Row {
    values: Vec<(String, String, String)>, // (lower, original, value)
}

impl Row {
    fn get(&self, column: &str) -> &str {
        self.values
            .iter()
            .find(|(lower, _, _)| lower == column)
            .map_or("", |(_, _, v)| v.trim())
    }

    fn first(&self, columns: &[&str]) -> &str {
        columns
            .iter()
            .map(|c| self.get(c))
            .find(|v| !v.is_empty())
            .unwrap_or("")
    }

    /// The non-empty columns not in `used`, as custom fields.
    fn rest(&self, used: &[&str]) -> Vec<FieldView> {
        self.values
            .iter()
            .filter(|(lower, _, value)| !value.trim().is_empty() && !used.contains(&lower.as_str()))
            .map(|(lower, original, value)| field(original, value.trim(), looks_secret(lower)))
            .collect()
    }
}

fn field(key: &str, value: &str, protected: bool) -> FieldView {
    FieldView {
        key: key.trim().to_owned(),
        value: value.to_owned(),
        protected,
    }
}

fn looks_secret(name: &str) -> bool {
    [
        "password",
        "passwd",
        "pin",
        "secret",
        "cvv",
        "cvc",
        "security code",
        "otp",
        "totp",
        "private",
        "recovery",
    ]
    .iter()
    .any(|word| name.contains(word))
}

fn read_rows(text: &str) -> Result<(Vec<String>, Vec<Row>), ImportError> {
    let mut reader = csv::ReaderBuilder::new()
        .delimiter(separator(text))
        .flexible(true)
        .has_headers(true)
        .from_reader(text.as_bytes());
    let headers: Vec<String> = reader
        .headers()
        .map_err(|e| ImportError::Unreadable(e.to_string()))?
        .iter()
        .map(|h| h.trim().to_owned())
        .collect();
    if headers.iter().all(|h| h.is_empty()) {
        return Err(ImportError::Empty);
    }
    let lower: Vec<String> = headers.iter().map(|h| h.to_lowercase()).collect();
    let mut rows = Vec::new();
    for record in reader.records() {
        let record = record.map_err(|e| ImportError::Unreadable(e.to_string()))?;
        if record.iter().all(|v| v.trim().is_empty()) {
            continue;
        }
        let values = record
            .iter()
            .enumerate()
            .map(|(i, v)| {
                let name = headers
                    .get(i)
                    .cloned()
                    .unwrap_or_else(|| format!("Column {}", i + 1));
                (
                    lower.get(i).cloned().unwrap_or_else(|| name.to_lowercase()),
                    name,
                    v.to_owned(),
                )
            })
            .collect();
        rows.push(Row { values });
    }
    Ok((lower, rows))
}

/// Which app made a file with these columns.
pub fn detect(columns: &[String]) -> Option<Provider> {
    let has = |c: &&str| columns.iter().any(|h| h == c);
    // The most specific first: 1Password's columns include Safari's.
    let order = [
        Provider::Bitwarden,
        Provider::NordPass,
        Provider::LastPass,
        Provider::ProtonPass,
        Provider::KeePassXc,
        Provider::Dashlane,
        Provider::Firefox,
        Provider::OnePassword,
        Provider::Safari,
        Provider::Chrome,
    ];
    order
        .into_iter()
        .find(|p| p.required().iter().all(has))
        .or_else(|| detect_generic(columns))
}

const GENERIC_TITLE: &[&str] = &["title", "name", "account", "entry", "item", "label"];
const GENERIC_USERNAME: &[&str] = &[
    "username",
    "user name",
    "user",
    "login",
    "login_username",
    "email",
    "e-mail",
    "login name",
];
const GENERIC_PASSWORD: &[&str] = &["password", "pass", "pwd", "login_password"];
const GENERIC_URL: &[&str] = &[
    "url",
    "urls",
    "website",
    "web site",
    "uri",
    "login_uri",
    "site",
    "address",
    "web address",
];
const GENERIC_NOTES: &[&str] = &[
    "notes",
    "note",
    "comments",
    "comment",
    "extra",
    "description",
];
const GENERIC_OTP: &[&str] = &[
    "totp",
    "otp",
    "otpauth",
    "2fa",
    "one-time code",
    "login_totp",
    "authenticator",
];
const GENERIC_GROUP: &[&str] = &[
    "group",
    "folder",
    "category",
    "vault",
    "grouping",
    "collection",
];
const GENERIC_TAGS: &[&str] = &["tags", "tag", "labels"];

/// Reads an export. `provider` forces a format; otherwise it is detected.
pub fn parse(bytes: &[u8], provider: Option<Provider>) -> Result<Parsed, ImportError> {
    if bytes.is_empty() {
        return Err(ImportError::Empty);
    }
    if bytes.len() > MAX_IMPORT_BYTES {
        return Err(ImportError::TooLarge);
    }
    let text = decode(bytes)?;
    let (columns, rows) = read_rows(&text)?;
    let provider = match provider {
        Some(p) => {
            let missing: Vec<&str> = p
                .required()
                .iter()
                .copied()
                .filter(|c| !columns.iter().any(|h| h == c))
                .collect();
            if !missing.is_empty() {
                return Err(ImportError::MissingColumns(
                    p.name().into(),
                    missing.join(", "),
                ));
            }
            if p == Provider::Generic && detect_generic(&columns).is_none() {
                return Err(ImportError::UnknownFormat);
            }
            p
        }
        None => detect(&columns).ok_or(ImportError::UnknownFormat)?,
    };
    if rows.is_empty() {
        return Err(ImportError::Empty);
    }
    if rows.len() > MAX_IMPORT_ENTRIES {
        return Err(ImportError::TooMany);
    }
    let mut parsed = Parsed {
        provider,
        entries: Vec::new(),
        skipped: Vec::new(),
        warnings: Vec::new(),
    };
    for row in &rows {
        match read_row(provider, row, &mut parsed.warnings) {
            Read::Entry(entry) => parsed.entries.push(*entry),
            Read::Skip(reason) => parsed.skipped.push(reason),
            Read::Nothing => {}
        }
    }
    if provider == Provider::KeePassXc {
        strip_shared_root(&mut parsed.entries);
    }
    if parsed.entries.is_empty() && parsed.skipped.is_empty() {
        return Err(ImportError::Empty);
    }
    Ok(parsed)
}

fn detect_generic(columns: &[String]) -> Option<Provider> {
    let has = |names: &[&str]| names.iter().any(|n| columns.iter().any(|h| h == n));
    ((has(GENERIC_PASSWORD) || has(GENERIC_USERNAME)) && (has(GENERIC_TITLE) || has(GENERIC_URL)))
        .then_some(Provider::Generic)
}

enum Read {
    Entry(Box<ImportedEntry>),
    Skip(String),
    /// A row that is not an entry (NordPass's folder rows).
    Nothing,
}

/// A host name for a title, from a URL with or without a scheme.
pub fn hostname(url: &str) -> Option<String> {
    let rest = url
        .trim()
        .split_once("://")
        .map_or(url.trim(), |(_, rest)| rest);
    let host = rest
        .split(['/', '?', '#'])
        .next()?
        .rsplit('@')
        .next()?
        .split(':')
        .next()?;
    (!host.is_empty()).then(|| host.trim_start_matches("www.").to_owned())
}

fn split_path(path: &str) -> Vec<String> {
    path.replace('\\', "/")
        .split('/')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(str::to_owned)
        .collect()
}

fn split_tags(tags: &str) -> Vec<String> {
    tags.split([',', ';'])
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_owned)
        .collect()
}

fn percent_encode(text: &str) -> String {
    text.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// A one-time code secret as KeePassXC keeps it (`otpauth://`): from a URI,
/// a bare base32 secret, or KeeOTP's `key=…&size=…&step=…`.
pub fn normalize_otp(value: &str, label: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if value.to_ascii_lowercase().starts_with("otpauth://") {
        return Some(value.to_owned());
    }
    let (secret, digits, period) = if value.contains("key=") {
        let mut secret = "";
        let mut digits = "6";
        let mut period = "30";
        for part in value.split('&') {
            match part.split_once('=') {
                Some(("key", v)) => secret = v,
                Some(("size", v)) => digits = v,
                Some(("step", v)) => period = v,
                _ => {}
            }
        }
        (secret.to_owned(), digits.to_owned(), period.to_owned())
    } else {
        (value.to_owned(), "6".into(), "30".into())
    };
    let secret: String = secret
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .to_uppercase();
    let secret = secret.trim_end_matches('=');
    let base32 = secret.len() >= 16
        && secret
            .chars()
            .all(|c| c.is_ascii_uppercase() || ('2'..='7').contains(&c));
    if !base32 || digits.parse::<u8>().is_err() || period.parse::<u32>().is_err() {
        return None;
    }
    let label = if label.is_empty() {
        "Kutup Pass"
    } else {
        label
    };
    Some(format!(
        "otpauth://totp/{}?secret={secret}&period={period}&digits={digits}&algorithm=SHA1",
        percent_encode(label)
    ))
}

/// A time: epoch seconds, epoch milliseconds, or ISO 8601.
pub fn parse_time(value: &str) -> Option<NaiveDateTime> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if value.chars().all(|c| c.is_ascii_digit()) {
        let number: i64 = value.parse().ok()?;
        let seconds = if number > i64::from(i32::MAX) {
            number / 1000
        } else {
            number
        };
        return DateTime::from_timestamp(seconds, 0).map(|t| t.naive_utc());
    }
    DateTime::parse_from_rfc3339(value)
        .map(|t| t.naive_utc())
        .ok()
        .or_else(|| crate::view::parse_time(value))
}

/// The entry, finished: title fallback, one-time code read or kept aside.
fn finish(mut entry: ImportedEntry, otp_raw: &str, warnings: &mut Vec<String>) -> ImportedEntry {
    entry.urls.retain(|u| !u.trim().is_empty());
    entry.urls.dedup();
    if entry.title.trim().is_empty() {
        entry.title = entry
            .urls
            .first()
            .and_then(|u| hostname(u))
            .or_else(|| (!entry.username.is_empty()).then(|| entry.username.clone()))
            .unwrap_or_else(|| "Untitled".into());
    }
    if !otp_raw.trim().is_empty() {
        match normalize_otp(otp_raw, &entry.title) {
            Some(uri) => entry.otp = Some(uri),
            None => {
                warnings.push(format!("{}: the one-time code secret could not be read; it is kept as the hidden field \"TOTP\"", entry.title));
                entry.fields.push(field("TOTP", otp_raw.trim(), true));
            }
        }
    }
    entry
}

fn is_empty(entry: &ImportedEntry) -> bool {
    entry.title.is_empty()
        && entry.username.is_empty()
        && entry.password.is_empty()
        && entry.urls.is_empty()
        && entry.notes.is_empty()
        && entry.fields.is_empty()
}

fn read_row(provider: Provider, row: &Row, warnings: &mut Vec<String>) -> Read {
    let mut entry = ImportedEntry::default();
    let mut otp = String::new();
    match provider {
        Provider::KeePassXc => {
            entry.group = split_path(row.get("group"));
            entry.title = row.get("title").into();
            entry.username = row.get("username").into();
            entry.password = row.get("password").into();
            entry.urls = vec![row.get("url").into()];
            entry.notes = row.get("notes").into();
            entry.tags = split_tags(row.get("tags"));
            otp = row.get("totp").into();
            entry.modified = parse_time(row.get("last modified"));
            entry.created = parse_time(row.get("created"));
        }
        Provider::Bitwarden => {
            entry.group = split_path(row.first(&["folder", "collections"]));
            entry.title = row.get("name").into();
            entry.notes = row.get("notes").into();
            if row.get("favorite") == "1" {
                entry.tags.push("Favorite".into());
            }
            for line in row.get("fields").lines() {
                if let Some((name, value)) = line.rsplit_once(": ") {
                    entry
                        .fields
                        .push(field(name, value, looks_secret(&name.to_lowercase())));
                } else if !line.trim().is_empty() {
                    entry.fields.push(field("Field", line, false));
                }
            }
            match row.get("type") {
                "note" | "login" | "" => {}
                other => return Read::Skip(format!("{other}: {}", entry.title)),
            }
            entry.username = row.first(&["login_username", "username"]).into();
            entry.password = row.first(&["login_password", "password"]).into();
            entry.urls = row
                .first(&["login_uri", "uri"])
                .split([',', '\n'])
                .map(|u| u.trim().to_owned())
                .collect();
            otp = row.first(&["login_totp", "totp"]).into();
        }
        Provider::OnePassword => {
            entry.title = row.get("title").into();
            entry.username = row.get("username").into();
            entry.password = row.get("password").into();
            entry.urls = row
                .first(&["url", "urls"])
                .lines()
                .map(|u| u.trim().to_owned())
                .collect();
            entry.notes = row.first(&["notes", "notesplain"]).into();
            entry.tags = split_tags(row.get("tags"));
            if row.get("favorite").eq_ignore_ascii_case("true") {
                entry.tags.push("Favorite".into());
            }
            if row.get("archived").eq_ignore_ascii_case("true") {
                entry.tags.push("Archived".into());
            }
            otp = row.first(&["otpauth", "one-time password"]).into();
            entry.fields = row.rest(&[
                "title",
                "username",
                "password",
                "url",
                "urls",
                "notes",
                "notesplain",
                "tags",
                "favorite",
                "archived",
                "otpauth",
                "one-time password",
            ]);
        }
        Provider::LastPass => {
            entry.group = split_path(row.get("grouping"));
            entry.title = row.get("name").into();
            if row.get("fav") == "1" {
                entry.tags.push("Favorite".into());
            }
            // Secure notes (cards, addresses…): the note text holds them whole.
            if row.get("url") == "http://sn" {
                entry.notes = row.get("extra").into();
            } else {
                entry.username = row.get("username").into();
                entry.password = row.get("password").into();
                entry.urls = vec![row.get("url").into()];
                entry.notes = row.get("extra").into();
                otp = row.get("totp").into();
            }
        }
        Provider::ProtonPass => {
            entry.group = split_path(row.get("vault"));
            entry.title = row.get("name").into();
            entry.notes = row.get("note").into();
            entry.created = parse_time(row.get("createtime"));
            entry.modified = parse_time(row.get("modifytime"));
            match row.get("type") {
                "alias" => {
                    return Read::Skip(format!(
                        "alias: {} (an email alias, not a password)",
                        entry.title
                    ))
                }
                "creditCard" | "identity" => {
                    // The details are JSON in the note column.
                    let details = std::mem::take(&mut entry.notes);
                    match serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(
                        &details,
                    ) {
                        Ok(map) => {
                            for (key, value) in map {
                                let value = match value {
                                    serde_json::Value::String(s) => s,
                                    serde_json::Value::Null => continue,
                                    other => other.to_string(),
                                };
                                if !value.is_empty() {
                                    entry.fields.push(field(
                                        &key,
                                        &value,
                                        looks_secret(&key.to_lowercase())
                                            || key == "number"
                                            || key == "verificationNumber",
                                    ));
                                }
                            }
                        }
                        Err(_) => entry.notes = details,
                    }
                    entry.tags.push(if row.get("type") == "creditCard" {
                        "Card".into()
                    } else {
                        "Identity".into()
                    });
                }
                _ => {
                    let email = row.get("email");
                    entry.username = if row.get("username").is_empty() {
                        email.into()
                    } else {
                        row.get("username").into()
                    };
                    if !email.is_empty() && email != entry.username {
                        entry.fields.push(field("Email", email, false));
                    }
                    entry.password = row.get("password").into();
                    entry.urls = row
                        .get("url")
                        .split(", ")
                        .map(|u| u.trim().to_owned())
                        .collect();
                    otp = row.get("totp").into();
                }
            }
        }
        Provider::NordPass => {
            entry.group = split_path(row.get("folder"));
            entry.title = row.get("name").into();
            entry.notes = row.get("note").into();
            match row.get("type") {
                "folder" => return Read::Nothing,
                "password" | "" => {
                    entry.username = row.get("username").into();
                    entry.password = row.get("password").into();
                    entry.urls = vec![row.get("url").into()];
                    if let Ok(more) =
                        serde_json::from_str::<Vec<String>>(row.get("additional_urls"))
                    {
                        entry.urls.extend(more);
                    }
                    if let Ok(custom) =
                        serde_json::from_str::<Vec<serde_json::Value>>(row.get("custom_fields"))
                    {
                        for item in custom {
                            let label = item["label"].as_str().unwrap_or("Field");
                            let value = item["value"].as_str().unwrap_or("");
                            if !value.is_empty() {
                                entry
                                    .fields
                                    .push(field(label, value, item["type"] == "hidden"));
                            }
                        }
                    }
                }
                "credit_card" => {
                    for (column, name, secret) in [
                        ("cardholdername", "Cardholder", false),
                        ("cardnumber", "Card number", true),
                        ("cvc", "Security code", true),
                        ("expirydate", "Expiry", false),
                        ("zipcode", "Postal code", false),
                    ] {
                        if !row.get(column).is_empty() {
                            entry.fields.push(field(name, row.get(column), secret));
                        }
                    }
                    entry.tags.push("Card".into());
                }
                "identity" => {
                    for (column, name) in [
                        ("full_name", "Full name"),
                        ("email", "Email"),
                        ("phone_number", "Phone"),
                        ("address1", "Address"),
                        ("address2", "Address line 2"),
                        ("city", "City"),
                        ("state", "State"),
                        ("zipcode", "Postal code"),
                        ("country", "Country"),
                    ] {
                        if !row.get(column).is_empty() {
                            entry.fields.push(field(name, row.get(column), false));
                        }
                    }
                    entry.tags.push("Identity".into());
                }
                "note" => {}
                other => return Read::Skip(format!("{other}: {}", entry.title)),
            }
        }
        Provider::Dashlane => {
            entry.group = split_path(row.get("category"));
            entry.title = row.get("title").into();
            entry.username = row.get("username").into();
            entry.password = row.get("password").into();
            entry.urls = vec![row.get("url").into()];
            entry.notes = row.get("note").into();
            for column in ["username2", "username3"] {
                if !row.get(column).is_empty() {
                    entry
                        .fields
                        .push(field("Other user name", row.get(column), false));
                }
            }
            otp = row.first(&["otpurl", "otpsecret"]).into();
        }
        Provider::Chrome => {
            entry.title = row.get("name").into();
            entry.username = row.get("username").into();
            entry.password = row.get("password").into();
            entry.urls = vec![row.get("url").into()];
            entry.notes = row.get("note").into();
        }
        Provider::Firefox => {
            if row.get("url") == "chrome://FirefoxAccounts" {
                return Read::Nothing;
            }
            entry.username = row.get("username").into();
            entry.password = row.get("password").into();
            entry.urls = vec![row.get("url").into()];
            entry.created = parse_time(row.get("timecreated"));
            entry.modified = parse_time(row.get("timepasswordchanged"));
        }
        Provider::Safari => {
            entry.title = row.get("title").into();
            entry.username = row.get("username").into();
            entry.password = row.get("password").into();
            entry.urls = vec![row.get("url").into()];
            entry.notes = row.get("notes").into();
            otp = row.get("otpauth").into();
        }
        Provider::Generic => {
            entry.title = row.first(GENERIC_TITLE).into();
            entry.username = row.first(GENERIC_USERNAME).into();
            entry.password = row.first(GENERIC_PASSWORD).into();
            entry.urls = row
                .first(GENERIC_URL)
                .split(['\n', ','])
                .map(|u| u.trim().to_owned())
                .collect();
            entry.notes = row.first(GENERIC_NOTES).into();
            entry.group = split_path(row.first(GENERIC_GROUP));
            entry.tags = split_tags(row.first(GENERIC_TAGS));
            otp = row.first(GENERIC_OTP).into();
            let used: Vec<&str> = [
                GENERIC_TITLE,
                GENERIC_USERNAME,
                GENERIC_PASSWORD,
                GENERIC_URL,
                GENERIC_NOTES,
                GENERIC_OTP,
                GENERIC_GROUP,
                GENERIC_TAGS,
            ]
            .concat()
            .into_iter()
            .collect();
            entry.fields = row.rest(&used);
        }
    }
    let entry = finish(entry, &otp, warnings);
    if is_empty(&entry)
        || (entry.title == "Untitled"
            && entry.username.is_empty()
            && entry.password.is_empty()
            && entry.urls.is_empty()
            && entry.notes.is_empty())
    {
        return Read::Nothing;
    }
    Read::Entry(Box::new(entry))
}

/// KeePassXC writes every group path from the root ("Root/Banks"): when all
/// share their first part, it is the old vault's root and is dropped.
fn strip_shared_root(entries: &mut [ImportedEntry]) {
    let Some(first) = entries.first().and_then(|e| e.group.first()).cloned() else {
        return;
    };
    if entries.iter().all(|e| e.group.first() == Some(&first)) {
        for entry in entries {
            entry.group.remove(0);
        }
    }
}
