//! Field references and placeholders (docs/plans/pass-gaps-3.md, B1), as
//! KeePassXC resolves them (`src/core/Entry.cpp`,
//! `src/core/EntryPlaceholders.cpp`; KeePass's "Field References"):
//!
//! - `{REF:<field>@<search>:<text>}`: the field (T title, U user name,
//!   P password, A URL, N notes, I UUID) of the first entry whose field
//!   (T, U, P, A, N, I, or O any other field) equals the text; nothing when
//!   none does;
//! - `{TITLE}`, `{USERNAME}`, `{PASSWORD}`, `{URL}`, `{NOTES}`, `{UUID}`,
//!   `{TOTP}`, `{S:<field>}`, the URL's parts (`{URL:HOST}`…), the date and
//!   time (`{DT_SIMPLE}`, `{DT_UTC_YEAR}`…) and `{T-CONV:/text/kind/}`;
//! - resolved again inside what they give, up to ten levels; anything else in
//!   braces (auto-type keys, `{CMD:…}`, `{T-REPLACE-RX:…}`) stays as written.
//!
//! Stored values never change: this is for showing, copying and opening.

use base64::Engine as _;
use chrono::NaiveDateTime;
use keepass::db::{Entry, GroupId};
use keepass::Database;

use crate::view::STANDARD_FIELDS;

/// How deep references and placeholders resolve (KeePassXC's limit).
pub const MAX_DEPTH: u32 = 10;

/// What resolving needs besides the vault.
#[derive(Debug, Clone, Copy)]
pub struct Context {
    /// The device's local time, for `{DT_*}`.
    pub local: NaiveDateTime,
    pub utc: NaiveDateTime,
    /// Seconds since 1970, for `{TOTP}`.
    pub unix_seconds: u64,
}

/// `value` of `entry`, its references and placeholders resolved.
pub fn resolve(db: &Database, entry: &Entry, value: &str, context: &Context) -> String {
    multiple(db, entry, value, MAX_DEPTH, context)
}

/// Whether `value` holds anything this would resolve (a reference or a
/// placeholder), so a page can mark the value as coming from elsewhere.
pub fn has_reference(value: &str) -> bool {
    value.to_ascii_uppercase().contains("{REF:")
}

/// The outermost balanced `{…}` spans of `text`, by byte offset.
fn placeholders(text: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut start = 0;
    for (i, c) in text.char_indices() {
        match c {
            '{' => {
                if depth == 0 {
                    start = i;
                }
                depth += 1;
            }
            '}' if depth > 0 => {
                depth -= 1;
                if depth == 0 {
                    out.push((start, i + 1));
                }
            }
            _ => {}
        }
    }
    out
}

fn multiple(db: &Database, entry: &Entry, text: &str, depth: u32, context: &Context) -> String {
    let Some(depth) = depth.checked_sub(1) else {
        return text.to_owned();
    };
    // An escaped placeholder, as KeePassXC: "\{…\}" means the braces themselves.
    if text.len() >= 4 && text.starts_with("\\{") && text.ends_with("\\}") {
        return format!("{{{}}}", &text[2..text.len() - 2]);
    }
    let mut out = String::new();
    let mut at = 0;
    for (start, end) in placeholders(text) {
        out.push_str(&text[at..start]);
        out.push_str(&one(db, entry, &text[start..end], depth, context));
        at = end;
    }
    out.push_str(&text[at..]);
    out
}

fn field<'a>(entry: &'a Entry, key: &str) -> &'a str {
    entry.fields.get(key).map_or("", |v| v.get().as_str())
}

fn uuid_hex(entry: &Entry) -> String {
    entry.id.uuid().simple().to_string()
}

fn one(db: &Database, entry: &Entry, placeholder: &str, depth: u32, context: &Context) -> String {
    let Some(depth) = depth.checked_sub(1) else {
        return placeholder.to_owned();
    };
    let inner = &placeholder[1..placeholder.len() - 1];
    if let Some(key) = placeholder
        .strip_prefix("{S:")
        .and_then(|p| p.strip_suffix('}'))
    {
        // The passkey's private key never resolves into another field
        // (crate::passkey): the page would get it.
        if key == crate::passkey::PRIVATE_KEY_PEM {
            return String::new();
        }
        return match entry.fields.get(key) {
            Some(value) => multiple(db, entry, value.get(), depth, context),
            None => String::new(),
        };
    }
    if placeholder.starts_with("{REF:") {
        return reference(db, entry, placeholder, depth + 1, context);
    }
    let upper = placeholder.to_uppercase();
    if upper.starts_with("{T-CONV:") {
        return conversion(
            db,
            entry,
            &placeholder["{T-CONV:".len()..placeholder.len() - 1],
            depth,
            context,
        )
        .map(|resolved| multiple(db, entry, &resolved, depth, context))
        .unwrap_or_default();
    }
    let standard = |key: &str| multiple(db, entry, field(entry, key), depth, context);
    let date = |time: NaiveDateTime, format: &str| time.format(format).to_string();
    match upper.as_str() {
        "{TITLE}" => standard("Title"),
        "{USERNAME}" => standard("UserName"),
        "{PASSWORD}" => standard("Password"),
        "{NOTES}" => standard("Notes"),
        "{URL}" => standard("URL"),
        "{UUID}" => uuid_hex(entry),
        "{TOTP}" | "{TIMEOTP}" => crate::otp::settings(entry)
            .map(|s| crate::otp::code(&s, context.unix_seconds))
            .unwrap_or_default(),
        "{DT_SIMPLE}" => date(context.local, "%Y%m%d%H%M%S"),
        "{DT_YEAR}" => date(context.local, "%Y"),
        "{DT_MONTH}" => date(context.local, "%m"),
        "{DT_DAY}" => date(context.local, "%d"),
        "{DT_HOUR}" => date(context.local, "%H"),
        "{DT_MINUTE}" => date(context.local, "%M"),
        "{DT_SECOND}" => date(context.local, "%S"),
        "{DT_UTC_SIMPLE}" => date(context.utc, "%Y%m%d%H%M%S"),
        "{DT_UTC_YEAR}" => date(context.utc, "%Y"),
        "{DT_UTC_MONTH}" => date(context.utc, "%m"),
        "{DT_UTC_DAY}" => date(context.utc, "%d"),
        "{DT_UTC_HOUR}" => date(context.utc, "%H"),
        "{DT_UTC_MINUTE}" => date(context.utc, "%M"),
        "{DT_UTC_SECOND}" => date(context.utc, "%S"),
        url_part if url_part.starts_with("{URL:") => {
            match url_placeholder(&standard("URL"), &url_part[5..url_part.len() - 1]) {
                Some(part) => part,
                None => format!("{{{}}}", multiple(db, entry, inner, depth, context)),
            }
        }
        // Not one this resolves (auto-type keys, {CMD:…}): kept, with what
        // is inside it resolved, as KeePassXC.
        _ => format!("{{{}}}", multiple(db, entry, inner, depth, context)),
    }
}

/// A part of `url` for `{URL:<part>}`; `None` for a part this doesn't know.
fn url_placeholder(url: &str, part: &str) -> Option<String> {
    let known = [
        "RMVSCM",
        "WITHOUTSCHEME",
        "SCM",
        "SCHEME",
        "HOST",
        "PORT",
        "PATH",
        "QUERY",
        "FRAGMENT",
        "USERINFO",
        "USERNAME",
        "PASSWORD",
    ];
    if !known.contains(&part) {
        return None;
    }
    if url.is_empty() {
        return Some(String::new());
    }
    let Ok(parsed) = url::Url::parse(url) else {
        return Some(String::new());
    };
    Some(match part {
        "RMVSCM" | "WITHOUTSCHEME" => url
            .split_once(':')
            .map_or(url.to_owned(), |(_, rest)| rest.to_owned()),
        "SCM" | "SCHEME" => parsed.scheme().to_owned(),
        "HOST" => parsed.host_str().unwrap_or("").to_owned(),
        // QUrl's port(): -1 when the URL names none.
        "PORT" => parsed.port().map_or("-1".to_owned(), |p| p.to_string()),
        "PATH" => parsed.path().to_owned(),
        "QUERY" => parsed.query().unwrap_or("").to_owned(),
        "FRAGMENT" => parsed.fragment().unwrap_or("").to_owned(),
        "USERINFO" => match parsed.password() {
            Some(password) => format!("{}:{password}", parsed.username()),
            None => parsed.username().to_owned(),
        },
        "USERNAME" => parsed.username().to_owned(),
        _ => parsed.password().unwrap_or("").to_owned(),
    })
}

/// `{T-CONV:/text/kind/}`: base64, hex, uri, uri-dec, upper or lower.
fn conversion(
    db: &Database,
    entry: &Entry,
    body: &str,
    depth: u32,
    context: &Context,
) -> Option<String> {
    let separator = body.chars().next()?;
    let parts: Vec<&str> = body.split(separator).collect();
    if parts.len() < 4 {
        return None;
    }
    let text = multiple(db, entry, parts[1], depth, context);
    let kind = parts[2].to_lowercase();
    Some(match kind.as_str() {
        "base64" => base64::engine::general_purpose::STANDARD.encode(text.as_bytes()),
        "hex" => hex::encode(text.as_bytes()),
        "uri" => url::form_urlencoded::byte_serialize(text.as_bytes())
            .collect::<String>()
            .replace('+', "%20"),
        "uri-dec" => url::form_urlencoded::parse(text.replace('+', "%2B").as_bytes())
            .map(|(k, v)| {
                if v.is_empty() {
                    k.into_owned()
                } else {
                    format!("{k}={v}")
                }
            })
            .collect(),
        k if k.starts_with('u') => text.to_uppercase(),
        k if k.starts_with('l') => text.to_lowercase(),
        _ => return None,
    })
}

/// `{REF:W@S:text}`.
fn reference(
    db: &Database,
    entry: &Entry,
    placeholder: &str,
    depth: u32,
    context: &Context,
) -> String {
    let Some(depth) = depth.checked_sub(1) else {
        return placeholder.to_owned();
    };
    let body = &placeholder[5..placeholder.len() - 1];
    let mut chars = body.chars();
    let (Some(wanted), Some('@'), Some(search_in), Some(':')) = (
        chars.next().map(|c| c.to_ascii_uppercase()),
        chars.next(),
        chars.next().map(|c| c.to_ascii_uppercase()),
        chars.next(),
    ) else {
        return placeholder.to_owned();
    };
    if !"TUPANI".contains(wanted) || !"TUPANIO".contains(search_in) {
        return placeholder.to_owned();
    }
    // The search text may hold placeholders of its own ({UUID}…).
    let text = multiple(db, entry, chars.as_str(), 2, context);
    let Some(found) = find(db, search_in, &text) else {
        return String::new();
    };
    let value = match wanted {
        'T' => field(found, "Title").to_owned(),
        'U' => field(found, "UserName").to_owned(),
        'P' => field(found, "Password").to_owned(),
        'A' => field(found, "URL").to_owned(),
        'N' => field(found, "Notes").to_owned(),
        _ => uuid_hex(found),
    };
    multiple(db, found, &value, depth, context)
}

/// The first entry, group by group from the top (KeePassXC's
/// `findEntryBySearchTerm`), whose field equals `text`.
fn find<'a>(db: &'a Database, search_in: char, text: &str) -> Option<&'a Entry> {
    let mut stack: Vec<GroupId> = vec![db.root];
    let mut groups = Vec::new();
    while let Some(id) = stack.pop() {
        if let Some(group) = db.groups.get(&id) {
            groups.push(id);
            stack.extend(group.groups.iter().rev().copied());
        }
    }
    for id in groups {
        for entry in db.groups[&id]
            .entries
            .iter()
            .filter_map(|e| db.entries.get(e))
        {
            let matches = match search_in {
                'T' => field(entry, "Title") == text,
                'U' => field(entry, "UserName") == text,
                'P' => field(entry, "Password") == text,
                'A' => field(entry, "URL") == text,
                'N' => field(entry, "Notes") == text,
                'I' => uuid_hex(entry).eq_ignore_ascii_case(&text.replace('-', "")),
                _ => entry.fields.iter().any(|(key, value)| {
                    !STANDARD_FIELDS.contains(&key.as_str()) && value.get() == text
                }),
            };
            if matches {
                return Some(entry);
            }
        }
    }
    None
}
