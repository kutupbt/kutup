//! Searching a vault's entries as KeePassXC does (`src/core/EntrySearcher.cpp`,
//! docs/plans/pass-gaps-2.md P3).
//!
//! A query is words, each a part every matching entry holds. A word may name
//! the field it looks in (`title:bank`, `u:ayse`, `tag:work`, `is:expired`),
//! be negated (`-old`, or `!old` as KeePassXC also writes it), match the
//! whole value with `+` (`+title:bank` finds "Bank", not "Bank card"),
//! quoted to keep spaces (`"my bank"`) and hold `*` for any run of
//! characters (`*.example.com`). The modifiers combine (`!+u:admin`). Text is folded as Kutup's
//! other searches fold it (`kutup_search::fold`: Turkish I's, accents, case),
//! so `istanbul` finds "İstanbul". Without a field, a word looks in the
//! title, user name, URL, notes, tags and custom fields that aren't
//! protected; the password and protected fields only with their field.
//! Regular expressions are not taken (a later step).

use std::collections::HashSet;

use chrono::NaiveDateTime;
use keepass::db::{Entry, EntryId, GroupId};
use keepass::Database;

use crate::view::{group_in_recycle_bin, STANDARD_FIELDS};

/// Where a word looks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    /// The title, user name, URL, notes, tags and unprotected custom fields.
    Default,
    Title,
    UserName,
    Password,
    Url,
    Notes,
    /// Custom fields' names, and their values when not protected.
    Attribute,
    /// Attachments' names.
    Attachment,
    /// The names of the groups the entry is in, its own and those above it.
    Group,
    Tag,
    /// The entry's id, as 32 hex digits.
    Uuid,
    /// `is:expired`, `is:expired-N` (expires within N days), `is:weak`.
    Is,
    /// `has:totp`.
    Has,
}

impl Field {
    fn named(name: &str) -> Option<Self> {
        Some(match name {
            "title" | "t" => Self::Title,
            "username" | "user" | "u" => Self::UserName,
            "password" | "pw" | "p" => Self::Password,
            "url" => Self::Url,
            "notes" | "n" => Self::Notes,
            "attr" => Self::Attribute,
            "attachment" | "a" => Self::Attachment,
            "group" | "g" => Self::Group,
            "tag" => Self::Tag,
            "uuid" => Self::Uuid,
            "is" => Self::Is,
            "has" => Self::Has,
            _ => return None,
        })
    }
}

/// One word of a query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Term {
    pub field: Field,
    /// Folded; `*` stands for any run of characters.
    pub pattern: String,
    pub negated: bool,
    /// The whole value must match (KeePassXC's `+`), not a part of it.
    pub exact: bool,
}

/// What a search needs besides the vault.
pub struct Context<'a> {
    /// Entries whose password counts as weak (the caller's estimate, as
    /// its health report shows it).
    pub weak: &'a HashSet<EntryId>,
    pub now: NaiveDateTime,
}

/// The words of `query`. A word that names no known field is searched as
/// it is, colon and all (`https://x`).
pub fn parse(query: &str) -> Vec<Term> {
    let mut terms = Vec::new();
    let mut chars = query.chars().peekable();
    loop {
        while chars.next_if(|c| c.is_whitespace()).is_some() {}
        if chars.peek().is_none() {
            break;
        }
        // KeePassXC's modifiers, in any order: `-` or `!` leaves out, `+`
        // matches whole values.
        let (mut negated, mut exact) = (false, false);
        while let Some(c) = chars.next_if(|c| matches!(c, '-' | '!' | '+')) {
            if c == '+' {
                exact = true;
            } else {
                negated = true;
            }
        }
        // The word up to the next space outside quotes; the quotes go.
        let mut word = String::new();
        let mut quoted = false;
        for c in chars.by_ref() {
            match c {
                '"' => quoted = !quoted,
                c if c.is_whitespace() && !quoted => break,
                c => word.push(c),
            }
        }
        let (field, text) = match word.split_once(':') {
            Some((name, rest)) => match Field::named(&name.to_lowercase()) {
                Some(field) => (field, rest.to_owned()),
                None => (Field::Default, word.clone()),
            },
            None => (Field::Default, word.clone()),
        };
        let pattern = kutup_search::fold(&text);
        // A lone "-" or an empty field ("title:") asks for nothing.
        if pattern.is_empty() || pattern.chars().all(|c| c == '*') {
            continue;
        }
        terms.push(Term {
            field,
            pattern,
            negated,
            exact,
        });
    }
    terms
}

/// Whether folded `text` holds `pattern` somewhere, `*` matching any run.
fn holds(text: &str, pattern: &str) -> bool {
    let mut parts = pattern.split('*').filter(|part| !part.is_empty());
    let Some(first) = parts.next() else {
        return true;
    };
    let Some(mut at) = text.find(first).map(|i| i + first.len()) else {
        return false;
    };
    for part in parts {
        match text[at..].find(part) {
            Some(i) => at += i + part.len(),
            None => return false,
        }
    }
    true
}

/// Whether all of folded `text` is `pattern`, `*` matching any run.
fn is_whole(text: &str, pattern: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return text == pattern;
    }
    let (first, last) = (parts[0], parts[parts.len() - 1]);
    if !text.starts_with(first) || text.len() < first.len() + last.len() || !text.ends_with(last) {
        return false;
    }
    holds(
        &text[first.len()..text.len() - last.len()],
        &parts[1..parts.len() - 1].join("*"),
    )
}

/// How a term compares one folded value: a part of it, or all of it.
fn compare(exact: bool) -> fn(&str, &str) -> bool {
    if exact {
        is_whole
    } else {
        holds
    }
}

fn field_holds(entry: &Entry, key: &str, pattern: &str, exact: bool) -> bool {
    entry
        .fields
        .get(key)
        .is_some_and(|value| compare(exact)(&kutup_search::fold(value.get()), pattern))
}

fn group_names(db: &Database, mut group: Option<GroupId>) -> Vec<String> {
    let mut names = Vec::new();
    while let Some(id) = group {
        let Some(g) = db.groups.get(&id) else { break };
        if id != db.root {
            names.push(kutup_search::fold(&g.name));
        }
        group = g.parent;
    }
    names
}

fn term_holds(db: &Database, entry: &Entry, term: &Term, context: &Context<'_>) -> bool {
    let p = term.pattern.as_str();
    let x = term.exact;
    let holds = compare(x);
    let custom = || {
        entry
            .fields
            .iter()
            .filter(|(key, _)| !STANDARD_FIELDS.contains(&key.as_str()))
    };
    match term.field {
        Field::Default => {
            ["Title", "UserName", "URL", "Notes"]
                .iter()
                .any(|key| field_holds(entry, key, p, x))
                || entry
                    .tags
                    .iter()
                    .any(|tag| holds(&kutup_search::fold(tag), p))
                || custom().any(|(_, value)| {
                    !value.is_protected() && holds(&kutup_search::fold(value.get()), p)
                })
        }
        Field::Title => field_holds(entry, "Title", p, x),
        Field::UserName => field_holds(entry, "UserName", p, x),
        Field::Password => field_holds(entry, "Password", p, x),
        Field::Url => field_holds(entry, "URL", p, x),
        Field::Notes => field_holds(entry, "Notes", p, x),
        Field::Attribute => custom().any(|(key, value)| {
            holds(&kutup_search::fold(key), p)
                || (!value.is_protected() && holds(&kutup_search::fold(value.get()), p))
        }),
        Field::Attachment => entry
            .attachments
            .keys()
            .any(|name| holds(&kutup_search::fold(name), p)),
        Field::Group => group_names(db, Some(entry.parent))
            .iter()
            .any(|name| holds(name, p)),
        Field::Tag => entry
            .tags
            .iter()
            .any(|tag| holds(&kutup_search::fold(tag), p)),
        Field::Uuid => holds(&entry.id.uuid().simple().to_string(), &p.replace('-', "")),
        Field::Is => {
            if p == "weak" {
                // As KeePassXC: never an entry excluded from reports, one
                // with no password, or one that has expired.
                context.weak.contains(&entry.id)
                    && entry.quality_check
                    && entry.get_password().is_some_and(|pw| !pw.is_empty())
                    && !expires_within(entry, context.now, 0)
            } else if let Some(rest) = p.strip_prefix("expired") {
                let days = rest
                    .strip_prefix('-')
                    .and_then(|n| n.parse::<i64>().ok())
                    .unwrap_or(0);
                expires_within(entry, context.now, days) && !group_in_recycle_bin(db, entry.parent)
            } else {
                false
            }
        }
        Field::Has => p == "totp" && crate::otp::settings(entry).is_some(),
    }
}

fn expires_within(entry: &Entry, now: NaiveDateTime, days: i64) -> bool {
    entry.times.expires.unwrap_or(false)
        && entry
            .times
            .expiry
            .is_some_and(|expiry| expiry <= now + chrono::Duration::days(days.clamp(0, 36_500)))
}

/// Whether `entry` matches every term of a parsed query.
pub fn matches(db: &Database, entry: &Entry, terms: &[Term], context: &Context<'_>) -> bool {
    terms
        .iter()
        .all(|term| term_holds(db, entry, term, context) != term.negated)
}

/// The ids of the entries matching `query`, in no particular order. An
/// empty query matches every entry.
pub fn search(db: &Database, query: &str, context: &Context<'_>) -> Vec<String> {
    let terms = parse(query);
    db.entries
        .values()
        .filter(|entry| matches(db, entry, &terms, context))
        .map(|entry| entry.id.uuid().to_string())
        .collect()
}
