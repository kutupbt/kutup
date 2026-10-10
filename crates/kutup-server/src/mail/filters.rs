//! Mail filters (docs/plans/mail-filters.md, F2), as Proton's simple
//! filters: conditions on the sender, the recipient, the subject and
//! attachments, compared with contains, is, begins with, ends with or
//! matches (`*`, `?`), each optionally negated; all or any of them; actions
//! to move, label, mark read and star. They run where every copy is stored
//! ([`super::insert_message`]): incoming mail and the sender's own sent
//! copy, never mail filed as spam. Comparisons ignore case, as Sieve's
//! `i;unicode-casemap` does, with Turkish İ, I, ı and i taken as one letter.

use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction};
use utoipa::ToSchema;
use uuid::Uuid;

use super::headers::{Mailbox, Readable};

pub const MAX_CONDITIONS: usize = 20;
pub const MAX_VALUE_CHARS: usize = 200;
pub const MAX_LABELS: usize = 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Field {
    Sender,
    Recipient,
    Subject,
    Attachments,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Comparator {
    Contains,
    Is,
    Begins,
    Ends,
    Matches,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Condition {
    pub field: Field,
    /// Ignored for `attachments` ("has attachments", or none when negated).
    #[serde(default = "contains")]
    pub op: Comparator,
    #[serde(default)]
    pub negate: bool,
    #[serde(default)]
    pub value: String,
}

fn contains() -> Comparator {
    Comparator::Contains
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Match {
    All,
    Any,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Actions {
    /// `inbox`, `archive`, `spam`, `trash`, or `custom:<folder id>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<Uuid>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub mark_read: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub star: bool,
}

/// Where a filter files mail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Destination {
    Fixed(&'static str),
    Custom(Uuid),
}

impl Actions {
    pub fn destination(&self) -> Option<Destination> {
        let folder = self.folder.as_deref()?;
        match folder {
            "inbox" => Some(Destination::Fixed("inbox")),
            "archive" => Some(Destination::Fixed("archive")),
            "spam" => Some(Destination::Fixed("spam")),
            "trash" => Some(Destination::Fixed("trash")),
            _ => folder
                .strip_prefix("custom:")
                .and_then(|id| Uuid::parse_str(id).ok())
                .map(Destination::Custom),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.folder.is_none() && self.labels.is_empty() && !self.mark_read && !self.star
    }
}

/// Checks a filter's shape; ownership of folders and labels is checked by the caller.
pub fn check(conditions: &[Condition], actions: &Actions) -> Result<(), &'static str> {
    if conditions.is_empty() {
        return Err("add at least one condition");
    }
    if conditions.len() > MAX_CONDITIONS {
        return Err("20 conditions at most");
    }
    for condition in conditions {
        if condition.field != Field::Attachments {
            let value = condition.value.trim();
            if value.is_empty() {
                return Err("a condition needs a value");
            }
            if value.chars().count() > MAX_VALUE_CHARS || value.chars().any(char::is_control) {
                return Err("a value is 1 to 200 characters");
            }
        }
    }
    if actions.is_empty() {
        return Err("add at least one action");
    }
    if actions.folder.is_some() && actions.destination().is_none() {
        return Err("unknown folder");
    }
    if actions.labels.len() > MAX_LABELS {
        return Err("20 labels at most");
    }
    Ok(())
}

/// Case folded for comparing: Turkish İ, I, ı and i as one letter.
pub fn fold(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            'İ' | 'I' | 'ı' => 'i',
            c => c,
        })
        .collect::<String>()
        .to_lowercase()
}

/// Sieve's `:matches`: `*` any run of characters, `?` one, on folded text.
fn glob(pattern: &[char], text: &[char]) -> bool {
    let (mut p, mut t) = (0, 0);
    let (mut star, mut mark) = (None, 0);
    while t < text.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some(p);
            mark = t;
            p += 1;
        } else if let Some(s) = star {
            p = s + 1;
            mark += 1;
            t = mark;
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|c| *c == '*')
}

fn compare(op: Comparator, text: &str, value: &str) -> bool {
    let (text, value) = (fold(text), fold(value.trim()));
    match op {
        Comparator::Contains => text.contains(&value),
        Comparator::Is => text == value,
        Comparator::Begins => text.starts_with(&value),
        Comparator::Ends => text.ends_with(&value),
        Comparator::Matches => glob(
            &value.chars().collect::<Vec<_>>(),
            &text.chars().collect::<Vec<_>>(),
        ),
    }
}

/// What a filter looks at in one message.
pub struct Subject<'a> {
    pub from: Option<&'a Mailbox>,
    pub to: &'a [Mailbox],
    pub cc: &'a [Mailbox],
    /// The account's address the copy came to (aliases later).
    pub address: &'a str,
    pub subject: &'a str,
    pub attachments: i32,
}

fn mailbox_texts(mailbox: &Mailbox) -> [&str; 2] {
    [mailbox.address.as_str(), mailbox.name.as_str()]
}

fn holds(condition: &Condition, message: &Subject<'_>) -> bool {
    let any = |texts: &mut dyn Iterator<Item = &str>| {
        texts
            .filter(|t| !t.is_empty())
            .any(|t| compare(condition.op, t, &condition.value))
    };
    let found = match condition.field {
        Field::Attachments => message.attachments > 0,
        Field::Subject => compare(condition.op, message.subject, &condition.value),
        Field::Sender => any(&mut message.from.into_iter().flat_map(mailbox_texts)),
        Field::Recipient => any(&mut message
            .to
            .iter()
            .chain(message.cc)
            .flat_map(mailbox_texts)
            .chain(std::iter::once(message.address))),
    };
    found != condition.negate
}

pub fn matches(rule: Match, conditions: &[Condition], message: &Subject<'_>) -> bool {
    match rule {
        Match::All => conditions.iter().all(|c| holds(c, message)),
        Match::Any => conditions.iter().any(|c| holds(c, message)),
    }
}

/// What the matching filters do together: the first move wins, labels and
/// flags add up (Proton runs its Sieve the same way).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    pub destination: Option<Destination>,
    pub labels: Vec<Uuid>,
    pub mark_read: bool,
    pub star: bool,
}

impl Outcome {
    pub fn add(&mut self, actions: &Actions) {
        if self.destination.is_none() {
            self.destination = actions.destination();
        }
        for label in &actions.labels {
            if !self.labels.contains(label) {
                self.labels.push(*label);
            }
        }
        self.mark_read |= actions.mark_read;
        self.star |= actions.star;
    }

    pub fn is_empty(&self) -> bool {
        self.destination.is_none() && self.labels.is_empty() && !self.mark_read && !self.star
    }
}

/// An enabled filter, as loaded for matching.
pub struct Loaded {
    pub rule: Match,
    pub conditions: Vec<Condition>,
    pub actions: Actions,
}

/// The account's enabled filters, in order (all of them, or only `only`).
pub async fn load(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    only: Option<&[Uuid]>,
) -> sqlx::Result<Vec<Loaded>> {
    let rows: Vec<(String, serde_json::Value, serde_json::Value)> = sqlx::query_as(
        "SELECT match, conditions, actions FROM mail_filters
          WHERE user_id = $1 AND enabled AND ($2::uuid[] IS NULL OR id = ANY($2))
          ORDER BY position, created_at",
    )
    .bind(user_id)
    .bind(only)
    .fetch_all(&mut **tx)
    .await?;
    Ok(rows
        .into_iter()
        .filter_map(|(rule, conditions, actions)| {
            Some(Loaded {
                rule: if rule == "any" {
                    Match::Any
                } else {
                    Match::All
                },
                conditions: serde_json::from_value(conditions).ok()?,
                actions: serde_json::from_value(actions).ok()?,
            })
        })
        .collect())
}

pub fn outcome(filters: &[Loaded], message: &Subject<'_>) -> Outcome {
    let mut outcome = Outcome::default();
    for filter in filters {
        if matches(filter.rule, &filter.conditions, message) {
            outcome.add(&filter.actions);
        }
    }
    outcome
}

/// Files message `id` of `user_id` as `outcome` says: a move only where the
/// message may go (sent mail never to Inbox or Spam), folders and labels
/// only the account's own. Returns whether anything changed.
pub async fn apply(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    id: Uuid,
    direction: &str,
    outcome: &Outcome,
) -> sqlx::Result<bool> {
    if outcome.is_empty() {
        return Ok(false);
    }
    let (folder, custom) = match outcome.destination {
        Some(Destination::Fixed("inbox" | "spam")) if direction == "outbound" => (None, None),
        Some(Destination::Fixed(folder)) => (Some(folder), None),
        Some(Destination::Custom(custom)) => (Some("custom"), Some(custom)),
        None => (None, None),
    };
    let moved = sqlx::query(
        "UPDATE mail_messages SET
             folder = CASE WHEN $3::text IS NULL THEN folder ELSE $3 END,
             custom_folder = CASE WHEN $3::text IS NULL THEN custom_folder ELSE $4 END,
             seen = seen OR $5 OR $3::text = 'trash',
             starred = starred OR $6
          WHERE user_id = $1 AND id = $2 AND folder <> 'drafts'
            AND ($4::uuid IS NULL OR EXISTS (SELECT 1 FROM mail_folders f WHERE f.user_id = $1 AND f.id = $4))",
    )
    .bind(user_id)
    .bind(id)
    .bind(folder)
    .bind(custom)
    .bind(outcome.mark_read)
    .bind(outcome.star)
    .execute(&mut **tx)
    .await?
    .rows_affected();
    // A folder the filter names that is gone: the other actions still count.
    let flagged = if moved == 0 && custom.is_some() {
        sqlx::query(
            "UPDATE mail_messages SET seen = seen OR $3, starred = starred OR $4
              WHERE user_id = $1 AND id = $2 AND folder <> 'drafts'",
        )
        .bind(user_id)
        .bind(id)
        .bind(outcome.mark_read)
        .bind(outcome.star)
        .execute(&mut **tx)
        .await?
        .rows_affected()
    } else {
        moved
    };
    if !outcome.labels.is_empty() {
        sqlx::query(
            "INSERT INTO mail_message_labels (message_id, label_id)
             SELECT $2, l.id FROM mail_labels l WHERE l.user_id = $1 AND l.id = ANY($3)
             ON CONFLICT DO NOTHING",
        )
        .bind(user_id)
        .bind(id)
        .bind(&outcome.labels)
        .execute(&mut **tx)
        .await?;
    }
    Ok(flagged > 0 || !outcome.labels.is_empty())
}

/// Runs the account's filters on a copy just stored (from `insert_message`):
/// incoming mail in the Inbox and the sender's copy in Sent.
pub async fn on_arrival(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    address_id: Uuid,
    id: Uuid,
    direction: &str,
    readable: &Readable,
) -> sqlx::Result<()> {
    let filters = load(tx, user_id, None).await?;
    if filters.is_empty() {
        return Ok(());
    }
    let address: String = sqlx::query_scalar("SELECT address FROM mail_addresses WHERE id = $1")
        .bind(address_id)
        .fetch_optional(&mut **tx)
        .await?
        .unwrap_or_default();
    let subject = Subject {
        from: readable.from.as_ref(),
        to: &readable.to,
        cc: &readable.cc,
        address: &address,
        subject: &readable.subject,
        attachments: readable.attachment_count,
    };
    let outcome = outcome(&filters, &subject);
    apply(tx, user_id, id, direction, &outcome).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mailbox(address: &str, name: &str) -> Mailbox {
        Mailbox {
            address: address.into(),
            name: name.into(),
        }
    }

    fn condition(field: Field, op: Comparator, value: &str) -> Condition {
        Condition {
            field,
            op,
            negate: false,
            value: value.into(),
        }
    }

    #[test]
    fn comparators_fold_case_and_turkish_i() {
        assert!(compare(Comparator::Contains, "Fatura Ödemesi", "ödeme"));
        assert!(compare(Comparator::Is, "İSTANBUL", "istanbul"));
        assert!(compare(Comparator::Is, "ıspanak", "Ispanak"));
        assert!(compare(Comparator::Begins, "Re: Toplantı", "re:"));
        assert!(compare(
            Comparator::Ends,
            "boss@Company.com",
            "@company.com"
        ));
        assert!(compare(
            Comparator::Matches,
            "invoice-2026-10",
            "invoice-*-1?"
        ));
        assert!(!compare(
            Comparator::Matches,
            "invoice-2026-10",
            "invoice-?"
        ));
        assert!(compare(Comparator::Matches, "a*b", "a*b"));
        assert!(!compare(Comparator::Is, "abc", "ab"));
    }

    #[test]
    fn conditions_all_any_and_negation() {
        let from = mailbox("news@shop.example", "Shop News");
        let to = [mailbox("alice@kutup.dev", "Alice")];
        let message = Subject {
            from: Some(&from),
            to: &to,
            cc: &[],
            address: "alice@kutup.dev",
            subject: "Haftalık indirimler",
            attachments: 0,
        };
        let shop = condition(Field::Sender, Comparator::Ends, "@shop.example");
        let named = condition(Field::Sender, Comparator::Contains, "news");
        let invoice = condition(Field::Subject, Comparator::Contains, "fatura");
        let mut none = condition(Field::Attachments, Comparator::Contains, "");
        assert!(matches(
            Match::All,
            &[shop.clone(), named.clone()],
            &message
        ));
        assert!(!matches(
            Match::All,
            &[shop.clone(), invoice.clone()],
            &message
        ));
        assert!(matches(
            Match::Any,
            &[shop.clone(), invoice.clone()],
            &message
        ));
        assert!(!matches(Match::All, &[none.clone()], &message));
        none.negate = true;
        assert!(matches(Match::All, &[none], &message));
        let mut not_shop = shop;
        not_shop.negate = true;
        assert!(!matches(Match::All, &[not_shop], &message));
        assert!(matches(
            Match::All,
            &[condition(
                Field::Recipient,
                Comparator::Is,
                "alice@kutup.dev"
            )],
            &message
        ));
    }

    #[test]
    fn outcomes_add_up_and_the_first_move_wins() {
        let label = Uuid::new_v4();
        let mut outcome = Outcome::default();
        outcome.add(&Actions {
            folder: Some("archive".into()),
            labels: vec![label],
            ..Default::default()
        });
        outcome.add(&Actions {
            folder: Some("trash".into()),
            labels: vec![label],
            star: true,
            ..Default::default()
        });
        assert_eq!(outcome.destination, Some(Destination::Fixed("archive")));
        assert_eq!(outcome.labels, vec![label]);
        assert!(outcome.star && !outcome.mark_read);
    }

    #[test]
    fn filters_are_checked() {
        let ok = Actions {
            mark_read: true,
            ..Default::default()
        };
        let one = [condition(Field::Subject, Comparator::Is, "x")];
        assert!(check(&one, &ok).is_ok());
        assert!(check(&[], &ok).is_err());
        assert!(check(&one, &Actions::default()).is_err());
        assert!(check(&[condition(Field::Subject, Comparator::Is, "  ")], &ok).is_err());
        assert!(check(&[condition(Field::Attachments, Comparator::Is, "")], &ok).is_ok());
        let bad = Actions {
            folder: Some("custom:nope".into()),
            ..Default::default()
        };
        assert!(check(&one, &bad).is_err());
        let custom = Actions {
            folder: Some(format!("custom:{}", Uuid::new_v4())),
            ..Default::default()
        };
        assert!(matches!(custom.destination(), Some(Destination::Custom(_))));
    }
}
