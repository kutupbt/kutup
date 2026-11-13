//! A message's headers, sealed (docs/plans/server-personal-data.md, A2, L7).
//!
//! Subject, sender, recipients, Message-IDs and attached file names are one
//! value sealed under the mailbox's data key: the account's, or a shared
//! mailbox's own (`crate::account_data::KeyOwner`). The server opens them to
//! answer a listing, as it does any sealed field. What it must find rows by
//! is a keyed hash under the same key (`kutup_crypto::server_data::Lookup`):
//!
//! - a Message-ID (its own, In-Reply-To, References), for threading,
//!   duplicates and bounces;
//! - every word of the subject, sender and recipients, tagged with its field,
//!   for search. Words are folded as `kutup_search` folds them; an address is
//!   also kept whole, as its local part and as its domain. A query matches
//!   whole words, every one of them (Proton's header search).
//!
//! Destroying the key destroys the headers and the hashes together.

use std::collections::BTreeSet;

use kutup_crypto::server_data::{DataKey, Field, Lookup};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::account_data::KeyOwner;
use crate::error::{AppError, AppResult};
use crate::mail::headers::{AttachmentMeta, Mailbox};

const TABLE: &str = "mail_messages";
const COLUMN: &str = "headers";

/// The headers' format version; a newer one is unreadable here.
const VERSION: u32 = 1;

/// Search tokens a message keeps at most (the column's CHECK).
const MAX_TOKENS: usize = 4000;

/// Words a query is cut to.
const MAX_QUERY_WORDS: usize = 16;

/// A message's sealed headers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Headers {
    pub v: u32,
    #[serde(default)]
    pub subject: String,
    #[serde(default)]
    pub from: Option<Mailbox>,
    #[serde(default)]
    pub to: Vec<Mailbox>,
    #[serde(default)]
    pub cc: Vec<Mailbox>,
    #[serde(default)]
    pub reply_to: Vec<Mailbox>,
    #[serde(default)]
    pub bcc: Vec<Mailbox>,
    #[serde(default)]
    pub message_id: Option<String>,
    #[serde(default)]
    pub in_reply_to: Option<String>,
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(default)]
    pub attachments: Vec<AttachmentMeta>,
    /// The address it was forwarded from (docs/plans/mail-forwarding.md).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forwarded_from: Option<String>,
}

impl Headers {
    /// A message's headers: what was read from it, and its Bcc.
    pub fn of(readable: &crate::mail::headers::Readable, bcc: &[Mailbox]) -> Self {
        Headers {
            v: VERSION,
            subject: readable.subject.clone(),
            from: readable.from.clone(),
            to: readable.to.clone(),
            cc: readable.cc.clone(),
            reply_to: readable.reply_to.clone(),
            bcc: bcc.to_vec(),
            message_id: readable.message_id.clone(),
            in_reply_to: readable.in_reply_to.clone(),
            references: readable.references.clone(),
            attachments: readable.attachments.clone(),
            forwarded_from: None,
        }
    }
}

/// Which header a search word came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Part {
    Subject,
    From,
    /// To and Cc.
    Recipient,
    Bcc,
}

impl Part {
    fn tag(self) -> u8 {
        match self {
            Part::Subject => b's',
            Part::From => b'f',
            Part::Recipient => b't',
            Part::Bcc => b'b',
        }
    }
}

/// What quick search looks in.
pub const QUICK: &[Part] = &[Part::Subject, Part::From, Part::Recipient];
/// Advanced search's sender.
pub const SENDER: &[Part] = &[Part::From];
/// Advanced search's recipient.
pub const RECIPIENT: &[Part] = &[Part::Recipient, Part::Bcc];

/// The mailbox whose key a message is under: its account's, else (a shared
/// mailbox's message) its group's.
pub fn owner_of(user_id: Option<Uuid>, group_id: Option<Uuid>) -> KeyOwner {
    match (user_id, group_id) {
        (Some(user_id), _) => KeyOwner::Account(user_id),
        (None, Some(group_id)) => KeyOwner::MailGroup(group_id),
        (None, None) => unreachable!("a message belongs to an account or a group"),
    }
}

fn keys() -> AppResult<&'static crate::opaque_setup::OpaqueSetupKeys> {
    crate::account_data::installed()
        .ok_or_else(|| AppError::internal("the server key list is not installed"))
}

fn internal(error: kutup_crypto::error::CryptoError) -> AppError {
    AppError::internal(format!("mail headers: {error}"))
}

/// The mailbox's key for sealing (made when it has none), in the caller's
/// transaction.
pub async fn key(conn: &mut sqlx::PgConnection, owner: KeyOwner) -> AppResult<DataKey> {
    crate::account_data::key_owner_in(conn, keys()?, owner).await
}

/// What a row stores: the sealed headers and its lookup hashes.
pub struct Sealed {
    pub headers: Vec<u8>,
    pub message_id_hash: Option<Vec<u8>>,
    pub in_reply_to_hash: Option<Vec<u8>>,
    pub references_hashes: Vec<Vec<u8>>,
    pub search_tokens: Vec<Vec<u8>>,
}

/// Seals `headers` for row `id` of `owner`'s mailbox under `key`.
pub fn seal(key: &DataKey, owner: KeyOwner, id: Uuid, headers: &Headers) -> AppResult<Sealed> {
    let mut headers = headers.clone();
    headers.v = VERSION;
    let plain = serde_json::to_vec(&headers)
        .map_err(|e| AppError::internal(format!("mail headers: {e}")))?;
    let row = id.to_string();
    let account = *owner.id().as_bytes();
    let sealed = key
        .seal(
            &Field {
                table: TABLE,
                column: COLUMN,
                row: &row,
                account_id: &account,
            },
            &plain,
        )
        .map_err(internal)?;
    let thread = |id: &str| thread_hash(key, id);
    Ok(Sealed {
        headers: sealed,
        message_id_hash: headers.message_id.as_deref().map(thread).transpose()?,
        in_reply_to_hash: headers.in_reply_to.as_deref().map(thread).transpose()?,
        references_hashes: headers
            .references
            .iter()
            .map(|id| thread(id))
            .collect::<AppResult<_>>()?,
        search_tokens: search_tokens(key, &headers)?,
    })
}

/// The keyed hash of a Message-ID (as stored: without angle brackets).
pub fn thread_hash(key: &DataKey, message_id: &str) -> AppResult<Vec<u8>> {
    Ok(key
        .lookup_hash(Lookup::MailThread, message_id.as_bytes())
        .map_err(internal)?
        .to_vec())
}

/// The keyed hashes of `message_ids` under every key of the mailbox (what a
/// lookup by Message-ID binds).
pub fn thread_hashes(keys: &[DataKey], message_ids: &[&str]) -> AppResult<Vec<Vec<u8>>> {
    let mut out = Vec::with_capacity(keys.len() * message_ids.len());
    for key in keys {
        for id in message_ids {
            out.push(thread_hash(key, id)?);
        }
    }
    Ok(out)
}

fn token(key: &DataKey, part: Part, word: &str) -> AppResult<Vec<u8>> {
    let mut input = Vec::with_capacity(word.len() + 2);
    input.push(part.tag());
    input.push(0);
    input.extend_from_slice(word.as_bytes());
    Ok(key
        .lookup_hash(Lookup::MailSearchToken, &input)
        .map_err(internal)?
        .to_vec())
}

/// The folded words of an address: its words, and the address whole, its
/// local part and its domain.
fn address_words(address: &str, into: &mut BTreeSet<String>) {
    into.extend(kutup_search::words(address));
    let folded = kutup_search::fold(address.trim());
    if let Some((local, domain)) = folded.rsplit_once('@') {
        for part in [local, domain] {
            if !part.is_empty() {
                into.insert(part.to_owned());
            }
        }
    }
    if !folded.is_empty() {
        into.insert(folded);
    }
}

fn mailbox_words(mailbox: &Mailbox, into: &mut BTreeSet<String>) {
    into.extend(kutup_search::words(&mailbox.name));
    address_words(&mailbox.address, into);
}

/// The words of each part of `headers`.
fn words(headers: &Headers) -> Vec<(Part, BTreeSet<String>)> {
    let subject: BTreeSet<String> = kutup_search::words(&headers.subject).into_iter().collect();
    let mut from = BTreeSet::new();
    if let Some(mailbox) = &headers.from {
        mailbox_words(mailbox, &mut from);
    }
    let mut recipients = BTreeSet::new();
    for mailbox in headers.to.iter().chain(&headers.cc) {
        mailbox_words(mailbox, &mut recipients);
    }
    let mut bcc = BTreeSet::new();
    for mailbox in &headers.bcc {
        mailbox_words(mailbox, &mut bcc);
    }
    vec![
        (Part::Subject, subject),
        (Part::From, from),
        (Part::Recipient, recipients),
        (Part::Bcc, bcc),
    ]
}

fn search_tokens(key: &DataKey, headers: &Headers) -> AppResult<Vec<Vec<u8>>> {
    let mut tokens = Vec::new();
    // Subject and sender first: past the limit, recipients' words go.
    'parts: for (part, words) in words(headers) {
        for word in words {
            if tokens.len() == MAX_TOKENS {
                break 'parts;
            }
            tokens.push(token(key, part, &word)?);
        }
    }
    Ok(tokens)
}

/// A query's words, folded: whitespace-separated terms; a term with an `@`
/// is an address (whole, or a local part or domain when one side is empty),
/// any other is its words.
pub fn query_words(query: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for term in query.split_whitespace() {
        let term = term.trim_matches(|c: char| matches!(c, '<' | '>' | '"' | ',' | ';' | '\''));
        let terms = if term.contains('@') {
            let folded = kutup_search::fold(term);
            match folded.rsplit_once('@') {
                Some(("", domain)) => vec![domain.to_owned()],
                Some((local, "")) => vec![local.to_owned()],
                _ => vec![folded],
            }
        } else {
            kutup_search::words(term)
        };
        for word in terms {
            if !word.is_empty() && !out.contains(&word) {
                out.push(word);
            }
        }
    }
    out.truncate(MAX_QUERY_WORDS);
    out
}

/// A search for SQL: per word, one token per key and part, flat and in word
/// order, with how many there are per word (each word's run is the same
/// length). [`SEARCH_WHERE`] matches a row holding a token of every run.
pub struct Search {
    pub tokens: Vec<Vec<u8>>,
    pub per_word: i32,
}

/// The tokens of `query` in `parts` under every key of the mailbox; none for
/// an empty query. A mailbox without a key matches nothing.
pub fn search(keys: &[DataKey], query: Option<&str>, parts: &[Part]) -> AppResult<Option<Search>> {
    let words = query.map(query_words).unwrap_or_default();
    if words.is_empty() {
        return Ok(None);
    }
    if keys.is_empty() {
        // Nothing is sealed under a key the mailbox doesn't have.
        return Ok(Some(Search {
            tokens: vec![vec![0; 32]],
            per_word: 1,
        }));
    }
    let mut tokens = Vec::with_capacity(words.len() * keys.len() * parts.len());
    for word in &words {
        for key in keys {
            for part in parts {
                tokens.push(token(key, *part, word)?);
            }
        }
    }
    Ok(Some(Search {
        tokens,
        per_word: (keys.len() * parts.len()) as i32,
    }))
}

/// A row matches the search in `$tokens` with `$per_word` tokens a word:
/// one of each word's tokens is among its own. The first word's run uses the
/// GIN index. `{tokens}` and `{per_word}` are the parameters. The listings
/// spell it out in their constant clauses; a test holds them to this.
#[cfg(test)]
pub fn search_where(tokens: &str, per_word: &str) -> String {
    format!(
        "({tokens}::bytea[] IS NULL OR (
            search_tokens && {tokens}[1:{per_word}]
            AND NOT EXISTS (
                SELECT 1 FROM generate_series(0, cardinality({tokens}) / {per_word} - 1) AS w(i)
                 WHERE NOT (search_tokens && {tokens}[w.i * {per_word} + 1:(w.i + 1) * {per_word}]))))"
    )
}

/// Opens one mailbox's rows: every generation of its key.
pub struct Opener {
    owner: KeyOwner,
    keys: Vec<DataKey>,
}

impl Opener {
    /// The mailbox's keys, on the pool. Never makes one.
    pub async fn load(pool: &sqlx::PgPool, owner: KeyOwner) -> AppResult<Self> {
        let mut conn = pool.acquire().await?;
        Self::load_in(&mut conn, owner).await
    }

    /// [`Opener::load`] on a connection (the caller's transaction).
    pub async fn load_in(conn: &mut sqlx::PgConnection, owner: KeyOwner) -> AppResult<Self> {
        let keys = crate::account_data::load_all_owner_in(conn, keys()?, owner).await?;
        Ok(Opener { owner, keys })
    }

    /// Every generation of the mailbox's key, newest first.
    pub fn keys(&self) -> &[DataKey] {
        &self.keys
    }

    /// Row `id`'s headers; empty when it keeps none, or they don't open (its
    /// key is gone: destroyed, or lost).
    pub fn open(&self, id: Uuid, sealed: Option<&[u8]>) -> Headers {
        let Some(sealed) = sealed.filter(|s| !s.is_empty()) else {
            return Headers::default();
        };
        let Ok(generation) = kutup_crypto::server_data::sealed_generation(sealed) else {
            tracing::warn!(%id, "mail headers: not a sealed value");
            return Headers::default();
        };
        let Some(key) = self.keys.iter().find(|k| k.generation() == generation) else {
            return Headers::default();
        };
        let row = id.to_string();
        let account = *self.owner.id().as_bytes();
        let opened = key.open(
            &Field {
                table: TABLE,
                column: COLUMN,
                row: &row,
                account_id: &account,
            },
            sealed,
        );
        let Ok(plain) = opened else {
            tracing::warn!(%id, "mail headers do not open under the mailbox's key");
            return Headers::default();
        };
        match serde_json::from_slice::<Headers>(&plain) {
            Ok(headers) if headers.v <= VERSION => headers,
            Ok(headers) => {
                tracing::warn!(%id, v = headers.v, "mail headers of a newer format");
                Headers::default()
            }
            Err(error) => {
                tracing::warn!(%id, %error, "mail headers do not parse");
                Headers::default()
            }
        }
    }
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

    fn sample() -> Headers {
        Headers {
            subject: "Ekim faturası".into(),
            from: Some(mailbox("Ali.Veli@Örnek.com.tr", "Ali Veli")),
            to: vec![mailbox("ayse@example.org", "Ayşe Yılmaz")],
            bcc: vec![mailbox("gizli@example.net", "")],
            message_id: Some("abc@example.org".into()),
            references: vec!["root@example.org".into()],
            ..Headers::default()
        }
    }

    fn opener(key: DataKey, owner: KeyOwner) -> Opener {
        Opener {
            owner,
            keys: vec![key],
        }
    }

    #[test]
    fn headers_open_only_in_their_row_and_mailbox() {
        let key = DataKey::generate(1).unwrap();
        let owner = KeyOwner::Account(Uuid::new_v4());
        let id = Uuid::new_v4();
        let sealed = seal(&key, owner, id, &sample()).unwrap();
        let opener = opener(key, owner);
        let opened = opener.open(id, Some(&sealed.headers));
        assert_eq!(
            opened,
            Headers {
                v: VERSION,
                ..sample()
            }
        );
        assert_eq!(
            opener.open(Uuid::new_v4(), Some(&sealed.headers)),
            Headers::default()
        );
        // Another mailbox, even with the same key bytes: refused.
        let other = Opener {
            owner: KeyOwner::MailGroup(Uuid::new_v4()),
            keys: opener.keys,
        };
        assert_eq!(other.open(id, Some(&sealed.headers)), Headers::default());
        assert_eq!(other.open(id, None), Headers::default());
    }

    #[test]
    fn threading_hashes_are_the_message_ids() {
        let key = DataKey::generate(1).unwrap();
        let sealed = seal(
            &key,
            KeyOwner::Account(Uuid::new_v4()),
            Uuid::new_v4(),
            &sample(),
        )
        .unwrap();
        assert_eq!(
            sealed.message_id_hash,
            Some(thread_hash(&key, "abc@example.org").unwrap())
        );
        assert_eq!(
            sealed.references_hashes,
            vec![thread_hash(&key, "root@example.org").unwrap()]
        );
        assert_eq!(sealed.in_reply_to_hash, None);
    }

    /// Whether `query` finds the sample, searching `parts`.
    fn finds(query: &str, parts: &[Part]) -> bool {
        let key = DataKey::generate(1).unwrap();
        let sealed = seal(
            &key,
            KeyOwner::Account(Uuid::new_v4()),
            Uuid::new_v4(),
            &sample(),
        )
        .unwrap();
        let search = search(std::slice::from_ref(&key), Some(query), parts)
            .unwrap()
            .unwrap();
        search
            .tokens
            .chunks(search.per_word as usize)
            .all(|run| run.iter().any(|t| sealed.search_tokens.contains(t)))
    }

    #[test]
    fn search_matches_whole_folded_words_of_each_part() {
        assert!(finds("ekim", QUICK));
        assert!(finds("FATURASI ekim", QUICK));
        assert!(finds("ayse", QUICK));
        assert!(finds("ali", SENDER));
        assert!(finds("ali.veli@ornek.com.tr", SENDER));
        assert!(finds("@ornek.com.tr", SENDER));
        assert!(finds("ornek", SENDER));
        assert!(finds("yilmaz", RECIPIENT));
        assert!(finds("gizli", RECIPIENT));
        // Whole words only, every one, in the parts asked.
        assert!(!finds("fatura", QUICK));
        assert!(!finds("ekim mart", QUICK));
        assert!(!finds("ekim", SENDER));
        assert!(!finds("gizli", QUICK));
    }

    #[test]
    fn a_mailbox_without_a_key_matches_nothing() {
        let search = search(&[], Some("ekim"), QUICK).unwrap().unwrap();
        assert_eq!(search.tokens, vec![vec![0u8; 32]]);
        assert!(search_with_empty_query_is_none());
    }

    /// The SQL clause matches as the tokens do: every word, in the parts
    /// asked; and a shared mailbox's key goes with its group.
    #[tokio::test]
    async fn live_search_where_and_group_keys() {
        let Ok(url) = std::env::var("KUTUP_LIVE_DATABASE_URL") else {
            eprintln!("KUTUP_LIVE_DATABASE_URL unset; skipping");
            return;
        };
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .unwrap();
        let key = DataKey::generate(1).unwrap();
        let sealed = seal(
            &key,
            KeyOwner::Account(Uuid::new_v4()),
            Uuid::new_v4(),
            &sample(),
        )
        .unwrap();
        let clause = search_where("$1", "$2");
        let matches = |query: &'static str, parts: &'static [Part]| {
            let pool = pool.clone();
            let tokens = sealed.search_tokens.clone();
            let search = search(std::slice::from_ref(&key), Some(query), parts)
                .unwrap()
                .unwrap();
            let clause = clause.clone();
            async move {
                sqlx::query_scalar::<_, bool>(&format!(
                    "SELECT EXISTS (SELECT 1 FROM (SELECT $3::bytea[] AS search_tokens) m WHERE {clause})"
                ))
                .bind(&search.tokens)
                .bind(search.per_word)
                .bind(&tokens)
                .fetch_one(&pool)
                .await
                .unwrap()
            }
        };
        assert!(matches("ekim faturası", QUICK).await);
        assert!(matches("ayşe", QUICK).await);
        assert!(matches("gizli", RECIPIENT).await);
        assert!(!matches("ekim mart", QUICK).await);
        assert!(!matches("gizli", QUICK).await);
        let none: bool = sqlx::query_scalar(&format!(
            "SELECT EXISTS (SELECT 1 FROM (SELECT '{{}}'::bytea[] AS search_tokens) m WHERE {clause})"
        ))
        .bind(None::<Vec<Vec<u8>>>)
        .bind(1i32)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(none, "no search matches every row");

        let mut entry = [0u8; 32];
        kutup_crypto::primitives::random(&mut entry);
        let keys = crate::opaque_setup::OpaqueSetupKeys::parse(&format!(
            "3:{}",
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, entry)
        ))
        .unwrap();
        let group: Uuid = sqlx::query_scalar(
            "INSERT INTO mail_groups (address, kind, storage_quota_bytes)
             VALUES ($1, 'shared', 1000) RETURNING id",
        )
        .bind(format!(
            "g{}@sealed.test",
            &Uuid::new_v4().simple().to_string()[..12]
        ))
        .fetch_one(&pool)
        .await
        .unwrap();
        let owner = KeyOwner::MailGroup(group);
        let mut conn = pool.acquire().await.unwrap();
        let made = crate::account_data::key_owner_in(&mut conn, &keys, owner)
            .await
            .unwrap();
        let again = crate::account_data::load_all_owner_in(&mut conn, &keys, owner)
            .await
            .unwrap();
        assert_eq!(again.len(), 1);
        assert_eq!(
            again[0].lookup_hash(Lookup::MailThread, b"x").unwrap(),
            made.lookup_hash(Lookup::MailThread, b"x").unwrap()
        );
        // An account with the same id has no key: the tables are apart.
        assert!(crate::account_data::load_in(&mut conn, &keys, group, None)
            .await
            .unwrap()
            .is_none());
        sqlx::query("DELETE FROM mail_groups WHERE id = $1")
            .bind(group)
            .execute(&mut *conn)
            .await
            .unwrap();
        assert!(
            crate::account_data::load_all_owner_in(&mut conn, &keys, owner)
                .await
                .unwrap()
                .is_empty()
        );
    }

    fn search_with_empty_query_is_none() -> bool {
        search(&[], Some("  ,; "), QUICK).unwrap().is_none()
            && search(&[], None, QUICK).unwrap().is_none()
    }
}
