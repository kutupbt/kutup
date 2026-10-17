//! Auto-reply (docs/plans/mail-parity.md, P2), as Proton's AutoResponder:
//! while it is on, a message that reaches an account's own inbox is answered
//! once per sender every 7 days (RFC 3834 §2, the Sieve vacation default),
//! never mail that is automatic itself, from a list, filed as spam, or that
//! names the account only in Bcc (RFC 5230 §4.5). The answer is kept in
//! Sent, as Proton keeps it.
//!
//! The server writes the answer while the account is away, so it holds the
//! text readable, as Proton does; a Kutup sender's copy is encrypted to them
//! on arrival like any mail from outside (zero access).

use aws_sdk_s3::primitives::ByteStream;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use sqlx::PgPool;
use time::format_description::well_known::Rfc2822;
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time};
use uuid::Uuid;

use super::headers::{self, Mailbox, Readable};
use super::{insert_message, object_key, NewMessage};
use crate::AppState;

/// A sender is answered again only after this many days.
pub const RESEND_AFTER_DAYS: i32 = 7;
/// The largest message text, HTML or plain, as Proton's.
pub const MAX_MESSAGE_BYTES: usize = 10_000;

/// When the auto-reply is on, in the account's chosen time zone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Schedule {
    /// From `start` until `end`.
    Fixed {
        start: PrimitiveDateTime,
        end: PrimitiveDateTime,
    },
    /// On the chosen weekdays (0 Sunday to 6 Saturday), between two times.
    Daily {
        days: Vec<u8>,
        start_minute: u16,
        end_minute: u16,
    },
    /// Every week from one weekday and time to another.
    Weekly {
        start_day: u8,
        start_minute: u16,
        end_day: u8,
        end_minute: u16,
    },
    /// Every month from one day (1–31) and time to another.
    Monthly {
        start_day: u8,
        start_minute: u16,
        end_day: u8,
        end_minute: u16,
    },
    /// Until it is turned off.
    Permanent,
}

const DAY: u32 = 24 * 60;

/// `position` lies in `[start, end)`, which wraps round the period when
/// `end` comes before `start`; equal ends mean the whole period.
fn within(position: u32, start: u32, end: u32) -> bool {
    match start.cmp(&end) {
        std::cmp::Ordering::Less => start <= position && position < end,
        std::cmp::Ordering::Greater => position >= start || position < end,
        std::cmp::Ordering::Equal => true,
    }
}

impl Schedule {
    /// Whether it is on at `now`, a wall-clock time in its zone.
    pub fn is_on(&self, now: PrimitiveDateTime) -> bool {
        let minute = u32::from(now.hour()) * 60 + u32::from(now.minute());
        let weekday = u32::from(now.weekday().number_days_from_sunday());
        match self {
            Schedule::Fixed { start, end } => *start <= now && now < *end,
            Schedule::Daily {
                days,
                start_minute,
                end_minute,
            } => {
                days.contains(&(weekday as u8))
                    && within(minute, u32::from(*start_minute), u32::from(*end_minute))
            }
            Schedule::Weekly {
                start_day,
                start_minute,
                end_day,
                end_minute,
            } => within(
                weekday * DAY + minute,
                u32::from(*start_day) * DAY + u32::from(*start_minute),
                u32::from(*end_day) * DAY + u32::from(*end_minute),
            ),
            Schedule::Monthly {
                start_day,
                start_minute,
                end_day,
                end_minute,
            } => within(
                (u32::from(now.day()) - 1) * DAY + minute,
                (u32::from(*start_day) - 1) * DAY + u32::from(*start_minute),
                (u32::from(*end_day) - 1) * DAY + u32::from(*end_minute),
            ),
            Schedule::Permanent => true,
        }
    }

    /// The stored kind.
    pub fn repeat(&self) -> &'static str {
        match self {
            Schedule::Fixed { .. } => "fixed",
            Schedule::Daily { .. } => "daily",
            Schedule::Weekly { .. } => "weekly",
            Schedule::Monthly { .. } => "monthly",
            Schedule::Permanent => "permanent",
        }
    }
}

/// `YYYY-MM-DDTHH:MM`, as an `<input type="datetime-local">` gives it.
pub fn parse_local(text: &str) -> Option<PrimitiveDateTime> {
    let (date, time) = text.split_once('T')?;
    let mut date = date.splitn(3, '-').map(str::parse::<u16>);
    let (year, month, day) = (date.next()?.ok()?, date.next()?.ok()?, date.next()?.ok()?);
    let (hour, minute) = time.split_once(':')?;
    let date = Date::from_calendar_date(
        i32::from(year),
        Month::try_from(u8::try_from(month).ok()?).ok()?,
        u8::try_from(day).ok()?,
    )
    .ok()?;
    let time = Time::from_hms(hour.parse().ok()?, minute.parse().ok()?, 0).ok()?;
    Some(PrimitiveDateTime::new(date, time))
}

/// The inverse of [`parse_local`].
pub fn format_local(at: PrimitiveDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}",
        at.year(),
        u8::from(at.month()),
        at.day(),
        at.hour(),
        at.minute()
    )
}

/// An account's saved auto-reply.
#[derive(Debug, Clone)]
pub struct Saved {
    pub enabled: bool,
    pub zone: String,
    pub schedule: Schedule,
    pub message_html: String,
    pub message_text: String,
    /// Now, on the wall clock of `zone`.
    pub local_now: PrimitiveDateTime,
}

impl Saved {
    /// On and inside its schedule.
    pub fn is_on(&self) -> bool {
        self.enabled && self.schedule.is_on(self.local_now)
    }
}

type Row = (
    bool,
    String,
    String,
    Option<PrimitiveDateTime>,
    Option<PrimitiveDateTime>,
    Vec<i16>,
    Option<i16>,
    Option<i16>,
    Option<i16>,
    Option<i16>,
    String,
    String,
    PrimitiveDateTime,
);

fn schedule_of(row: &Row) -> Option<Schedule> {
    let (_, repeat, _, start, end, days, start_day, end_day, start_minute, end_minute, ..) = row;
    let minutes = || {
        Some((
            u16::try_from((*start_minute)?).ok()?,
            u16::try_from((*end_minute)?).ok()?,
        ))
    };
    let days_of = || {
        Some((
            u8::try_from((*start_day)?).ok()?,
            u8::try_from((*end_day)?).ok()?,
        ))
    };
    Some(match repeat.as_str() {
        "fixed" => Schedule::Fixed {
            start: (*start)?,
            end: (*end)?,
        },
        "daily" => {
            let (start_minute, end_minute) = minutes()?;
            Schedule::Daily {
                days: days.iter().filter_map(|d| u8::try_from(*d).ok()).collect(),
                start_minute,
                end_minute,
            }
        }
        "weekly" | "monthly" => {
            let (start_minute, end_minute) = minutes()?;
            let (start_day, end_day) = days_of()?;
            if repeat == "weekly" {
                Schedule::Weekly {
                    start_day,
                    start_minute,
                    end_day,
                    end_minute,
                }
            } else {
                Schedule::Monthly {
                    start_day,
                    start_minute,
                    end_day,
                    end_minute,
                }
            }
        }
        "permanent" => Schedule::Permanent,
        _ => return None,
    })
}

/// The account's auto-reply, if it saved one.
pub async fn load(pool: &PgPool, user_id: Uuid) -> sqlx::Result<Option<Saved>> {
    let row: Option<Row> = sqlx::query_as(
        "SELECT enabled, repeat, zone, start_local, end_local, days, start_day, end_day,
                start_minute, end_minute, message_html, message_text, now() AT TIME ZONE zone
           FROM mail_auto_replies WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|row| {
        let schedule = schedule_of(&row)?;
        let (enabled, _, zone, .., message_html, message_text, local_now) = row;
        Some(Saved {
            enabled,
            zone,
            schedule,
            message_html,
            message_text,
            local_now,
        })
    }))
}

/// One message just delivered to an account's own mailbox.
#[derive(Debug, Clone, Copy)]
pub struct Delivered {
    pub user_id: Uuid,
    pub message: Uuid,
}

/// Answers `delivered` in the background, after its delivery committed,
/// when the account's auto-reply is on.
pub fn spawn(state: &AppState, delivered: Delivered) {
    let state = state.clone();
    tokio::spawn(async move {
        if let Err(error) = answer(&state, delivered).await {
            tracing::warn!(error = %error, "mail: auto-reply failed");
        }
    });
}

/// Senders that are machines or lists (RFC 3834 §3.1.4, RFC 5230 §4.6).
fn automated_sender(address: &str) -> bool {
    let local = address
        .rsplit_once('@')
        .map_or(address, |(local, _)| local)
        .to_ascii_lowercase();
    matches!(
        local.as_str(),
        "mailer-daemon"
            | "postmaster"
            | "listserv"
            | "majordomo"
            | "noreply"
            | "no-reply"
            | "no_reply"
            | "donotreply"
            | "do-not-reply"
            | "do_not_reply"
    ) || local.starts_with("owner-")
        || local.ends_with("-request")
        || local.starts_with("bounce")
}

type MessageRow = (
    String,
    String,
    String,
    sqlx::types::Json<Vec<Mailbox>>,
    sqlx::types::Json<Vec<Mailbox>>,
    String,
    Option<String>,
    Vec<String>,
    String,
    bool,
    String,
);

async fn answer(state: &AppState, delivered: Delivered) -> anyhow::Result<()> {
    let Some(saved) = load(&state.pool, delivered.user_id).await? else {
        return Ok(());
    };
    if !saved.is_on() {
        return Ok(());
    }
    let row: Option<MessageRow> = sqlx::query_as(
        // Mail to an old (receiving) address is answered too, always from
        // the account's current one: the old address sends nothing.
        "SELECT a.address, m.folder, m.from_address, m.to_list, m.cc_list, m.subject,
                m.message_id, m.references_list,
                COALESCE(NULLIF(i.display_name, ''), u.username), u.is_admin, cur.address
           FROM mail_messages m
           JOIN mail_addresses a ON a.id = m.address_id
           JOIN users u ON u.id = a.user_id
           JOIN mail_addresses cur ON cur.user_id = u.id AND cur.state = 'active'
           LEFT JOIN mail_identities i ON i.address_id = cur.id
          WHERE m.id = $1 AND m.user_id = $2 AND m.direction = 'inbound'",
    )
    .bind(delivered.message)
    .bind(delivered.user_id)
    .fetch_optional(&state.pool)
    .await?;
    // Blocked meanwhile, or deleted already.
    let Some((own, folder, from, to, cc, subject, message_id, references, name, is_admin, current)) =
        row
    else {
        return Ok(());
    };
    // Compared as senders are: this server's addresses in any spelling.
    let key = |address: &str| super::sender_key(&state.config.chat_server_name, address);
    // Answered at the address as written; remembered as compared.
    let sender = from.trim().to_ascii_lowercase();
    let sender_key = key(&sender);
    let named =
        to.0.iter()
            .chain(cc.0.iter())
            .any(|m| key(&m.address) == key(&own));
    if matches!(folder.as_str(), "spam" | "trash")
        || !named
        || sender.is_empty()
        || !sender.contains('@')
        || sender_key == key(&own)
        || sender_key == key(&current)
        || automated_sender(&sender)
    {
        return Ok(());
    }
    let local = super::local_address(&sender, &state.config.chat_server_name);
    // Outside mail goes through Stalwart only for those who may send there.
    if local.is_none()
        && (!crate::site_settings::mail_outside_sending(
            &state.pool,
            state.config.mail_outside_sending,
        )
        .await?
        .allows(is_admin)
            || super::safety::check_send(state, delivered.user_id, 1)
                .await
                .is_err())
    {
        return Ok(());
    }
    // Once per sender every RESEND_AFTER_DAYS: the claim is the record.
    let claimed: Option<String> = sqlx::query_scalar(
        "INSERT INTO mail_auto_reply_sent (user_id, sender) VALUES ($1, $2)
         ON CONFLICT (user_id, sender) DO UPDATE SET sent_at = now()
          WHERE mail_auto_reply_sent.sent_at < now() - make_interval(days => $3)
         RETURNING sender",
    )
    .bind(delivered.user_id)
    .bind(&sender_key)
    .bind(RESEND_AFTER_DAYS)
    .fetch_optional(&state.pool)
    .await?;
    if claimed.is_none() {
        return Ok(());
    }
    let reply_id = format!("{}@{}", Uuid::new_v4(), state.config.chat_server_name);
    let raw = compose(&Compose {
        from: &Mailbox {
            address: current.clone(),
            name,
        },
        to: &sender,
        subject: &subject,
        in_reply_to: message_id.as_deref(),
        references: &references,
        message_id: &reply_id,
        html: &saved.message_html,
        text: &saved.message_text,
        date: OffsetDateTime::now_utc(),
    });
    let sent = match &local {
        Some(address) => match super::resolve(state, address).await {
            Ok(recipient) => {
                let reply = super::store(state, &recipient, &raw).await;
                if reply.is_success() {
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("not stored: {reply:?}"))
                }
            }
            Err(reply) => Err(anyhow::anyhow!("not deliverable: {reply:?}")),
        },
        None => super::submit::submit(
            &state.config.mail_submission_addr,
            &format!("kutup@{}", state.config.chat_server_name),
            &state.config.mail_inbound_token,
            super::submit::Envelope {
                from: &current,
                recipients: std::slice::from_ref(&sender),
                message: &raw,
            },
        )
        .await
        .map_err(anyhow::Error::from),
    };
    if let Err(error) = sent {
        // Not answered: the next message from them may try again.
        sqlx::query("DELETE FROM mail_auto_reply_sent WHERE user_id = $1 AND sender = $2")
            .bind(delivered.user_id)
            .bind(&sender_key)
            .execute(&state.pool)
            .await?;
        return Err(error);
    }
    keep_in_sent(
        state,
        delivered.user_id,
        &current,
        &raw,
        i32::from(local.is_none()),
    )
    .await
}

/// The answer's copy in the account's Sent, encrypted to its own key.
async fn keep_in_sent(
    state: &AppState,
    user_id: Uuid,
    own: &str,
    raw: &[u8],
    external_recipients: i32,
) -> anyhow::Result<()> {
    let Ok(recipient) = super::resolve(state, own).await else {
        // A full pool keeps no copy; the answer went all the same.
        return Ok(());
    };
    let owned = raw.to_vec();
    let public_key = recipient.public_key.clone();
    let (readable, ciphertext) = tokio::task::spawn_blocking(move || {
        let readable = Readable::parse(&owned);
        kutup_crypto::mail_key::encrypt_binary(&public_key, &owned).map(|c| (readable, c))
    })
    .await??;
    let id = Uuid::new_v4();
    let key = object_key(user_id, id);
    let size = i64::try_from(ciphertext.len())?;
    let version = state
        .storage
        .put_object_versioned(&key, ByteStream::from(ciphertext), size)
        .await?;
    let recorded: anyhow::Result<bool> = async {
        let mut tx = state.pool.begin().await?;
        let pool = crate::storage_pool::lock(&mut tx, user_id, Default::default()).await?;
        if !pool.fits(size, 0) {
            return Ok(false);
        }
        let inserted = insert_message(
            &mut tx,
            NewMessage {
                id,
                user_id: Some(user_id),
                address_id: recipient.address_id,
                thread_id: None,
                direction: "outbound",
                folder: "sent",
                protection: "zero_access",
                seen: true,
                object_key: &key,
                object_version: &version,
                size,
                readable: &readable,
                bcc: &[],
                external_recipients,
                group_id: None,
                key_packet: None,
                sent_by: None,
            },
        )
        .await?;
        tx.commit().await?;
        Ok(inserted)
    }
    .await;
    if !matches!(recorded, Ok(true)) {
        if let Err(error) = state.storage.delete_stored(&key, &version).await {
            tracing::warn!(error = %error, "mail: unrecorded auto-reply copy left for the sweep");
        }
    }
    recorded.map(|_| ())
}

/// What an answer says.
pub struct Compose<'a> {
    pub from: &'a Mailbox,
    pub to: &'a str,
    pub subject: &'a str,
    pub in_reply_to: Option<&'a str>,
    pub references: &'a [String],
    pub message_id: &'a str,
    pub html: &'a str,
    pub text: &'a str,
    pub date: OffsetDateTime,
}

/// A header value: as is when plain ASCII, else RFC 2047 encoded; control
/// characters never reach the header.
fn header_text(value: &str) -> String {
    let clean: String = value.chars().filter(|c| !c.is_control()).collect();
    if clean.is_ascii() {
        clean
    } else {
        format!("=?UTF-8?B?{}?=", STANDARD.encode(clean.as_bytes()))
    }
}

fn base64_lines(body: &str) -> String {
    let encoded = STANDARD.encode(body.as_bytes());
    let mut out = String::with_capacity(encoded.len() + encoded.len() / 76 * 2 + 2);
    for chunk in encoded.as_bytes().chunks(76) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        out.push_str("\r\n");
    }
    out
}

/// A message id for a header, without stray brackets or spaces.
fn id_text(id: &str) -> String {
    id.chars()
        .filter(|c| !c.is_control() && !c.is_whitespace() && *c != '<' && *c != '>')
        .collect()
}

/// The answer as MIME: `multipart/alternative`, text and HTML, marked as
/// automatic (RFC 3834 `Auto-Submitted`, and the `X-Autoreply` Proton and
/// others look for).
pub fn compose(message: &Compose<'_>) -> Vec<u8> {
    let subject = message.subject.trim();
    let subject = if subject.is_empty() {
        "Auto".to_string()
    } else if subject.to_ascii_lowercase().starts_with("auto:") {
        subject.to_string()
    } else {
        format!("Auto: {subject}")
    };
    let name: String = message
        .from
        .name
        .trim()
        .chars()
        .filter(|c| !c.is_control() && *c != '"' && *c != '\\')
        .collect();
    let address = id_text(&message.from.address);
    // An encoded word stands alone; plain text goes in quotes.
    let from = match (name.is_empty(), name.is_ascii()) {
        (true, _) => format!("<{address}>"),
        (false, true) => format!("\"{name}\" <{address}>"),
        (false, false) => format!("{} <{address}>", header_text(&name)),
    };
    let boundary = format!("kutup-{}", Uuid::new_v4().simple());
    let mut out = String::new();
    out.push_str(&format!("From: {from}\r\n"));
    out.push_str(&format!("To: <{}>\r\n", id_text(message.to)));
    out.push_str(&format!("Subject: {}\r\n", header_text(&subject)));
    out.push_str(&format!(
        "Date: {}\r\n",
        message.date.format(&Rfc2822).unwrap_or_default()
    ));
    out.push_str(&format!(
        "Message-ID: <{}>\r\n",
        id_text(message.message_id)
    ));
    if let Some(parent) = message.in_reply_to {
        let parent = id_text(parent);
        out.push_str(&format!("In-Reply-To: <{parent}>\r\n"));
        let mut chain: Vec<String> = message.references.iter().map(|r| id_text(r)).collect();
        if !chain.contains(&parent) {
            chain.push(parent);
        }
        let chain: Vec<String> = chain.into_iter().map(|r| format!("<{r}>")).collect();
        out.push_str(&format!("References: {}\r\n", chain.join(" ")));
    }
    out.push_str("Auto-Submitted: auto-replied\r\n");
    out.push_str("X-Autoreply: yes\r\n");
    out.push_str("Precedence: auto_reply\r\n");
    out.push_str("MIME-Version: 1.0\r\n");
    out.push_str(&format!(
        "Content-Type: multipart/alternative; boundary=\"{boundary}\"\r\n\r\n"
    ));
    for (kind, body) in [("plain", message.text), ("html", message.html)] {
        out.push_str(&format!("--{boundary}\r\n"));
        out.push_str(&format!("Content-Type: text/{kind}; charset=utf-8\r\n"));
        out.push_str("Content-Transfer-Encoding: base64\r\n\r\n");
        out.push_str(&base64_lines(body));
    }
    out.push_str(&format!("--{boundary}--\r\n"));
    out.into_bytes()
}

/// Forgets who was answered more than [`RESEND_AFTER_DAYS`] ago; run with
/// the hourly mail upkeep.
pub async fn forget_old(pool: &PgPool) -> sqlx::Result<u64> {
    Ok(sqlx::query(
        "DELETE FROM mail_auto_reply_sent WHERE sent_at < now() - make_interval(days => $1)",
    )
    .bind(RESEND_AFTER_DAYS)
    .execute(pool)
    .await?
    .rows_affected())
}

/// Whether mail with these headers may be answered: not automatic itself
/// (`Auto-Submitted` other than `no`, `X-Autoreply` and kin), not from a
/// list (`List-Id`, `List-Unsubscribe`, `Precedence: bulk/list/junk`), and
/// with a return path to answer (RFC 3834 §2, RFC 5230 §4.6).
pub fn may_answer(raw: &[u8]) -> bool {
    for (name, value) in headers::fields(raw) {
        let value = value.trim().to_ascii_lowercase();
        let refuses = match name.as_str() {
            "auto-submitted" => value != "no",
            "x-autoreply" | "x-autorespond" | "x-autoreply-from" | "x-mail-autoreply" => true,
            "list-id" | "list-unsubscribe" | "list-post" | "list-help" => true,
            "precedence" | "x-precedence" => {
                matches!(value.as_str(), "bulk" | "list" | "junk" | "auto_reply")
            }
            "return-path" => value
                .trim_matches(|c| c == '<' || c == '>')
                .trim()
                .is_empty(),
            _ => false,
        };
        if refuses {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str) -> PrimitiveDateTime {
        parse_local(text).expect("a local time")
    }

    #[test]
    fn local_times_round_trip_and_refuse_nonsense() {
        assert_eq!(format_local(at("2026-10-12T09:05")), "2026-10-12T09:05");
        assert!(parse_local("2026-02-30T09:00").is_none());
        assert!(parse_local("2026-10-12T24:00").is_none());
        assert!(parse_local("2026-10-12").is_none());
    }

    #[test]
    fn fixed_is_on_from_start_until_end() {
        let s = Schedule::Fixed {
            start: at("2026-10-12T09:00"),
            end: at("2026-10-19T09:00"),
        };
        assert!(!s.is_on(at("2026-10-12T08:59")));
        assert!(s.is_on(at("2026-10-12T09:00")));
        assert!(!s.is_on(at("2026-10-19T09:00")));
    }

    #[test]
    fn daily_needs_the_weekday_and_wraps_past_midnight() {
        // 2026-10-12 is a Monday.
        let s = Schedule::Daily {
            days: vec![1],
            start_minute: 18 * 60,
            end_minute: 8 * 60,
        };
        assert!(s.is_on(at("2026-10-12T22:00")));
        assert!(s.is_on(at("2026-10-12T07:00")));
        assert!(!s.is_on(at("2026-10-12T12:00")));
        assert!(!s.is_on(at("2026-10-13T22:00")));
    }

    #[test]
    fn weekly_wraps_round_the_week() {
        // Friday 18:00 to Monday 08:00.
        let s = Schedule::Weekly {
            start_day: 5,
            start_minute: 18 * 60,
            end_day: 1,
            end_minute: 8 * 60,
        };
        assert!(s.is_on(at("2026-10-17T12:00"))); // Saturday
        assert!(s.is_on(at("2026-10-12T07:59"))); // Monday
        assert!(!s.is_on(at("2026-10-12T08:00")));
        assert!(!s.is_on(at("2026-10-14T12:00"))); // Wednesday
    }

    #[test]
    fn monthly_counts_days_of_the_month() {
        let s = Schedule::Monthly {
            start_day: 1,
            start_minute: 0,
            end_day: 3,
            end_minute: 0,
        };
        assert!(s.is_on(at("2026-10-02T12:00")));
        assert!(!s.is_on(at("2026-10-03T00:00")));
    }

    #[test]
    fn machines_and_lists_get_no_answer() {
        assert!(automated_sender("MAILER-DAEMON@example.org"));
        assert!(automated_sender("no-reply@example.org"));
        assert!(automated_sender("owner-list@example.org"));
        assert!(automated_sender("list-request@example.org"));
        assert!(!automated_sender("ayse@example.org"));
        assert!(may_answer(b"From: a@b.c\r\nAuto-Submitted: no\r\n\r\nhi"));
        assert!(!may_answer(
            b"From: a@b.c\r\nAuto-Submitted: auto-replied\r\n\r\nhi"
        ));
        assert!(!may_answer(
            b"From: a@b.c\r\nList-Id: <x.example.org>\r\n\r\nhi"
        ));
        assert!(!may_answer(b"From: a@b.c\r\nPrecedence: bulk\r\n\r\nhi"));
        assert!(!may_answer(b"Return-Path: <>\r\nFrom: a@b.c\r\n\r\nhi"));
        assert!(!may_answer(b"From: a@b.c\r\nX-Autoreply: yes\r\n\r\nhi"));
    }

    #[test]
    fn the_answer_is_marked_automatic_and_threads() {
        let raw = compose(&Compose {
            from: &Mailbox {
                address: "ayse@kutup.test".into(),
                name: "Ayşe Yılmaz".into(),
            },
            to: "bob@example.org",
            subject: "Toplantı\r\nBcc: x@y.z",
            in_reply_to: Some("orig@example.org"),
            references: &["root@example.org".into()],
            message_id: "reply@kutup.test",
            html: "<p>Dışarıdayım.</p>",
            text: "Dışarıdayım.",
            date: OffsetDateTime::UNIX_EPOCH,
        });
        let text = String::from_utf8(raw.clone()).unwrap();
        assert!(text.contains("Auto-Submitted: auto-replied\r\n"));
        assert!(text.contains("References: <root@example.org> <orig@example.org>\r\n"));
        assert!(!text.contains("\r\nBcc:"));
        let parsed = Readable::parse(&raw);
        assert_eq!(parsed.subject, "Auto: ToplantıBcc: x@y.z");
        assert_eq!(parsed.in_reply_to.as_deref(), Some("orig@example.org"));
        assert_eq!(parsed.from.unwrap().name, "Ayşe Yılmaz");
        assert!(!may_answer(&raw));
    }
}
