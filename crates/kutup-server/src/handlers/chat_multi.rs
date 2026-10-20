//! Multi-recipient sealed sends (docs/plans/pairwise-groups.md, slice 2;
//! Signal-Server's `PUT /v1/messages/multi_recipient`): one group message to
//! member accounts of one server, sent once. The body is libsignal's sent
//! sealed-sender v2 message and each recipient account's group capability;
//! the server checks capabilities, then budgets, then devices, and stores the
//! shared part once, with each recipient device's mailbox row naming it.
//!
//! It never learns the sender. What it learns is that these of its accounts
//! share one send (as Signal's server does).

use std::collections::BTreeMap;

use axum::extract::{ConnectInfo, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_chat_proto::{
    capability_hash, ChatWsServerMessage, EnvelopeType, SealedMultiDevicesV1,
    SealedMultiResponseV1, SealedMultiStaleV1, SealedMultiSubmissionV1,
};
use libsignal_protocol::{SealedSenderV2SentMessage, ServiceId};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::chat_hub::ChatWsOut;
use crate::error::{AppError, AppResult};
use crate::handlers::chat::{anonymous_count, envelope_type_code, AccountServerQuery};
use crate::site_settings::MultiLimits;
use crate::AppState;

/// libsignal's sent message carrying 17-byte service ids.
const SENT_VERSION: u8 = 0x23;
/// The received message each recipient device gets (libsignal's
/// `SEALED_SENDER_V2_UUID_FULL_VERSION`).
const RECEIVED_VERSION: u8 = 0x22;
/// `C_i ‖ AT_i`: an account's key material in the sent message.
const KEY_MATERIAL_LEN: usize = 48;
/// The per-recipient header the request may grow by (a service id, devices
/// and the key material), as Signal sizes the request.
const PER_RECIPIENT_BYTES: i64 = 32 + 100;
/// The direct chat suite every sealed envelope is stored under.
const SEALED_SUITE: i16 = 1;

/// One recipient account as the payload names it.
struct Recipient {
    account_id: String,
    user_id: Uuid,
    /// Device id and registration id, as the sender has them.
    devices: Vec<(u32, u32)>,
    /// `C_i ‖ AT_i`.
    key_material: Vec<u8>,
}

/// The payload, checked: its recipients by account id (in account-id order,
/// so concurrent sends lock in one order) and its shared part.
struct Parsed {
    recipients: Vec<Recipient>,
    shared: Vec<u8>,
}

fn malformed(message: &str) -> AppError {
    AppError::bad_request(message.to_owned())
        .with_details(serde_json::json!({ "code": "malformed" }))
}

fn too_large(message: &str) -> AppError {
    AppError::new(StatusCode::PAYLOAD_TOO_LARGE, message.to_owned())
}

/// Parses and sizes the payload against the request's capabilities and the
/// administrators' limits (`400`, `413`).
fn parse(submission: &SealedMultiSubmissionV1, limits: &MultiLimits) -> AppResult<Parsed> {
    submission.validate().map_err(|error| malformed(&error))?;
    let accounts = i64::try_from(submission.capabilities.len()).unwrap_or(i64::MAX);
    if accounts > limits.max_recipients {
        return Err(too_large("too many recipients in one send"));
    }
    let payload = submission
        .payload_bytes()
        .map_err(|error| malformed(&error))?;
    let ceiling = limits
        .base_bytes
        .saturating_add(PER_RECIPIENT_BYTES.saturating_mul(accounts));
    if i64::try_from(payload.len()).unwrap_or(i64::MAX) > ceiling {
        return Err(too_large("the send is too large"));
    }
    let sent = SealedSenderV2SentMessage::parse(&payload)
        .map_err(|_| malformed("payload is not a sealed sender v2 message"))?;
    if sent.version != SENT_VERSION {
        return Err(malformed("payload must be version 0x23"));
    }
    let shared = payload[sent.offset_of_shared_bytes()..].to_vec();
    let received_len = 1 + KEY_MATERIAL_LEN + shared.len();
    if i64::try_from(received_len).unwrap_or(i64::MAX) > limits.max_message_bytes {
        return Err(too_large("each recipient's message is too large"));
    }
    let mut recipients = BTreeMap::new();
    for (service_id, recipient) in &sent.recipients {
        let ServiceId::Aci(aci) = service_id else {
            return Err(malformed("recipients are account ids"));
        };
        let user_id = Uuid::from(*aci);
        let account_id = user_id.hyphenated().to_string();
        if recipient.devices.is_empty() {
            return Err(malformed("a recipient has no devices"));
        }
        let mut devices = BTreeMap::new();
        for (device, registration) in &recipient.devices {
            let device = u32::from(u8::from(*device));
            if devices.insert(device, u32::from(*registration)).is_some() {
                return Err(malformed("a device is listed twice"));
            }
        }
        let key_material = payload[sent.range_for_recipient_key_material(recipient)].to_vec();
        if key_material.len() != KEY_MATERIAL_LEN {
            return Err(malformed("a recipient's key material is malformed"));
        }
        recipients.insert(
            account_id.clone(),
            Recipient {
                account_id,
                user_id,
                devices: devices.into_iter().collect(),
                key_material,
            },
        );
    }
    if recipients.len() != submission.capabilities.len()
        || !recipients
            .keys()
            .all(|account| submission.capabilities.contains_key(account))
    {
        return Err(malformed(
            "capabilities name exactly the payload's recipient accounts",
        ));
    }
    Ok(Parsed {
        recipients: recipients.into_values().collect(),
        shared,
    })
}

/// The device answers for one recipient: missing and extra devices (`409`),
/// else devices whose registration changed (`410`).
fn device_answers(
    current: &[(i32, i64)],
    supplied: &[(u32, u32)],
) -> (Vec<u32>, Vec<u32>, Vec<u32>) {
    let current: BTreeMap<u32, u32> = current
        .iter()
        .filter_map(|(device, registration)| {
            Some((
                u32::try_from(*device).ok()?,
                u32::try_from(*registration).ok()?,
            ))
        })
        .collect();
    let supplied: BTreeMap<u32, u32> = supplied.iter().copied().collect();
    let missing = current
        .keys()
        .filter(|device| !supplied.contains_key(device))
        .copied()
        .collect();
    let extra = supplied
        .keys()
        .filter(|device| !current.contains_key(device))
        .copied()
        .collect();
    let stale = current
        .iter()
        .filter(|(device, registration)| {
            supplied
                .get(device)
                .is_some_and(|seen| seen != *registration)
        })
        .map(|(device, _)| *device)
        .collect();
    (missing, extra, stale)
}

/// `POST /api/chat/anonymous/messages/multi?server=` — one group message to
/// member accounts of one server, sent once (docs/plans/pairwise-groups.md,
/// slice 2). Anonymous, as the other sealed routes.
#[utoipa::path(
    post,
    path = "/api/chat/anonymous/messages/multi",
    tag = "chat",
    params(("server" = Option<String>, Query, description = "The recipients' server; this one when absent")),
    request_body = SealedMultiSubmissionV1,
    responses(
        (status = 200, description = "Delivered to all but `refused` and `rateLimited`", body = SealedMultiResponseV1),
        (status = 400, description = "Malformed: the payload, a device listed twice, capabilities not matching the recipients"),
        (status = 409, description = "Devices missing or extra (`devices`); nothing stored", body = SealedMultiResponseV1),
        (status = 410, description = "Devices whose registration changed (`stale`); nothing stored", body = SealedMultiResponseV1),
        (status = 413, description = "Too many recipients, or too large"),
        (status = 429, description = "Over this address's budget"),
        (status = 503, description = "peerUnavailable: send these members' copies one by one"),
    )
)]
pub async fn send_multi(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<AccountServerQuery>,
    Json(submission): Json<SealedMultiSubmissionV1>,
) -> AppResult<Response> {
    let limits = crate::site_settings::chat_multi_limits(&state.pool).await?;
    let parsed = parse(&submission, &limits)?;
    let local = &state.config.chat_server_name;
    let server = query.server.as_deref().unwrap_or(local);
    if server != local {
        // Remote destinations come with the federated route; until then the
        // client sends these members' copies one by one.
        return Err(peer_unavailable());
    }

    let mut tx = state.pool.begin().await?;
    // This address's bytes a minute (the request itself was counted by the
    // anonymous route's per-address limit).
    let address =
        crate::middleware::client_key(crate::middleware::client_ip_from_headers(&headers), peer);
    let address_digest: [u8; 32] =
        Sha256::digest([b"kutup/multi-ip-bytes/v1\0".as_slice(), address.as_bytes()].concat())
            .into();
    let bytes = i64::try_from(submission.payload.len()).unwrap_or(i64::MAX);
    if anonymous_count(&mut tx, "ip_bytes", &address_digest, bytes, 60).await?
        > limits.ip_bytes_per_min
    {
        crate::telemetry::rate_limit_rejection("anonymous_ip");
        return Err(AppError::too_many_requests(
            "anonymous delivery rate limit exceeded",
        ));
    }

    let mut answer = SealedMultiResponseV1::default();
    // 1. Capabilities: an account that isn't an active one here and a
    // capability that doesn't hold get one answer.
    let mut passing = Vec::new();
    for recipient in parsed.recipients {
        let hash = capability_hash(
            &submission
                .capability_for(&recipient.account_id)
                .ok_or_else(|| malformed("a recipient has no capability"))?,
        );
        let holds: Option<Uuid> = sqlx::query_scalar(
            "SELECT u.id FROM users u
               JOIN chat_group_capabilities c ON c.user_id = u.id
              WHERE u.id = $1 AND u.is_active AND c.capability_hash = $2
              FOR SHARE OF u",
        )
        .bind(recipient.user_id)
        .bind(&hash[..])
        .fetch_optional(&mut *tx)
        .await?;
        if holds.is_none() {
            answer.refused.push(recipient.account_id);
            continue;
        }
        // 2. Budgets per capability: one member's capability drains only
        // its own group's, never the member's direct sealed route.
        let minute = anonymous_count(&mut tx, "group_capability_minute", &hash, 1, 60).await?;
        let day = anonymous_count(&mut tx, "group_capability_day", &hash, 1, 86_400).await?;
        if minute > limits.capability_sends_per_min || day > limits.capability_sends_per_day {
            answer.rate_limited.push(recipient.account_id);
            continue;
        }
        passing.push((recipient, hash));
    }

    // 3. Devices, for those that passed: missing or extra (409) before a
    // changed registration (410); nothing is stored on either.
    for (recipient, _) in &passing {
        let current: Vec<(i32, i64)> = sqlx::query_as(
            "SELECT device_id, registration_id FROM chat_devices WHERE user_id = $1",
        )
        .bind(recipient.user_id)
        .fetch_all(&mut *tx)
        .await?;
        let (missing, extra, stale) = device_answers(&current, &recipient.devices);
        if !missing.is_empty() || !extra.is_empty() {
            answer.devices.push(SealedMultiDevicesV1 {
                account_id: recipient.account_id.clone(),
                missing_devices: missing,
                extra_devices: extra,
            });
        } else if !stale.is_empty() {
            answer.stale.push(SealedMultiStaleV1 {
                account_id: recipient.account_id.clone(),
                stale_devices: stale,
            });
        }
    }
    if !answer.devices.is_empty() {
        tx.rollback().await?;
        answer.stale.clear();
        return Ok((StatusCode::CONFLICT, Json(answer)).into_response());
    }
    if !answer.stale.is_empty() {
        tx.rollback().await?;
        return Ok((StatusCode::GONE, Json(answer)).into_response());
    }

    // 4. Store: the shared part once (only if a device gets a new row), and
    // a row per device naming it. A sendId already stored for an account
    // stores nothing again for it.
    let send_id = Uuid::parse_str(&submission.send_id)
        .map_err(|_| malformed("sendId must be a lowercase hyphenated UUID"))?;
    let mut payload_id: Option<Uuid> = None;
    let mut stored = Vec::new();
    for (recipient, hash) in &passing {
        let claimed: Option<i32> = sqlx::query_scalar(
            "INSERT INTO chat_anonymous_send_ids
                 (recipient_user_id, capability_hash, send_id, stored_count)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT DO NOTHING RETURNING stored_count",
        )
        .bind(recipient.user_id)
        .bind(&hash[..])
        .bind(send_id)
        .bind(i32::try_from(recipient.devices.len()).unwrap_or(i32::MAX))
        .fetch_optional(&mut *tx)
        .await?;
        if claimed.is_none() {
            continue;
        }
        let shared_id = match payload_id {
            Some(id) => id,
            None => {
                let id: Uuid = sqlx::query_scalar(
                    "INSERT INTO chat_shared_payloads (payload) VALUES ($1) RETURNING id",
                )
                .bind(&parsed.shared)
                .fetch_one(&mut *tx)
                .await?;
                payload_id = Some(id);
                id
            }
        };
        let content = STANDARD.encode(&recipient.key_material);
        for (device, _) in &recipient.devices {
            sqlx::query(
                "INSERT INTO chat_mailbox
                    (recipient_user_id, recipient_device_id, sealed_sender, sender_device_id,
                     envelope_type, suite, content, send_id, shared_payload_id)
                 VALUES ($1, $2, true, 0, $3, $4, $5, $6, $7)",
            )
            .bind(recipient.user_id)
            .bind(i32::try_from(*device).unwrap_or(i32::MAX))
            .bind(envelope_type_code(EnvelopeType::Message))
            .bind(SEALED_SUITE)
            .bind(&content)
            .bind(&submission.send_id)
            .bind(shared_id)
            .execute(&mut *tx)
            .await?;
            stored.push((
                recipient.user_id,
                i32::try_from(*device).unwrap_or(i32::MAX),
            ));
        }
    }
    tx.commit().await?;
    crate::telemetry::sealed_send_event("multi", "stored", stored.len() as u64);
    nudge(&state, &stored, submission.urgent).await;
    Ok(Json(answer).into_response())
}

/// Tells each stored device there is mail: connected ones drain it (nothing
/// is assembled here, so a send to many never builds every copy in memory);
/// an urgent send also wakes offline ones by web push.
async fn nudge(state: &AppState, stored: &[(Uuid, i32)], urgent: bool) {
    let Ok(text) = serde_json::to_string(&ChatWsServerMessage::DrainMailbox) else {
        return;
    };
    for (user, device) in stored {
        if urgent {
            crate::web_push::wake_if_offline(state, *user, *device);
        }
        for connection in state.chat_hub.connections(*user, *device) {
            connection.write(ChatWsOut::Text(text.clone())).await;
        }
    }
}

fn peer_unavailable() -> AppError {
    AppError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "the recipients' server can't take this send now; send their copies one by one",
    )
    .with_details(serde_json::json!({ "code": "peerUnavailable" }))
}

/// The envelope a device drains for a mailbox row naming a shared payload:
/// `0x22 ‖ C_i ‖ AT_i ‖ e_pub ‖ ciphertext`, base64, as an ordinary sealed
/// envelope.
pub(crate) fn assemble(key_material: &str, shared: &[u8]) -> AppResult<String> {
    let key_material = STANDARD
        .decode(key_material)
        .map_err(|_| AppError::internal("stored key material is not base64"))?;
    let mut message = Vec::with_capacity(1 + key_material.len() + shared.len());
    message.push(RECEIVED_VERSION);
    message.extend_from_slice(&key_material);
    message.extend_from_slice(shared);
    Ok(STANDARD.encode(message))
}

/// Deletes the shared payloads among `ids` that no mailbox row names any
/// more (after an ack); the sweep collects the rest.
pub(crate) async fn collect_payloads(pool: &sqlx::PgPool, ids: &[Uuid]) -> AppResult<u64> {
    if ids.is_empty() {
        return Ok(0);
    }
    Ok(sqlx::query(
        "DELETE FROM chat_shared_payloads p
          WHERE p.id = ANY($1)
            AND NOT EXISTS (SELECT 1 FROM chat_mailbox m WHERE m.shared_payload_id = p.id)",
    )
    .bind(ids)
    .execute(pool)
    .await?
    .rows_affected())
}

/// Deletes every shared payload no mailbox row names (retention, deleted
/// devices): collection by reference, never by a fixed expiry.
pub(crate) async fn sweep_payloads(pool: &sqlx::PgPool) -> AppResult<u64> {
    Ok(sqlx::query(
        "DELETE FROM chat_shared_payloads p
          WHERE NOT EXISTS (SELECT 1 FROM chat_mailbox m WHERE m.shared_payload_id = p.id)",
    )
    .execute(pool)
    .await?
    .rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;
    use libsignal_protocol::Aci;

    const LIMITS: MultiLimits = MultiLimits {
        max_message_bytes: 96 * 1024,
        base_bytes: 256 * 1024,
        max_recipients: 256,
        ip_bytes_per_min: 32 * 1024 * 1024,
        capability_sends_per_min: 120,
        capability_sends_per_day: 10_000,
    };

    /// A sent sealed-sender v2 message as libsignal lays it out: recipients
    /// with their devices and key material, then `e_pub ‖ ciphertext`.
    /// A recipient as the test lays it out: its account, its devices (id,
    /// registration id) and the byte its key material is filled with.
    type TestRecipient<'a> = (Uuid, &'a [(u8, u16)], u8);

    fn sent(recipients: &[TestRecipient], shared: &[u8]) -> Vec<u8> {
        let mut message = vec![SENT_VERSION];
        assert!(recipients.len() < 128, "one varint byte");
        message.push(recipients.len() as u8);
        for (account, devices, fill) in recipients {
            message.extend_from_slice(&Aci::from(*account).service_id_fixed_width_binary());
            for (index, (device, registration)) in devices.iter().enumerate() {
                message.push(*device);
                let more = if index + 1 < devices.len() { 0x8000 } else { 0 };
                message.extend_from_slice(&(registration | more).to_be_bytes());
            }
            message.extend_from_slice(&[*fill; KEY_MATERIAL_LEN]);
        }
        message.extend_from_slice(shared);
        message
    }

    fn submission(payload: &[u8], accounts: &[Uuid]) -> SealedMultiSubmissionV1 {
        SealedMultiSubmissionV1 {
            send_id: "0a0a0a0a-0000-4000-8000-000000000001".into(),
            payload: STANDARD.encode(payload),
            capabilities: accounts
                .iter()
                .map(|account| (account.hyphenated().to_string(), STANDARD.encode([9u8; 16])))
                .collect(),
            urgent: true,
        }
    }

    #[test]
    fn a_send_parses_into_recipients_and_one_shared_part() {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let shared = [7u8; 64];
        let payload = sent(&[(b, &[(1, 100)], 2), (a, &[(1, 10), (2, 20)], 1)], &shared);
        let parsed = parse(&submission(&payload, &[a, b]), &LIMITS).unwrap();
        assert_eq!(parsed.shared, shared);
        // In account-id order, whatever order the payload has.
        let mut expected = [a, b];
        expected.sort();
        let order: Vec<Uuid> = parsed.recipients.iter().map(|r| r.user_id).collect();
        assert_eq!(order, expected);
        let first = parsed.recipients.iter().find(|r| r.user_id == a).unwrap();
        assert_eq!(first.devices, vec![(1, 10), (2, 20)]);
        assert_eq!(first.key_material, [1u8; KEY_MATERIAL_LEN]);
        // What the device drains is libsignal's received message.
        let drained = STANDARD
            .decode(assemble(&STANDARD.encode(&first.key_material), &parsed.shared).unwrap())
            .unwrap();
        assert_eq!(drained[0], RECEIVED_VERSION);
        assert_eq!(&drained[1..49], &[1u8; KEY_MATERIAL_LEN]);
        assert_eq!(&drained[49..], &shared);
    }

    #[test]
    fn a_send_that_doesnt_fit_its_capabilities_or_limits_is_refused() {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let payload = sent(&[(a, &[(1, 10)], 1)], &[7u8; 64]);
        // A capability for an account the payload doesn't name, or none for
        // one it does.
        assert_eq!(
            parse(&submission(&payload, &[a, b]), &LIMITS)
                .err()
                .unwrap()
                .status,
            400
        );
        assert_eq!(
            parse(&submission(&payload, &[b]), &LIMITS)
                .err()
                .unwrap()
                .status,
            400
        );
        // A device listed twice.
        let twice = sent(&[(a, &[(1, 10), (1, 10)], 1)], &[7u8; 64]);
        assert_eq!(
            parse(&submission(&twice, &[a]), &LIMITS)
                .err()
                .unwrap()
                .status,
            400
        );
        // Not a sent message at all.
        assert_eq!(
            parse(&submission(&[0x23, 0xff], &[a]), &LIMITS)
                .err()
                .unwrap()
                .status,
            400
        );
        // Too large for one recipient's message, or too many recipients.
        let big = sent(&[(a, &[(1, 10)], 1)], &vec![7u8; 97 * 1024]);
        assert_eq!(
            parse(&submission(&big, &[a]), &LIMITS)
                .err()
                .unwrap()
                .status,
            413
        );
        let few = MultiLimits {
            max_recipients: 1,
            ..LIMITS
        };
        let two = sent(&[(a, &[(1, 10)], 1), (b, &[(1, 10)], 2)], &[7u8; 64]);
        assert_eq!(
            parse(&submission(&two, &[a, b]), &few)
                .err()
                .unwrap()
                .status,
            413
        );
    }

    #[test]
    fn devices_answer_missing_and_extra_before_stale() {
        let current = [(1, 10), (2, 20)];
        assert_eq!(
            device_answers(&current, &[(1, 10), (2, 20)]),
            (vec![], vec![], vec![])
        );
        assert_eq!(
            device_answers(&current, &[(1, 10)]),
            (vec![2], vec![], vec![])
        );
        assert_eq!(
            device_answers(&current, &[(1, 10), (2, 20), (3, 30)]),
            (vec![], vec![3], vec![])
        );
        assert_eq!(
            device_answers(&current, &[(1, 11), (2, 20)]),
            (vec![], vec![], vec![1])
        );
    }
}
