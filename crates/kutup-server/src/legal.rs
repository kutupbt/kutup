//! Notices and consents (docs/plans/server-personal-data.md, A3 and A4), as
//! separate records.
//!
//! - **Documents** an administrator publishes: a kind, a version, a language,
//!   where the text is and the SHA-256 of the exact text shown. A version is
//!   never edited. The current version of a kind is its latest; a sign-up must
//!   acknowledge the current version of every kind `required_at_signup`.
//! - **Acknowledgements:** the notice was shown and confirmed (not a
//!   consent), at sign-up in the account's creating transaction, or when a
//!   new required version is shown at a later sign-in. Append-only.
//! - **Consents**, per purpose (`federation_abroad`, `marketing`), given or
//!   withdrawn; each change is a row and the latest is the state. A
//!   purpose's text is the current document of the purpose's kind.
//!
//! Nothing published means nothing is asked: a server's sign-up is as before.
//! The core fixes no jurisdiction's texts: they are the operator's documents.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{PgPool, Postgres, Transaction};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::middleware::{AdminUser, AuthUser};
use crate::AppState;

/// The purposes a consent is given for: the core's, worded neutrally; their
/// texts are the operator's documents of the same kind.
pub const PURPOSES: [&str; 2] = ["federation_abroad", "marketing"];

/// One published version of a document, in one language.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct Document {
    pub id: Uuid,
    pub kind: String,
    pub version: String,
    pub language: String,
    pub url: String,
    /// The SHA-256 of the exact text, hex.
    #[sqlx(try_from = "Vec<u8>")]
    #[schema(value_type = String)]
    pub sha256: Hex,
    pub required_at_signup: bool,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String)]
    pub published_at: OffsetDateTime,
}

/// Bytes shown as lowercase hex.
#[derive(Debug, Clone)]
pub struct Hex(Vec<u8>);

impl From<Vec<u8>> for Hex {
    fn from(bytes: Vec<u8>) -> Self {
        Hex(bytes)
    }
}

impl Serialize for Hex {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(&self.0))
    }
}

const DOCUMENT_COLUMNS: &str =
    "d.id, d.kind, d.version, d.language, d.url, d.sha256, d.required_at_signup, d.published_at";

/// The current version of every kind, in every language it was published in.
pub async fn current<'e, E: sqlx::PgExecutor<'e>>(executor: E) -> sqlx::Result<Vec<Document>> {
    sqlx::query_as(&format!(
        "SELECT {DOCUMENT_COLUMNS} FROM legal_documents d
           JOIN (SELECT DISTINCT ON (kind) kind, version FROM legal_documents
                  ORDER BY kind, published_at DESC, id) latest
             ON latest.kind = d.kind AND latest.version = d.version
          ORDER BY d.kind, d.language"
    ))
    .fetch_all(executor)
    .await
}

fn acknowledgements_required(missing: &[String]) -> AppError {
    AppError::bad_request("acknowledge the current required documents")
        .with_details(json!({ "code": "acknowledgementsRequired", "kinds": missing }))
}

/// Records that `user_id` acknowledged the documents `ids` (`context`:
/// `signup` or `update`), in the caller's transaction. Each must be a current
/// document, and together they cover every required kind (`require_all`, at
/// sign-up) or name only required ones (an update).
pub async fn acknowledge(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    ids: &[Uuid],
    context: &str,
) -> AppResult<()> {
    let current = current(&mut **tx).await?;
    let required: Vec<&Document> = current.iter().filter(|d| d.required_at_signup).collect();
    for id in ids {
        if !required.iter().any(|d| d.id == *id) {
            return Err(AppError::bad_request("not a current required document")
                .with_details(json!({ "code": "documentNotCurrent" })));
        }
    }
    if context == "signup" {
        let mut missing: Vec<String> = required
            .iter()
            .filter(|d| {
                !required
                    .iter()
                    .any(|o| o.kind == d.kind && ids.contains(&o.id))
            })
            .map(|d| d.kind.clone())
            .collect();
        missing.dedup();
        if !missing.is_empty() {
            return Err(acknowledgements_required(&missing));
        }
    }
    for id in ids {
        sqlx::query(
            "INSERT INTO document_acknowledgements (user_id, document_id, context)
             VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
        )
        .bind(user_id)
        .bind(id)
        .bind(context)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

/// The current required documents `user_id` hasn't acknowledged (in any
/// language of their version): shown at the next sign-in.
pub async fn pending(pool: &PgPool, user_id: Uuid) -> sqlx::Result<Vec<Document>> {
    let current = current(pool).await?;
    let acknowledged: Vec<(String, String)> = sqlx::query_as(
        "SELECT d.kind, d.version FROM document_acknowledgements a
           JOIN legal_documents d ON d.id = a.document_id
          WHERE a.user_id = $1",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(current
        .into_iter()
        .filter(|d| {
            d.required_at_signup
                && !acknowledged
                    .iter()
                    .any(|(k, v)| *k == d.kind && *v == d.version)
        })
        .collect())
}

/// One purpose's state for an account: the latest row, if any.
#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct Consent {
    pub purpose: String,
    pub given: bool,
    pub document_id: Option<Uuid>,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String)]
    pub at: OffsetDateTime,
}

/// Each purpose's latest row for `user_id`.
pub async fn consents<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    user_id: Uuid,
) -> sqlx::Result<Vec<Consent>> {
    sqlx::query_as(
        "SELECT DISTINCT ON (purpose) purpose, given, document_id, at FROM consents
          WHERE user_id = $1 ORDER BY purpose, seq DESC",
    )
    .bind(user_id)
    .fetch_all(executor)
    .await
}

/// Whether `user_id` gave `purpose` (its latest row says so).
pub async fn given<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    user_id: Uuid,
    purpose: &str,
) -> sqlx::Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT given FROM consents WHERE user_id = $1 AND purpose = $2
          ORDER BY seq DESC LIMIT 1",
    )
    .bind(user_id)
    .bind(purpose)
    .fetch_optional(executor)
    .await?
    .unwrap_or(false))
}

/// Records a consent given or withdrawn, in the caller's transaction. Giving
/// one names the current document of the purpose's kind when one is
/// published (`documentNotCurrent` otherwise).
pub async fn set_consent(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    purpose: &str,
    given: bool,
    document_id: Option<Uuid>,
    channel: &str,
) -> AppResult<()> {
    if !PURPOSES.contains(&purpose) {
        return Err(AppError::bad_request("unknown purpose"));
    }
    let texts: Vec<Uuid> = current(&mut **tx)
        .await?
        .into_iter()
        .filter(|d| d.kind == purpose)
        .map(|d| d.id)
        .collect();
    let document_id = match (given, document_id) {
        // Given: the text shown must be the current one, when there is one.
        (true, Some(id)) if texts.contains(&id) => Some(id),
        (true, None) if texts.is_empty() => None,
        (true, _) => {
            return Err(AppError::bad_request("give it under the current document")
                .with_details(json!({ "code": "documentNotCurrent" })))
        }
        (false, _) => None,
    };
    sqlx::query(
        "INSERT INTO consents (user_id, purpose, given, document_id, channel)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(user_id)
    .bind(purpose)
    .bind(given)
    .bind(document_id)
    .bind(channel)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

// --- handlers ----------------------------------------------------------------

/// `GET /api/legal/documents` — the current documents (anyone: the sign-up
/// page shows the required ones).
#[utoipa::path(
    get,
    path = "/api/legal/documents",
    tag = "legal",
    responses((status = 200, description = "Current documents", body = Vec<Document>))
)]
pub async fn get_documents(State(state): State<AppState>) -> AppResult<Response> {
    Ok(Json(current(&state.pool).await?).into_response())
}

/// `GET /api/user/legal/pending` — the required documents the caller hasn't
/// acknowledged in their current version.
#[utoipa::path(
    get,
    path = "/api/user/legal/pending",
    tag = "legal",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "Documents to acknowledge", body = Vec<Document>))
)]
pub async fn get_pending(State(state): State<AppState>, user: AuthUser) -> AppResult<Response> {
    let user_id = crate::handlers::trusted_uuid(&user.user_id)?;
    Ok(Json(pending(&state.pool, user_id).await?).into_response())
}

/// `POST /api/user/legal/acknowledge` body.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", default)]
pub struct AcknowledgeRequest {
    document_ids: Vec<Uuid>,
}

/// `POST /api/user/legal/acknowledge` — the caller confirmed new required
/// versions.
#[utoipa::path(
    post,
    path = "/api/user/legal/acknowledge",
    tag = "legal",
    security(("BearerAuth" = [])),
    request_body = AcknowledgeRequest,
    responses((status = 204, description = "Recorded"))
)]
pub async fn post_acknowledge(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<AcknowledgeRequest>,
) -> AppResult<Response> {
    let user_id = crate::handlers::trusted_uuid(&user.user_id)?;
    if req.document_ids.is_empty() || req.document_ids.len() > 32 {
        return Err(AppError::bad_request("name 1 to 32 documents"));
    }
    let mut tx = state.pool.begin().await?;
    acknowledge(&mut tx, user_id, &req.document_ids, "update").await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `GET /api/user/consents` answer.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConsentsView {
    /// Each purpose's latest state (a purpose never answered is absent).
    consents: Vec<Consent>,
    /// The current text of each purpose, when one is published.
    documents: Vec<Document>,
}

/// `GET /api/user/consents`
#[utoipa::path(
    get,
    path = "/api/user/consents",
    tag = "legal",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "The caller's consents", body = ConsentsView))
)]
pub async fn get_consents(State(state): State<AppState>, user: AuthUser) -> AppResult<Response> {
    let user_id = crate::handlers::trusted_uuid(&user.user_id)?;
    let documents = current(&state.pool)
        .await?
        .into_iter()
        .filter(|d| PURPOSES.contains(&d.kind.as_str()))
        .collect();
    Ok(Json(ConsentsView {
        consents: consents(&state.pool, user_id).await?,
        documents,
    })
    .into_response())
}

/// `PUT /api/user/consents` body.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", default)]
pub struct ConsentRequest {
    purpose: String,
    given: bool,
    /// The text shown, when one is published for the purpose.
    document_id: Option<Uuid>,
}

/// `PUT /api/user/consents` — give or withdraw one purpose.
#[utoipa::path(
    put,
    path = "/api/user/consents",
    tag = "legal",
    security(("BearerAuth" = [])),
    request_body = ConsentRequest,
    responses((status = 204, description = "Recorded"))
)]
pub async fn put_consent(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<ConsentRequest>,
) -> AppResult<Response> {
    let user_id = crate::handlers::trusted_uuid(&user.user_id)?;
    let mut tx = state.pool.begin().await?;
    set_consent(
        &mut tx,
        user_id,
        &req.purpose,
        req.given,
        req.document_id,
        "settings",
    )
    .await?;
    // Talking to other servers rests on this consent: withdrawn, it stops.
    if req.purpose == crate::federation_switch::PURPOSE && !req.given {
        crate::federation_switch::turn_off(&mut tx, user_id).await?;
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `GET /api/admin/legal/documents` — every published version.
#[utoipa::path(
    get,
    path = "/api/admin/legal/documents",
    tag = "admin",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "Every version", body = Vec<Document>))
)]
pub async fn admin_documents(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> AppResult<Response> {
    let all: Vec<Document> = sqlx::query_as(&format!(
        "SELECT {DOCUMENT_COLUMNS} FROM legal_documents d ORDER BY d.kind, d.published_at DESC, d.language"
    ))
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(all).into_response())
}

/// `POST /api/admin/legal/documents` body.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", default)]
pub struct PublishRequest {
    kind: String,
    version: String,
    language: String,
    url: String,
    /// The SHA-256 of the exact text, hex.
    sha256: String,
    required_at_signup: bool,
}

/// `POST /api/admin/legal/documents` — publish a version (never edited
/// after). Audited.
#[utoipa::path(
    post,
    path = "/api/admin/legal/documents",
    tag = "admin",
    security(("BearerAuth" = [])),
    request_body = PublishRequest,
    responses((status = 201, description = "Published", body = Document), (status = 409, description = "That version is published already"))
)]
pub async fn publish(
    State(state): State<AppState>,
    admin: AdminUser,
    Json(req): Json<PublishRequest>,
) -> AppResult<Response> {
    let sha256 = hex::decode(req.sha256.trim())
        .ok()
        .filter(|bytes| bytes.len() == 32)
        .ok_or_else(|| AppError::bad_request("sha256 is 64 hex characters"))?;
    let url = req.url.trim();
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err(AppError::bad_request("url is an http(s) address"));
    }
    let admin_id = crate::handlers::trusted_uuid(&admin.user_id)?;
    let published: Result<Document, sqlx::Error> = sqlx::query_as(&format!(
        "INSERT INTO legal_documents AS d (kind, version, language, url, sha256, required_at_signup, published_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING {DOCUMENT_COLUMNS}"
    ))
    .bind(req.kind.trim())
    .bind(req.version.trim())
    .bind(req.language.trim())
    .bind(url)
    .bind(&sha256)
    .bind(req.required_at_signup)
    .bind(admin_id)
    .fetch_one(&state.pool)
    .await;
    let document = match published {
        Ok(document) => document,
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            return Err(AppError::conflict("that version is published already")
                .with_details(json!({ "code": "documentExists" })))
        }
        Err(sqlx::Error::Database(e)) if e.is_check_violation() => {
            return Err(AppError::bad_request(
                "kind is lowercase letters, digits and _; version 1 to 40 characters; language a code like en or pt-BR",
            ))
        }
        Err(e) => return Err(e.into()),
    };
    crate::handlers::admin::audit(
        &state.pool,
        &admin.user_id,
        "legal.publish",
        None,
        json!({
            "documentId": document.id,
            "kind": document.kind,
            "version": document.version,
            "language": document.language,
            "requiredAtSignup": document.required_at_signup,
        }),
    )
    .await;
    Ok((StatusCode::CREATED, Json(document)).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn account(pool: &PgPool) -> Uuid {
        let user_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users (id, username, master_key_envelope, recovery_key_envelope,
                public_key, account_authority_public_key,
                account_authority_key_id, account_incarnation_id, drive_signing_public_key)
             VALUES ($1, $2, '', '', '', '', '', '', '')",
        )
        .bind(user_id)
        .bind(format!("legal{}", &user_id.simple().to_string()[..12]))
        .execute(pool)
        .await
        .unwrap();
        user_id
    }

    async fn publish(pool: &PgPool, kind: &str, version: &str, required: bool) -> Uuid {
        sqlx::query_scalar(
            "INSERT INTO legal_documents (kind, version, language, url, sha256, required_at_signup)
             VALUES ($1, $2, 'en', 'https://example.org/t', sha256('t'), $3) RETURNING id",
        )
        .bind(kind)
        .bind(version)
        .bind(required)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    /// Sign-up must confirm every required kind's current version; a new
    /// version is then pending; a consent's state is its latest row, and
    /// giving one names the purpose's current text.
    #[tokio::test]
    async fn live_documents_acknowledgements_and_consents() {
        let Ok(url) = std::env::var("KUTUP_LIVE_DATABASE_URL") else {
            eprintln!("KUTUP_LIVE_DATABASE_URL unset; skipping");
            return;
        };
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .unwrap();
        let kind = format!("terms{}", &Uuid::new_v4().simple().to_string()[..8]);
        let v1 = publish(&pool, &kind, "1", true).await;
        // Every required document the database holds now (other tests' too).
        let required: Vec<Uuid> = current(&pool)
            .await
            .unwrap()
            .into_iter()
            .filter(|d| d.required_at_signup)
            .map(|d| d.id)
            .collect();
        assert!(required.contains(&v1));

        let user = account(&pool).await;
        let mut tx = pool.begin().await.unwrap();
        let without: Vec<Uuid> = required.iter().copied().filter(|id| *id != v1).collect();
        let error = acknowledge(&mut tx, user, &without, "signup")
            .await
            .unwrap_err();
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        acknowledge(&mut tx, user, &required, "signup")
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert!(!pending(&pool, user)
            .await
            .unwrap()
            .iter()
            .any(|d| d.kind == kind));

        // A new version: pending until confirmed; the old one can't stand in.
        let v2 = publish(&pool, &kind, "2", true).await;
        assert!(pending(&pool, user)
            .await
            .unwrap()
            .iter()
            .any(|d| d.id == v2));
        let mut tx = pool.begin().await.unwrap();
        assert!(acknowledge(&mut tx, user, &[v1], "update").await.is_err());
        tx.rollback().await.unwrap();
        let mut tx = pool.begin().await.unwrap();
        acknowledge(&mut tx, user, &[v2], "update").await.unwrap();
        tx.commit().await.unwrap();
        assert!(!pending(&pool, user)
            .await
            .unwrap()
            .iter()
            .any(|d| d.kind == kind));

        // Consents: the latest row is the state.
        let mut tx = pool.begin().await.unwrap();
        let text: Option<Uuid> = current(&mut *tx)
            .await
            .unwrap()
            .into_iter()
            .find(|d| d.kind == "marketing")
            .map(|d| d.id);
        set_consent(&mut tx, user, "marketing", true, text, "settings")
            .await
            .unwrap();
        assert!(given(&mut *tx, user, "marketing").await.unwrap());
        set_consent(&mut tx, user, "marketing", false, None, "settings")
            .await
            .unwrap();
        assert!(!given(&mut *tx, user, "marketing").await.unwrap());
        assert!(
            set_consent(&mut tx, user, "profiling", true, None, "settings")
                .await
                .is_err()
        );
        tx.commit().await.unwrap();

        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user)
            .execute(&pool)
            .await
            .unwrap();
        // Its documents go too: a required one left published would make
        // every later sign-up on this database need it.
        sqlx::query("DELETE FROM legal_documents WHERE kind = $1")
            .bind(&kind)
            .execute(&pool)
            .await
            .unwrap();
    }
}
