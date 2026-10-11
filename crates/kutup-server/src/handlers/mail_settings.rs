//! Mail settings (docs/plans/mail-parity.md), as Proton's mail settings:
//! auto-delete of Trash and Spam after 30 days, and whether All mail leaves
//! out Spam and Trash, whether mail outside Kutup starts signed, and the
//! appearance (layout, density, composer, conversations).
//! Emptying a folder is here too.

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::handlers::mail::{delete_for_good, mailbox, UpdatedMailMessages};
use crate::handlers::trusted_uuid;
use crate::middleware::AuthUser;
use crate::AppState;

#[derive(Debug, Serialize, Deserialize, ToSchema, PartialEq, Eq, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct MailSettings {
    /// 30 to delete Trash and Spam after 30 days, 0 not to (Proton's
    /// `AutoDeleteSpamAndTrashDays`).
    pub auto_delete_days: i32,
    /// All mail leaves out Spam and Trash (Proton's `AlmostAllMail`).
    pub almost_all_mail: bool,
    /// New mail to people outside Kutup starts with Sign on (Proton's "Sign
    /// external messages"); the composer can still change it per message.
    pub sign_outside: bool,
    /// `column`: the reading pane beside the list; `row`: below it
    /// (Proton's `ViewLayout`).
    pub view_layout: String,
    /// `comfortable` or `compact` list rows (Proton's `Density`).
    pub density: String,
    /// `popup` or `maximized`: how the composer opens (Proton's
    /// `ComposerMode`).
    pub composer_mode: String,
    /// `conversation`: the list groups each thread in one row; `message`:
    /// one row per message (Proton's `ViewMode`).
    pub view_mode: String,
}

/// The account's settings, the defaults when it has none saved.
pub(crate) async fn settings_of(state: &AppState, user_id: Uuid) -> AppResult<MailSettings> {
    let row: Option<MailSettings> = sqlx::query_as(
        "SELECT auto_delete_days, almost_all_mail, sign_outside, view_layout, density, composer_mode,
                view_mode
           FROM mail_settings WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await?;
    Ok(row.unwrap_or_else(|| MailSettings {
        auto_delete_days: 0,
        almost_all_mail: false,
        sign_outside: true,
        view_layout: "column".into(),
        density: "comfortable".into(),
        composer_mode: "popup".into(),
        view_mode: "conversation".into(),
    }))
}

/// `GET /api/mail/settings`.
#[utoipa::path(
    get,
    path = "/api/mail/settings",
    tag = "mail",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "The account's mail settings", body = MailSettings))
)]
pub async fn get(State(state): State<AppState>, user: AuthUser) -> AppResult<Json<MailSettings>> {
    let user_id = trusted_uuid(&user.user_id)?;
    Ok(Json(settings_of(&state, user_id).await?))
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateMailSettings {
    pub auto_delete_days: Option<i32>,
    pub almost_all_mail: Option<bool>,
    pub sign_outside: Option<bool>,
    pub view_layout: Option<String>,
    pub density: Option<String>,
    pub composer_mode: Option<String>,
    pub view_mode: Option<String>,
}

/// `PATCH /api/mail/settings`.
#[utoipa::path(
    patch,
    path = "/api/mail/settings",
    tag = "mail",
    security(("BearerAuth" = [])),
    request_body = UpdateMailSettings,
    responses(
        (status = 200, description = "Saved", body = MailSettings),
        (status = 400, description = "Auto-delete is 0 or 30 days; an unknown layout, density or composer mode"),
    )
)]
pub async fn update(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<UpdateMailSettings>,
) -> AppResult<Json<MailSettings>> {
    let user_id = trusted_uuid(&user.user_id)?;
    if request
        .auto_delete_days
        .is_some_and(|days| days != 0 && days != 30)
    {
        return Err(AppError::bad_request("auto-delete is 0 or 30 days"));
    }
    let one_of = |value: &Option<String>, allowed: [&str; 2]| {
        value.as_deref().is_none_or(|v| allowed.contains(&v))
    };
    if !one_of(&request.view_layout, ["column", "row"])
        || !one_of(&request.density, ["comfortable", "compact"])
        || !one_of(&request.composer_mode, ["popup", "maximized"])
        || !one_of(&request.view_mode, ["conversation", "message"])
    {
        return Err(AppError::bad_request(
            "layout is column or row, density comfortable or compact, the composer popup or maximized, view conversation or message",
        ));
    }
    sqlx::query(
        "INSERT INTO mail_settings
             (user_id, auto_delete_days, almost_all_mail, view_layout, density, composer_mode,
              view_mode, sign_outside)
         VALUES ($1, COALESCE($2, 0), COALESCE($3, false), COALESCE($4, 'column'),
                 COALESCE($5, 'comfortable'), COALESCE($6, 'popup'), COALESCE($7, 'conversation'),
                 COALESCE($8, true))
         ON CONFLICT (user_id) DO UPDATE SET
             auto_delete_days = COALESCE($2, mail_settings.auto_delete_days),
             almost_all_mail = COALESCE($3, mail_settings.almost_all_mail),
             view_layout = COALESCE($4, mail_settings.view_layout),
             density = COALESCE($5, mail_settings.density),
             composer_mode = COALESCE($6, mail_settings.composer_mode),
             view_mode = COALESCE($7, mail_settings.view_mode),
             sign_outside = COALESCE($8, mail_settings.sign_outside),
             updated_at = now()",
    )
    .bind(user_id)
    .bind(request.auto_delete_days)
    .bind(request.almost_all_mail)
    .bind(request.view_layout.as_deref())
    .bind(request.density.as_deref())
    .bind(request.composer_mode.as_deref())
    .bind(request.view_mode.as_deref())
    .bind(request.sign_outside)
    .execute(&state.pool)
    .await?;
    Ok(Json(settings_of(&state, user_id).await?))
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EmptyMailFolder {
    /// `trash` or `spam`.
    pub folder: String,
    /// A shared mailbox (its group id) instead of your own.
    pub group: Option<String>,
}

/// `POST /api/mail/messages/empty` — deletes everything in Trash or Spam for
/// good (Proton's "Delete all"), freeing its storage.
#[utoipa::path(
    post,
    path = "/api/mail/messages/empty",
    tag = "mail",
    security(("BearerAuth" = [])),
    request_body = EmptyMailFolder,
    responses(
        (status = 200, description = "How many were deleted", body = UpdatedMailMessages),
        (status = 400, description = "Only Trash and Spam are emptied"),
    )
)]
pub async fn empty(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<EmptyMailFolder>,
) -> AppResult<Json<UpdatedMailMessages>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let folder = match request.folder.as_str() {
        "trash" => "trash",
        "spam" => "spam",
        _ => return Err(AppError::bad_request("only Trash and Spam are emptied")),
    };
    let scope = mailbox(&state, user_id, request.group.as_deref()).await?;
    Ok(Json(UpdatedMailMessages {
        updated: delete_all(&state, scope, folder, None).await?,
    }))
}

/// Deletes the mailbox's messages in `folder` for good, in batches; only
/// those that came into it before `before` days ago when given.
pub(crate) async fn delete_all(
    state: &AppState,
    scope: crate::handlers::mail::Mailbox,
    folder: &'static str,
    older_than_days: Option<i32>,
) -> AppResult<u64> {
    let mut deleted = 0;
    loop {
        let ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id FROM mail_messages
              WHERE owner = $1 AND folder = $2
                AND ($3::int IS NULL OR folder_changed_at < now() - make_interval(days => $3))
              LIMIT 500",
        )
        .bind(scope.owner())
        .bind(folder)
        .bind(older_than_days)
        .fetch_all(&state.pool)
        .await?;
        if ids.is_empty() {
            break;
        }
        let removed = delete_for_good(state, scope, &ids, &[folder]).await?;
        deleted += removed;
        if removed == 0 {
            break;
        }
    }
    Ok(deleted)
}
