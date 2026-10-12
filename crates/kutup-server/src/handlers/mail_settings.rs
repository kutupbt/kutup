//! Mail settings (docs/plans/mail-parity.md), as Proton's mail settings:
//! auto-delete of Trash and Spam after 30 days, and whether All mail leaves
//! out Spam and Trash, PGP for mail outside Kutup (sign, attach the key,
//! PGP/MIME or Inline), and the appearance (layout, density, composer,
//! conversations).
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
    /// Every new message carries your public key as an attachment (Proton's
    /// `AttachPublicKey`).
    pub attach_public_key: bool,
    /// `pgp_mime` or `inline`: how mail to outside OpenPGP users is
    /// encrypted or signed (Proton's `PGPScheme`); Inline is plain text.
    pub pgp_scheme: String,
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
    /// A link in a message that leads outside Kutup asks first (Proton's
    /// `ConfirmLink`).
    pub confirm_link: bool,
    /// Messages or conversations on a page of the list: 50, 100 or 200
    /// (Proton's `PageSize`).
    pub page_size: i32,
    /// Moving list mail to Spam: `ask`, `just_spam`, or
    /// `spam_and_unsubscribe` (Proton's `SpamAction`, "Auto-unsubscribe").
    pub spam_action: String,
    /// Remote images: `ask` (blocked until loaded) or `always` (Proton's
    /// "Auto show remote images"); never automatic in Spam.
    pub remote_images: String,
    /// Undo send: 0, 5, 10 or 20 seconds a send waits before it goes
    /// (Proton's `DelaySendSeconds`, 10 by default).
    pub delay_send_seconds: i32,
    /// New messages start as `html` or `plain` text (Proton's Composer mode).
    pub draft_type: String,
    /// `ltr` or `rtl` (Proton's Composer text direction).
    pub text_direction: String,
    /// The composer's default font and size in pixels (Proton's default
    /// font/size: Arial, 14).
    pub font_face: String,
    pub font_size: i32,
}

/// The composer fonts (Proton's FONT_FACES).
const FONT_FACES: [&str; 10] = [
    "sans-serif",
    "serif",
    "georgia",
    "arial",
    "helvetica",
    "monospace",
    "tahoma",
    "verdana",
    "times",
    "trebuchet",
];

/// The account's settings, the defaults when it has none saved.
pub(crate) async fn settings_of(state: &AppState, user_id: Uuid) -> AppResult<MailSettings> {
    let row: Option<MailSettings> = sqlx::query_as(
        "SELECT auto_delete_days, almost_all_mail, sign_outside, attach_public_key, pgp_scheme,
                view_layout, density, composer_mode, view_mode, confirm_link, page_size, spam_action, remote_images, delay_send_seconds,
                draft_type, text_direction, font_face, font_size
           FROM mail_settings WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await?;
    Ok(row.unwrap_or_else(|| MailSettings {
        auto_delete_days: 0,
        almost_all_mail: false,
        sign_outside: true,
        attach_public_key: false,
        pgp_scheme: "pgp_mime".into(),
        view_layout: "column".into(),
        density: "comfortable".into(),
        composer_mode: "popup".into(),
        view_mode: "conversation".into(),
        confirm_link: true,
        page_size: 50,
        spam_action: "ask".into(),
        remote_images: "ask".into(),
        delay_send_seconds: state.config.mail_default_delay_send_seconds,
        draft_type: "html".into(),
        text_direction: "ltr".into(),
        font_face: "arial".into(),
        font_size: 14,
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
    pub attach_public_key: Option<bool>,
    pub pgp_scheme: Option<String>,
    pub confirm_link: Option<bool>,
    pub page_size: Option<i32>,
    pub spam_action: Option<String>,
    pub remote_images: Option<String>,
    pub delay_send_seconds: Option<i32>,
    pub draft_type: Option<String>,
    pub text_direction: Option<String>,
    pub font_face: Option<String>,
    pub font_size: Option<i32>,
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
        (status = 400, description = "Auto-delete is 0 or 30 days; page size 50, 100 or 200; an unknown layout, density or composer mode"),
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
    if request
        .page_size
        .is_some_and(|size| ![50, 100, 200].contains(&size))
    {
        return Err(AppError::bad_request("page size is 50, 100 or 200"));
    }
    if request
        .delay_send_seconds
        .is_some_and(|s| ![0, 5, 10, 20].contains(&s))
    {
        return Err(AppError::bad_request("undo send is 0, 5, 10 or 20 seconds"));
    }
    if request
        .draft_type
        .as_deref()
        .is_some_and(|v| !["html", "plain"].contains(&v))
        || request
            .text_direction
            .as_deref()
            .is_some_and(|v| !["ltr", "rtl"].contains(&v))
        || request
            .font_face
            .as_deref()
            .is_some_and(|v| !FONT_FACES.contains(&v))
        || request
            .font_size
            .is_some_and(|v| !(10..=26).contains(&v) || v % 2 != 0)
    {
        return Err(AppError::bad_request(
            "composer: html or plain, ltr or rtl, a known font, 10 to 26 pixels",
        ));
    }
    if request
        .spam_action
        .as_deref()
        .is_some_and(|a| !["ask", "just_spam", "spam_and_unsubscribe"].contains(&a))
    {
        return Err(AppError::bad_request(
            "spam action is ask, just_spam or spam_and_unsubscribe",
        ));
    }
    let one_of = |value: &Option<String>, allowed: [&str; 2]| {
        value.as_deref().is_none_or(|v| allowed.contains(&v))
    };
    if !one_of(&request.view_layout, ["column", "row"])
        || !one_of(&request.density, ["comfortable", "compact"])
        || !one_of(&request.composer_mode, ["popup", "maximized"])
        || !one_of(&request.view_mode, ["conversation", "message"])
        || !one_of(&request.pgp_scheme, ["pgp_mime", "inline"])
        || !one_of(&request.remote_images, ["ask", "always"])
    {
        return Err(AppError::bad_request(
            "layout is column or row, density comfortable or compact, the composer popup or maximized, view conversation or message, PGP pgp_mime or inline, remote images ask or always",
        ));
    }
    sqlx::query(
        "INSERT INTO mail_settings
             (user_id, auto_delete_days, almost_all_mail, view_layout, density, composer_mode,
              view_mode, sign_outside, attach_public_key, pgp_scheme, confirm_link, page_size, spam_action, remote_images, delay_send_seconds,
              draft_type, text_direction, font_face, font_size)
         VALUES ($1, COALESCE($2, 0), COALESCE($3, false), COALESCE($4, 'column'),
                 COALESCE($5, 'comfortable'), COALESCE($6, 'popup'), COALESCE($7, 'conversation'),
                 COALESCE($8, true), COALESCE($9, false), COALESCE($10, 'pgp_mime'), COALESCE($11, true),
                 COALESCE($12, 50), COALESCE($13, 'ask'), COALESCE($14, 'ask'),
                 COALESCE($15, $16), COALESCE($17, 'html'), COALESCE($18, 'ltr'),
                 COALESCE($19, 'arial'), COALESCE($20, 14))
         ON CONFLICT (user_id) DO UPDATE SET
             auto_delete_days = COALESCE($2, mail_settings.auto_delete_days),
             almost_all_mail = COALESCE($3, mail_settings.almost_all_mail),
             view_layout = COALESCE($4, mail_settings.view_layout),
             density = COALESCE($5, mail_settings.density),
             composer_mode = COALESCE($6, mail_settings.composer_mode),
             view_mode = COALESCE($7, mail_settings.view_mode),
             sign_outside = COALESCE($8, mail_settings.sign_outside),
             attach_public_key = COALESCE($9, mail_settings.attach_public_key),
             pgp_scheme = COALESCE($10, mail_settings.pgp_scheme),
             confirm_link = COALESCE($11, mail_settings.confirm_link),
             page_size = COALESCE($12, mail_settings.page_size),
             spam_action = COALESCE($13, mail_settings.spam_action),
             remote_images = COALESCE($14, mail_settings.remote_images),
             delay_send_seconds = COALESCE($15, mail_settings.delay_send_seconds),
             draft_type = COALESCE($17, mail_settings.draft_type),
             text_direction = COALESCE($18, mail_settings.text_direction),
             font_face = COALESCE($19, mail_settings.font_face),
             font_size = COALESCE($20, mail_settings.font_size),
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
    .bind(request.attach_public_key)
    .bind(request.pgp_scheme.as_deref())
    .bind(request.confirm_link)
    .bind(request.page_size)
    .bind(request.spam_action.as_deref())
    .bind(request.remote_images.as_deref())
    .bind(request.delay_send_seconds)
    .bind(state.config.mail_default_delay_send_seconds)
    .bind(request.draft_type.as_deref())
    .bind(request.text_direction.as_deref())
    .bind(request.font_face.as_deref())
    .bind(request.font_size)
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
