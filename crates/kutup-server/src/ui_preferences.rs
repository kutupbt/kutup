//! How the web apps look for an account: theme and language, the same in
//! every app and on every device (docs/roadmap.md, "Web · theme and language
//! follow the account"). Not secret, so stored as they are.

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::error::{AppError, AppResult};
use crate::handlers::trusted_uuid;
use crate::middleware::AuthUser;
use crate::AppState;

const THEMES: [&str; 3] = ["light", "dark", "system"];
const LANGUAGES: [&str; 2] = ["en", "tr"];

#[derive(Debug, Default, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UiPreferences {
    /// `light`, `dark` or `system`; null until the account chooses one.
    pub theme: Option<String>,
    /// `en` or `tr`; null until the account chooses one.
    pub language: Option<String>,
}

impl UiPreferences {
    /// Only the values the apps know; an unknown one is refused, not stored.
    fn validate(&self) -> AppResult<()> {
        if let Some(theme) = &self.theme {
            if !THEMES.contains(&theme.as_str()) {
                return Err(AppError::bad_request("theme is light, dark or system"));
            }
        }
        if let Some(language) = &self.language {
            if !LANGUAGES.contains(&language.as_str()) {
                return Err(AppError::bad_request("language is en or tr"));
            }
        }
        Ok(())
    }
}

/// `GET /api/account/ui-preferences` — this account's theme and language.
#[utoipa::path(
    get,
    path = "/api/account/ui-preferences",
    tag = "account",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "Theme and language, null where never chosen", body = UiPreferences))
)]
pub async fn get_ui_preferences(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<Json<UiPreferences>> {
    let user_id = trusted_uuid(&user.user_id)?;
    let row: Option<(Option<String>, Option<String>)> =
        sqlx::query_as("SELECT theme, language FROM user_ui_preferences WHERE user_id = $1")
            .bind(user_id)
            .fetch_optional(&state.pool)
            .await?;
    let (theme, language) = row.unwrap_or_default();
    Ok(Json(UiPreferences { theme, language }))
}

/// `PUT /api/account/ui-preferences` — set the theme and language; a null
/// leaves that one unchosen.
#[utoipa::path(
    put,
    path = "/api/account/ui-preferences",
    tag = "account",
    security(("BearerAuth" = [])),
    request_body = UiPreferences,
    responses(
        (status = 200, description = "Saved", body = UiPreferences),
        (status = 400, description = "An unknown theme or language"),
    )
)]
pub async fn put_ui_preferences(
    State(state): State<AppState>,
    user: AuthUser,
    Json(request): Json<UiPreferences>,
) -> AppResult<Json<UiPreferences>> {
    request.validate()?;
    let user_id = trusted_uuid(&user.user_id)?;
    sqlx::query(
        "INSERT INTO user_ui_preferences (user_id, theme, language, updated_at)
         VALUES ($1, $2, $3, now())
         ON CONFLICT (user_id) DO UPDATE SET
             theme = EXCLUDED.theme,
             language = EXCLUDED.language,
             updated_at = now()",
    )
    .bind(user_id)
    .bind(&request.theme)
    .bind(&request.language)
    .execute(&state.pool)
    .await?;
    Ok(Json(request))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prefs(theme: Option<&str>, language: Option<&str>) -> UiPreferences {
        UiPreferences {
            theme: theme.map(str::to_owned),
            language: language.map(str::to_owned),
        }
    }

    #[test]
    fn accepts_the_known_values_and_nothing_chosen() {
        for theme in THEMES {
            assert!(prefs(Some(theme), None).validate().is_ok());
        }
        for language in LANGUAGES {
            assert!(prefs(None, Some(language)).validate().is_ok());
        }
        assert!(prefs(None, None).validate().is_ok());
    }

    #[test]
    fn refuses_anything_else() {
        assert!(prefs(Some("blue"), None).validate().is_err());
        assert!(prefs(Some("Dark"), None).validate().is_err());
        assert!(prefs(None, Some("de")).validate().is_err());
        assert!(prefs(None, Some("tr-TR")).validate().is_err());
    }

    #[test]
    fn refuses_unknown_fields() {
        let parsed: Result<UiPreferences, _> =
            serde_json::from_str(r#"{"theme":"dark","language":"tr","font":"big"}"#);
        assert!(parsed.is_err());
    }
}
