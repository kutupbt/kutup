//! How the web apps look for an account: theme and language, the same in
//! every app and on every device (docs/roadmap.md, "Web · theme and language
//! follow the account"). Not secret, so stored as they are.

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::error::{AppError, AppResult};
use crate::handlers::trusted_uuid;
use crate::middleware::AuthAccount;
use crate::AppState;

const THEMES: [&str; 3] = ["light", "dark", "system"];
/// The languages the web apps ship: exactly the locale files of every
/// `frontend/**/locales` directory and the i18n package's
/// `SUPPORTED_LANGUAGES` (a test fails when they drift; the server image is
/// built without the frontend, so this list is checked, not generated). The
/// schema takes any language tag, so adding one is no migration.
pub const LANGUAGES: [&str; 2] = ["en", "tr"];

#[derive(Debug, Default, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UiPreferences {
    /// `light`, `dark` or `system`; null until the account chooses one.
    pub theme: Option<String>,
    /// One of the languages the apps ship ([`LANGUAGES`]); null until the
    /// account chooses one.
    pub language: Option<String>,
    /// Keyboard shortcuts in every app (Proton's one setting); null until
    /// chosen, which is on. A save that leaves it out keeps the stored one.
    #[serde(default)]
    pub shortcuts: Option<bool>,
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
                return Err(AppError::bad_request(format!(
                    "language is one of {}",
                    LANGUAGES.join(", ")
                )));
            }
        }
        Ok(())
    }
}

/// `GET /api/v1/account/ui-preferences` — this account's theme and language.
#[utoipa::path(
    get,
    path = "/api/v1/account/ui-preferences",
    tag = "account",
    security(("BearerAuth" = [])),
    responses((status = 200, description = "Theme and language, null where never chosen", body = UiPreferences))
)]
pub async fn get_ui_preferences(
    State(state): State<AppState>,
    user: AuthAccount,
) -> AppResult<Json<UiPreferences>> {
    let user_id = trusted_uuid(&user.account_id)?;
    let row: Option<(Option<String>, Option<String>, Option<bool>)> = sqlx::query_as(
        "SELECT theme, language, shortcuts FROM account_ui_preferences WHERE account_id = $1",
    )
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await?;
    let (theme, language, shortcuts) = row.unwrap_or_default();
    Ok(Json(UiPreferences {
        theme,
        language,
        shortcuts,
    }))
}

/// `PUT /api/v1/account/ui-preferences` — set the theme and language; a null
/// leaves that one unchosen.
#[utoipa::path(
    put,
    path = "/api/v1/account/ui-preferences",
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
    user: AuthAccount,
    Json(request): Json<UiPreferences>,
) -> AppResult<Json<UiPreferences>> {
    request.validate()?;
    let user_id = trusted_uuid(&user.account_id)?;
    sqlx::query_as::<_, (Option<bool>,)>(
        "INSERT INTO account_ui_preferences (account_id, theme, language, shortcuts, updated_at)
         VALUES ($1, $2, $3, $4, now())
         ON CONFLICT (account_id) DO UPDATE SET
             theme = EXCLUDED.theme,
             language = EXCLUDED.language,
             shortcuts = COALESCE(EXCLUDED.shortcuts, account_ui_preferences.shortcuts),
             updated_at = now()
         RETURNING shortcuts",
    )
    .bind(user_id)
    .bind(&request.theme)
    .bind(&request.language)
    .bind(request.shortcuts)
    .fetch_one(&state.pool)
    .await
    .map(|shortcuts: (Option<bool>,)| UiPreferences {
        shortcuts: shortcuts.0,
        ..request
    })
    .map(Json)
    .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prefs(theme: Option<&str>, language: Option<&str>) -> UiPreferences {
        UiPreferences {
            theme: theme.map(str::to_owned),
            language: language.map(str::to_owned),
            shortcuts: None,
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

    /// The languages are the shipped locales: every `locales` directory of
    /// the frontend holds one file per language and no other, and the i18n
    /// package lists the same.
    #[test]
    fn the_languages_are_the_shipped_locales() {
        let frontend = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../frontend"));
        let mut expected: Vec<String> = LANGUAGES.iter().map(|l| format!("{l}.json")).collect();
        expected.sort();
        fn walk(dir: &std::path::Path, found: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                let name = path.file_name().unwrap().to_string_lossy().into_owned();
                if !path.is_dir()
                    || name == "node_modules"
                    || name == "dist"
                    || name.starts_with('.')
                {
                    continue;
                }
                if name == "locales" {
                    found.push(path);
                } else {
                    walk(&path, found);
                }
            }
        }
        let mut dirs = Vec::new();
        walk(&frontend.join("apps"), &mut dirs);
        walk(&frontend.join("packages"), &mut dirs);
        assert!(
            dirs.len() > 1,
            "no locales found under {}",
            frontend.display()
        );
        for dir in dirs {
            let mut files: Vec<String> = std::fs::read_dir(&dir)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .filter(|name| name.ends_with(".json"))
                .collect();
            files.sort();
            assert_eq!(files, expected, "{}", dir.display());
        }
        let i18n = std::fs::read_to_string(frontend.join("packages/i18n/src/index.ts")).unwrap();
        let line = i18n
            .lines()
            .find(|line| line.starts_with("export const SUPPORTED_LANGUAGES"))
            .expect("SUPPORTED_LANGUAGES");
        let listed: Vec<&str> = line.split('\'').skip(1).step_by(2).collect();
        assert_eq!(listed, LANGUAGES);
    }

    #[test]
    fn refuses_unknown_fields() {
        let parsed: Result<UiPreferences, _> =
            serde_json::from_str(r#"{"theme":"dark","language":"tr","font":"big"}"#);
        assert!(parsed.is_err());
    }
}
