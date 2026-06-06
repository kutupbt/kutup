//! OpenAPI document — replaces `swaggo/swag` (the `// @title …` annotations in
//! `backend/main.go`). Served at `/swagger` via `utoipa-swagger-ui`, mirroring the
//! Go `app.Get("/swagger/*", …)` route. Paths/schemas are registered here as each
//! handler slice lands; at the end (slice 8) the generated spec is diffed against
//! `backend/docs/swagger.yaml`.

use utoipa::openapi::security::{ApiKey, ApiKeyValue, SecurityScheme};
use utoipa::{Modify, OpenApi};

use crate::models;

/// The kutup API description — mirrors the `// @title/@version/...` block in `main.go`.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "Kutup API",
        version = "1.0.0",
        description = "Self-hosted, end-to-end encrypted file storage with federation. \
All file content and metadata are encrypted client-side; the server stores only ciphertext.",
        license(name = "AGPL-3.0-only", url = "https://www.gnu.org/licenses/agpl-3.0.html"),
    ),
    components(schemas(
        models::HealthResponse,
        models::ErrorResponse,
        models::MessageResponse,
        models::SettingsResponse,
        models::PreflightLoginResponse,
        models::PreflightRecoverResponse,
        models::RefreshResponse,
        models::MeResponse,
        models::OkResponse,
        models::TotpSetupResponse,
        models::TotpCodeRequest,
        models::UserLookupResponse,
        models::CollectionRow,
        models::CreateCollectionRequest,
        models::CreateCollectionResult,
        models::UpdateCollectionRequest,
        models::UpdateColorRequest,
        models::ShareCollectionRequest,
        models::ShareFederatedRequest,
        models::ShareFederatedResult,
        models::PubkeyResponse,
        models::FileRow,
        models::UploadResult,
        models::CreateShareRequest,
        models::CreateShareResult,
        models::PublicShareResponse,
        models::DownloadUrlResponse,
        models::FedInviteResponse,
        models::AddIncomingShareRequest,
        models::UserRow,
        models::CreateAdminUserRequest,
        models::UpdateAdminUserRequest,
        models::UpdateAdminSettingsRequest,
        models::StatsResponse,
    )),
    modifiers(&BearerAuthAddon),
)]
pub struct ApiDoc;

/// Registers the `BearerAuth` security scheme — mirrors the Go
/// `@securityDefinitions.apikey BearerAuth` / `@in header` / `@name Authorization`.
struct BearerAuthAddon;

impl Modify for BearerAuthAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "BearerAuth",
                SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("Authorization"))),
            );
        }
    }
}
