//! OpenAPI document — replaces `swaggo/swag` (the `// @title …` annotations in
//! `backend/main.go`). The raw spec is served at `GET /api-docs/openapi.json`; the
//! interactive Swagger UI is still deferred (see `docs/roadmap.md`). Every HTTP
//! operation from `main.rs::build_router` is registered in `paths(...)` below —
//! the test at the bottom cross-checks the operation count + key paths.

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
    paths(
        // --- health ---
        crate::health,
        // --- auth + user ---
        crate::handlers::auth::get_public_settings,
        crate::handlers::auth::register,
        crate::handlers::auth::get_login_preflight,
        crate::handlers::auth::login,
        crate::handlers::auth::login_two_fa,
        crate::handlers::auth::get_recovery_preflight,
        crate::handlers::auth::recover,
        crate::handlers::auth::refresh,
        crate::handlers::auth::complete_setup,
        crate::handlers::auth::get_me,
        crate::handlers::auth::update_me,
        crate::handlers::auth::setup_totp,
        crate::handlers::auth::verify_totp,
        crate::handlers::auth::disable_totp,
        crate::handlers::auth::get_user_by_email,
        // --- collections ---
        crate::handlers::collections::list_collections,
        crate::handlers::collections::create_collection,
        crate::handlers::collections::fetch_remote_pubkey,
        crate::handlers::collections::get_collection,
        crate::handlers::collections::update_collection,
        crate::handlers::collections::delete_collection,
        crate::handlers::collections::update_collection_color,
        crate::handlers::collections::share_collection,
        crate::handlers::collections::share_federated,
        // --- devices ---
        crate::handlers::devices::register,
        crate::handlers::devices::list,
        crate::handlers::devices::revoke,
        // --- tus resumable uploads ---
        crate::handlers::tus::create,
        crate::handlers::tus::patch,
        crate::handlers::tus::head,
        crate::handlers::tus::delete,
        // --- files ---
        crate::handlers::files::list_files,
        crate::handlers::files::upload,
        crate::handlers::files::download,
        crate::handlers::files::update_metadata,
        crate::handlers::files::delete,
        crate::handlers::files::claim_seed,
        // --- trash ---
        crate::handlers::trash::list,
        crate::handlers::trash::empty,
        crate::handlers::trash::destroy,
        crate::handlers::trash::restore,
        // --- file versions ---
        crate::handlers::file_versions::list,
        crate::handlers::file_versions::record,
        crate::handlers::file_versions::upload_snapshot_blob,
        crate::handlers::file_versions::download,
        crate::handlers::file_versions::patch,
        // --- file assets ---
        crate::handlers::file_assets::upload,
        crate::handlers::file_assets::download,
        // --- collab WebSocket ---
        crate::handlers::collab::ws,
        // --- public shares ---
        crate::handlers::shares::create_public_share,
        crate::handlers::shares::get_public_share,
        crate::handlers::shares::list_public_share_files,
        crate::handlers::shares::download_public_share_file,
        // --- federation (public, token-capability) ---
        crate::handlers::federation::get_user_by_username,
        crate::handlers::federation::get_invite,
        crate::handlers::federation::list_share_files,
        crate::handlers::federation::upload_share_file,
        crate::handlers::federation::download_share_file,
        crate::handlers::federation::delete_share_file,
        // --- federation proxy (authenticated) ---
        crate::handlers::fedproxy::add_incoming_share,
        crate::handlers::fedproxy::list_incoming_shares,
        crate::handlers::fedproxy::remove_incoming_share,
        crate::handlers::fedproxy::proxy_list_files,
        crate::handlers::fedproxy::proxy_download,
        crate::handlers::fedproxy::proxy_upload,
        crate::handlers::fedproxy::proxy_delete,
        // --- admin ---
        crate::handlers::admin::list_users,
        crate::handlers::admin::create_user,
        crate::handlers::admin::update_user,
        crate::handlers::admin::delete_user,
        crate::handlers::admin::force_disable_2fa,
        crate::handlers::admin::rotate_temp_password,
        crate::handlers::admin::wipe_user,
        crate::handlers::admin::get_stats,
        crate::handlers::admin::activity,
        crate::handlers::admin::get_settings,
        crate::handlers::admin::update_settings,
        // --- chat (E2EE messaging — phase 2 of docs/research/11-federated-chat.md) ---
        crate::handlers::chat::register_device,
        crate::handlers::chat::list_devices,
        crate::handlers::chat::revoke_device,
        crate::handlers::chat::replenish_keys,
        crate::handlers::chat::prekey_count,
        crate::handlers::chat::get_user_bundles,
        crate::handlers::chat::send_messages,
        crate::handlers::chat::drain_mailbox,
        crate::handlers::chat::ack_messages,
        crate::handlers::chat::ws,
    ),
    components(schemas(
        kutup_chat_proto::SuiteId,
        kutup_chat_proto::EnvelopeType,
        kutup_chat_proto::EcPreKey,
        kutup_chat_proto::KemPreKey,
        kutup_chat_proto::RegisterChatDeviceRequest,
        kutup_chat_proto::RegisterChatDeviceResponse,
        kutup_chat_proto::ReplenishKeysRequest,
        kutup_chat_proto::PreKeyCountResponse,
        kutup_chat_proto::DevicePreKeyBundle,
        kutup_chat_proto::UserPreKeyBundlesResponse,
        kutup_chat_proto::OutgoingEnvelope,
        kutup_chat_proto::SendMessagesRequest,
        kutup_chat_proto::DeviceListMismatch,
        kutup_chat_proto::DeliveredEnvelope,
        kutup_chat_proto::MailboxPage,
        kutup_chat_proto::AckRequest,
        kutup_chat_proto::ChatWsServerMessage,
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
        models::TrashFolderRow,
        models::TrashFileRow,
        models::TrashResponse,
        models::CreateShareRequest,
        models::CreateShareResult,
        models::PublicShareResponse,
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

#[cfg(test)]
mod tests {
    use utoipa::OpenApi;

    use super::ApiDoc;

    /// Every HTTP operation registered in `build_router` (74 router entries → 78
    /// method+path pairs, counting each method on a multi-method route). Keep in sync
    /// with `paths(...)` above when routes change.
    const EXPECTED_OPERATIONS: usize = 88;

    #[test]
    fn spec_lists_every_router_operation() {
        let spec = serde_json::to_value(ApiDoc::openapi()).expect("spec serializes");
        let paths = spec["paths"].as_object().expect("paths object");

        const METHODS: [&str; 8] = [
            "get", "put", "post", "delete", "options", "head", "patch", "trace",
        ];
        let operations: usize = paths
            .values()
            .map(|item| {
                item.as_object()
                    .expect("path item object")
                    .keys()
                    .filter(|k| METHODS.contains(&k.as_str()))
                    .count()
            })
            .sum();
        assert!(
            operations >= EXPECTED_OPERATIONS,
            "spec lists {operations} operations, expected at least {EXPECTED_OPERATIONS} — \
             did a handler lose its #[utoipa::path] registration?"
        );

        // Spot-check key paths (one per route group).
        for path in [
            "/api/health",
            "/api/auth/login",
            "/api/collections/{id}/files",
            "/api/devices",
            "/api/uploads/{id}",
            "/api/files/{id}",
            "/api/trash",
            "/api/files/{fileId}/versions/{vid}",
            "/api/files/{fileId}/assets/{assetId}",
            "/api/files/{fileId}/collab/ws",
            "/api/share/{token}/download/{fileId}",
            "/api/fed/shares/{token}/files",
            "/api/fed-proxy/{shareId}/upload",
            "/api/admin/activity",
            "/api/admin/users/{id}/rotate-temp-password",
            "/api/admin/users/{id}/wipe",
            "/api/chat/users/{username}/keys",
            "/api/chat/messages/ack",
            "/api/chat/ws",
        ] {
            assert!(paths.contains_key(path), "spec is missing path {path}");
        }
    }
}
