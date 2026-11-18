# W7: the schema made once, before the wipe

Status: **approved** 2026-11-17 (main session; answers at the end). Group 1
(renames) landed 2026-11-17. Branch `wipe/w7` on `wipe/final` c4ca4ad0 (with the W3 one-loop
follow-up). Scope: docs/plans/wipe-unification.md W7, smart's architecture
note §5 (items 1–8) and smart's sweep (items 4, 6–11, 14), and the user's
direction (2026-11-17): every cosmetic or structural change that is only
cheap before the wipe. Main does the API surface (versions, paths, field
names, federation routes) after W7.

The inventory behind this note was taken from a dump of the current chain:
181 tables (178 in `public`, 3 in `account_keys`), 1438 columns.

## 0. How it is built

1. **Squash.** One baseline generated from the chain by
   `scripts/check-migration-baseline.sh` (fixed: each migration now runs in
   one transaction, as sqlx does), proven equal to the chain **at the squash
   commit** by dumping both and diffing. Nothing else changes in that
   commit; the later groups edit the baseline in place, so the proof holds
   for the squash commit only.
2. **Restructure the baseline in place.** Nothing has applied the new
   baseline yet (the wipe), so the later commits edit the one file rather
   than add migrations. Each commit changes the schema and every query that
   reads it, and is gated on its own.
3. **Order:**
   1. renames (§1);
   2. encoding (§2);
   3. casing and admin actions (§3);
   4. the account row, entitlements, events and settings (§4–§7);
   5. storage, counters, client types, purposes, labels and `mls` (§8–§12).
4. **Gates** after each commit: static, rust, web, live backup. After the
   last: the two-server gate, the browser specs that touch the tables, and a
   final dump compared with this note.

There are no `query!` macros, so the compiler checks no SQL. The live suites
are the check, and each rename commit runs them.

## 1. Names

**Rules.**
- A table is prefixed by the app that owns it: `drive_`, `mail_`,
  `chat_`, `calendar_`, `pass_`, `photos_`, `contacts`, `collab_`.
  Account-wide and server-wide tables take no app prefix.
- A local account is `<role>_account_id`. A remote account also has a
  sibling `<role>_server`; a local one never has.
- A column holding a server name is `<role>_server`. The federation
  transport tables keep `domain` / `origin` / `destination`: they name peers,
  not accounts.
- An actor is `<verb>_by_account_id`.
- Mail's account-or-group key is `mailbox_owner`.

### 1.1 Tables (the 23 that change; the other 158 keep their names)

| Old | New | Note |
|---|---|---|
| users | accounts | its sequence and `kutup_current_user()` follow: `kutup_current_account()` |
| devices | account_devices | account-level device identities (Drive, manifests, Chat) |
| device_tickets | account_device_tickets | |
| user_security_keys | account_security_keys | |
| user_setting_overrides | (gone: §5 entitlements) | |
| user_ui_preferences | account_ui_preferences | |
| user_map_preferences | account_map_preferences | Maps is a shared feature, not an app yet |
| files | drive_files | |
| collections | drive_collections | folders and albums |
| collection_shares | drive_collection_shares | |
| collection_key_epoch_history | drive_collection_key_epoch_history | |
| file_assets | drive_file_assets | |
| file_key_history | drive_file_key_history | |
| file_shares | drive_file_shares | |
| file_thumbnails | drive_file_thumbnails | |
| file_versions | drive_file_versions | |
| uploads | drive_uploads | |
| public_shares | drive_public_shares | |
| public_link_reports | drive_public_link_reports | |
| federated_incoming_shares, federated_incoming_file_shares | drive_federated_incoming_shares, drive_federated_incoming_file_shares | |
| federated_outgoing_shares, federated_outgoing_file_shares | drive_federated_outgoing_shares, drive_federated_outgoing_file_shares | |
| album_items | photos_album_items | Photos is its own app (main's answer 4) |
| file_update_log, file_sender_floors | collab_update_log, collab_sender_floors | the frame log serves notes and whiteboards too; "Office" is a product name |
| contact_emails | contacts_emails | `contacts` stays |
| calendar_user_settings | calendar_account_settings | the account's calendar defaults (the per-calendar sealed settings are records) |
| sealed_sender_generated_certificates | chat_sealed_sender_certificates | |
| live_location_streams | chat_live_location_streams | shared through conversations |

Index, constraint and sequence names are regenerated from the new names. The
code matches by name only `calendar_events_pkey` and `mail_groups_pkey`
(unchanged), and the `_unique_name` / `_unique_top_level_name` suffixes,
which are kept.

**To decide:** `organization_access_requests` has no reference in the server.
Drop it, or keep it for the consenting-member flow (organizations plan)? I'd
drop it and let the organizations work add it back with its handler.

### 1.2 Columns

- **`user_id` → `account_id`: 84 columns.** Every `user_id` is a local
  account; none is kept. `accounts.id` stays `id`; 113 foreign keys point
  at it.
- **Roles, 57 columns:**

| New name | Old columns |
|---|---|
| owner_account_id | calendars.owner_id; chat_call_links, drive_collections, drive_public_shares `.owner_user_id` |
| owner_server + owner_account_id | drive_federated_incoming_shares, drive_federated_incoming_file_shares: `owner_user_id` (remote) with `remote_domain` → `owner_server`; the `owner_account` text label is **dropped** (§1.3) |
| mailbox_owner | mail_messages.owner, mail_message_tombstones.owner, mail_change_floors.owner |
| sender_account_id | chat_sends.sender_user_id, federation_outbox.sender_user_id, mail_messages.sender_account |
| sender_server + sender_account_id + sender_device_id | collab_update_log and collab_sender_floors: `sender_domain` / `sender_account` / `sender_device` (`''` for local becomes this server's own name, so the key needs no NULL) |
| recipient_account_id | `.recipient_user_id` on chat_anonymous_send_ids, chat_mailbox, chat_media_federation_inbound_pending, chat_media_origin_delivery_operations, drive_collection_shares, drive_file_shares |
| recipient_server + recipient_account_id | drive_federated_outgoing_*: `recipient_domain` → `recipient_server`; `recipient_username` is **dropped** (§1.3) |
| sharer_account_id | `.sharer_user_id` on the four share tables |
| uploader_account_id | drive_files, drive_file_assets, drive_file_thumbnails |
| author_account_id | calendar_events.author_user_id, drive_file_versions.author_user_id |
| origin_account_id (+ origin_server) | chat_media_objects, chat_media_federation_pull_grants, chat_media_origin_delivery_operations `.origin_user_id`; `chat_media_objects.origin_domain` → `origin_server` |
| admin_account_id | account_security_events.admin_user_id, admin_audit_log.admin_user_id |
| target_account_id | admin_audit_log.target_user_id, auth_grants.target_user_id |
| `<verb>_by_account_id` | added_by (photos_album_items, mail_group_members), created_by (mail_groups, registration_codes), live locations' creator_user_id, resolved_by (feedback, drive_public_link_reports), blocked_by (mail_domain_blocks, drive_public_shares), published_by, revoked_by, granted_by, invited_by, accounts.legal_hold_by, mail_messages.sent_by |

Kept, because they aren't accounts: accounts.closing_by (who: user, admin
or restore), destruction_events.actor, opaque_login_states.ceiling_account (a
rate bucket), the `*_device_id`, `*_incarnation_id` and mail `address_id`
columns. The columns already named `account_id` / `*_account_id` stay.

### 1.3 Remote accounts by (server, account_id) only

- Nothing is keyed by a username any more, but labels remain:
  `recipient_username`, `owner_account` (`user@server`), and
  `remote_account_renames` keyed by `(domain, incarnation_id)`. That last one
  sits beside `remote_account_manifests` keyed by `(domain, account_id)`, so
  two permanent remote ids coexist.
- **Decision:**
  - `remote_account_renames` is re-keyed `(server, account_id)` and keeps
    `incarnation_id` as a column. It becomes the one place a remote account's
    current address lives.
  - The share tables drop their labels and join it for display. The
    rename-relabel code (`remote_renames.rs` apply_rows) goes.
- Every `incarnation_id` becomes bytea(32) (§2).
- **Built (group 4):** every rename statement signs the account id
  (`accountId`, label `kutup/account/rename/v2`: a self-statement binds the
  account id), so a chain is kept under the id it signs, never one its server
  gives beside it; an announce's routing `accountId` must equal it. A remote account first met (a share to or from it)
  gets a row without a chain (`sequence` 0, no authority or digest) from what
  its server says (`remote_renames::note_account`), before the share row,
  which has a foreign key to it; a chain later replaces that label. Another
  incarnation of the same account (an admin reset there) replaces the row by
  announce or a new meeting, never by a lookup's answer. Rows without a chain
  don't count against the per-domain cap and answer no lookup.

## 2. Encoding

API JSON stays base64 / hex; only storage changes.

- **Bytes are `bytea`.** That covers the ~55 base64-text columns (envelopes,
  keys, signatures, sealed names, Chat key material, mailbox content,
  certificates). Length CHECKs become `octet_length`.
- **Hashes and ids we mint are `bytea` with a fixed `octet_length`:**
  - the 28 `character(64)` columns, and the hex-text ones (incarnation ids,
    capability, name, content and epoch hashes, document and manifest hashes,
    key ids, digests): 32 bytes;
  - call-link room and participant ids: 16;
  - `account_records.record_id` and its tombstones: 32. Each scope's id
    form decides the text; this is the one I'd keep as text. Pins' id is
    `pins` and a Pass id is a UUID, so a bytea needs a per-scope mapping.
    **Decision: keep `record_id` text.**
- **UUIDs held as text are `uuid`:** `accounts.key_binding`,
  `chat_mailbox.send_id` / `chat_sends.send_id`, `drive_file_assets.asset_id`
  (if a UUID), `federation_outbox.idempotency_key` (if a UUID).
- **Kept as text:**
  - external formats: armored OpenPGP, iCal, PHC/bcrypt hashes, S3 and
    Stalwart ids;
  - OpenPGP fingerprints, hex as Proton shows them;
  - human text.
- **Absent is NULL; no `''` sentinels.**
  - `account_devices.name`, `accounts.recovery_key_verifier`, and the version
    ids (gone with §8).
  - The first-login account's keys (`master_key_envelope`,
    `account_authority_*`, `account_incarnation_id`, `drive_signing_public_key`,
    `public_key`) become nullable bytea, with one CHECK: all set once the
    account is set up (§4).
  - The `repeat('0',64)` "no manifest yet" default in Chat backups becomes
    NULL.
- `drive_public_shares.token` (the raw link token) is stored as its SHA-256.
  A side finding: the server needn't keep the token itself.

## 3. Casing and the admin log

- **Enum values are camelCase** (the JSON is camelCase): 14 snake lists and
  the kebab `server_generated_keys.purpose`. For example `end_to_end` →
  `endToEnd`, `zero_access` → `zeroAccess`, `operator_order` →
  `operatorOrder`, `crypto_shred` → `cryptoShred`.
- **Kept as spelled:**
  - client types (`web-drive`…: bound into local-state crypto vectors);
  - CSS font names, MIME subtypes, DNS tokens and selectors, BCP 47
    languages, `ltr` / `rtl`.
- **Settings keys are not enum values:** dotted namespaces with snake_case
  segments (§7).
- **Admin actions: `area.verb`**, two camelCase segments with the verb
  imperative. The full list is below. The 15 `username` payload keys are
  dropped: the account is `target_account_id`.
  - The activity page then names a deleted account "deleted account"
    rather than keeping its username in an append-only log. A username
    snapshot is personal data (A8).
  - **To decide** if you want the snapshot kept.
- A test enumerates every action and payload key (one table in Rust that
  `audit()` must name), so a rename can't slip in after the first row.
- The destruction-event reference strings follow (`user.delete` →
  `account.delete`, `account-closing` → `accountClosing`), as does the
  payload's `actorType` (`operator-command` → `operatorCommand`).
- The frontend's `activityText.ts` keys and `limitName` follow.

Actions, old → new:
- **account:** `admin.view` → `account.view`, `user.create` →
  `account.create`, `user.federation` → `account.setFederation`,
  `user.publicSharing` → `account.setPublicSharing`, `user.update` →
  `account.update`, `user.delete` → `account.delete`, `user.close` →
  `account.close`, `user.legalHold.set` / `.clear` →
  `account.setLegalHold` / `account.clearLegalHold`, `user.2fa_disable` →
  `account.disableTwoFactor`, `user.rotate_temp_password` →
  `account.rotateTempPassword`, `user.wipe` → `account.resetKeys`,
  `user.setting` → `account.setEntitlement`, `user.rate_limit` →
  `account.setRateLimit`.
- **settings and other admin areas:** `settings.update` (same),
  `settings.rate_limit` → `settings.setRateLimit`, `maps.settings.update` →
  `maps.updateSettings`, `legal.publish`, `mail.sending.update` →
  `mail.updateSending`, `mail.outside_sending.update` →
  `mail.updateOutsideSending`, `mail.domains.*` → `mailDomain.updateSettings`
  / `approve` / `deactivate` / `unblock` / `setOverrides`, `mail_group.*` →
  `mailGroup.create` / `update` / `updateMembers` / `delete` / `setKey`.
  Unchanged: `report.dismiss`, `share.remove`, `share.block`,
  `share.unblock`, `feedback.resolve`, `feedback.delete`.
  `registration_code.created` / `revoked` → `registrationCode.create` /
  `revoke`. `name.close` and `name.free` are unchanged.
- **federation:** `federation.updatePolicy`, `setRule`, `deleteRule`,
  `retryPeer`, `retryPeers`, `createIdentity`, `rotateIdentity`, `pinPeer`,
  `verifyPeer`, `repinPeer`, `advancePeer`, `quarantinePeer`,
  `createFeaturePolicy`, `rotateFeaturePolicy`.

## 4. The account row

- **Roles:** `is_admin` and `is_break_glass` become `role` (`member`,
  `admin`, `breakGlassAdmin`). An organization role stays on
  `organization_members`.
- **First login:** `is_first_login` becomes `keys_set_up_at timestamptz`
  (NULL: the account still has to set up its keys). One CHECK ties every
  key column to it:
  - `keys_set_up_at IS NULL OR` (envelopes, authority, incarnation, Drive
    signing key, `key_binding`, `drive_key_binding` all NOT NULL).
  - That is the "NOT NULL once set up" for `key_binding` and
    `drive_key_binding`.
- `public_key` → `drive_xwing_public_key`.
- `totp_enabled` is dropped (it is `totp_secret IS NOT NULL`).
- `is_active` (generated) is dropped. Its 77 readers read `state = 'active'`.
- **States:** as built (`active` | `suspended` + `suspended_reason` |
  `closing`). That is already smart's neutral `suspended` with a reason code;
  only the camelCase values change (§3).
- `identity_suite`: CHECK `= 2`, no default (PQ-only).
- `version_retention_days`: the choices become a setting
  (`drive.version_retention_choices`) checked in Rust.
- `storage_quota_bytes` goes to §5.
- The `deleting_*` claim columns stay: they are the deletion job's
  bookkeeping.

**As built (group 4):**
- `role` CHECK (`member`, `admin`, `breakGlassAdmin`), `member` by default;
  Rust `models::AccountRole`. The API keeps its booleans (`isAdmin`,
  `isProtected`), computed from it; a promotion never touches the
  break-glass administrator's role. `accounts_one_break_glass` is a unique
  index on `role = 'breakGlassAdmin'`.
- The key columns are nullable, NULL until set up (an administrator's
  account, a reset one). `accounts_keys_set_up` requires, once
  `keys_set_up_at` is set, both envelopes, the X-Wing, authority and Drive
  signing keys and `drive_key_binding` non-empty and the authority key id,
  incarnation id and `key_binding` present. `recovery_key_envelope` is in it:
  every setup path (sign-up, first sign-in) and the master-key rotation
  write one, and the recovery phrase is not optional. Authority key id and
  incarnation id are exactly 32 bytes when present. Sign-up sets
  `keys_set_up_at` with the keys; the first sign-in's setup sets it in the
  same UPDATE as the keys.
- `totp_enabled` went, but the authenticator's secret being set up (before
  its first code) moved to its own column, `totp_pending_secret_sealed`;
  `totp_secret_sealed IS NOT NULL` is "the authenticator app is on".
- Sharing to a local account that has not set up its keys is refused
  (`keysPendingUpgrade`) by `keys_set_up_at`, as it was by suite 1 before.
- `drive.version_retention_choices`: an admin setting outside the numeric
  registry (it is a list), stored as ascending comma-separated days, edited
  in Administration → Server settings → Drive (`driveVersionRetentionChoices`),
  checked by `PATCH /api/user/me`; `/api/user/me` gives the account its
  `versionRetentionChoices`. The column keeps only `> 0`.

## 5. Entitlements

`account_entitlements (account_id, key text, value bigint, source text,
updated_at)`, PK `(account_id, key)`; `source` is `admin` | `plan` |
`organization`.
- **It replaces:**
  - `user_setting_overrides`: the 24 per-account settings, the per-account
    rate limits and `mail.domains.addresses_per_account`;
  - `accounts.storage_quota_bytes` and its literal 10 GiB default. The site
    default stays the setting `account.default_storage_quota_bytes`;
  - the per-account switches `public_sharing` and `federation`, as keys
    `drive.public_sharing` and `server.federation` (0/1).
- The precedence (account > site > default) is today's `load_for`.
- Billing later only writes rows with `source = 'plan'`.
- `organization_setting_overrides` becomes `organization_entitlements`, the
  same shape for org scope.
- Usage counters (`storage_used_bytes`) are not entitlements.

**As built (group 4):**
- `crate::entitlements` reads and writes both tables (`Holder::Account` /
  `Holder::Organization`); every former reader of
  `account_setting_overrides`, `organization_setting_overrides` and the three
  account columns goes through it or the SQL below.
- `source` also takes `account` (account table only): the account holder's
  own federation switch (Settings → Privacy, the `federationAbroad` consent
  withdrawn) is neither an administrator's, a plan's nor an organization's.
- Quota: the key `account.storage_quota_bytes` (named finally now, like the
  two switches); `storage_pool::quota` resolves account > site
  `default_storage_quota_bytes` (key unchanged) > 10 GiB. An account without
  its own follows the site default as it changes (before, the default was
  copied in at creation). `POST /api/admin/users` writes one only for a
  quota given above 0 (the New user page sends 0 unless the field was
  edited); `PUT /api/admin/users/{id}` writes one and logs
  `account.setEntitlement` `{key, value, previous}`.
- `drive.public_sharing`: 0 off, 1 or none follows the site's switch; the
  API still says `on`/`off`. `server.federation`: written at sign-up and admin
  creation from `federation_default`, so a later change of the default leaves
  existing accounts as they are; none (the break-glass account) follows the
  default. `kutup_account_federates` reads it. The admin switches keep their
  own actions (`account.setFederation`, `account.setPublicSharing`).
- Values that are not whole numbers: none. The site's `public_sharing`
  (`on`/`off`/`signedIn`) stays a site setting; the account's is 0/1.

## 6. Event rows

- **Shape:** `admin_audit_log` and `account_security_events` share one column
  shape:
  - `id`, `kind`, `actor_kind` (`account` | `admin` | `job` | `peer`),
    `actor_account_id`, `subject_account_id`, `at`, `payload jsonb`, `count`;
  - `chain_version`, `previous_hash`, `row_hash`.
  - Security events' extra columns (acting session and client, old and new
    name, the sealed client) move into the payload. Their per-kind CHECKs
    move to the Rust kind table, which the enumerating test also covers.
- **They stay two tables** (plan A8: "two logs stay two"). The admin log is
  one chain. Security events are pruned per kind, so they keep
  `chain_version` = 0 and no hashes, and `row_hash` is NOT NULL only for the
  chained table, by a CHECK on `chain_version`.
- **The admin log's genesis** is `previous_hash` = 32 zero bytes, so
  `previous_hash` and `row_hash` are both NOT NULL.
- **`destruction_events` stays apart:** its own schema and dump, no account
  ids (HMAC subjects), and restore replay. Only its enum values follow §3.

## 7. Settings, namespaced

- **Keys are `<namespace>.<name>`.** Namespaces: `drive`, `mail`, `chat`,
  `pass`, `calendar`, `photos`, `account`, `server`. For example
  `chat_link_token_seconds` → `chat.link_token_seconds`, the retention ones →
  `server.retention.*`, `account_closing_days` → `account.closing_days`, and
  each records-count setting to its app (`pass.records.secrets`…). That is
  about 202 keys: 86 registry settings, 16 ad-hoc keys, 12 `mail_domains.*`
  and 88 rate limits.
- **Rate limits** go to `<app>.rate.<name>` by the app the spec belongs to.
- An unknown namespace in a stored row is kept and ignored, so a newer
  server's or the enterprise fork's keys survive an older binary.
- **The admin API's `field` names stay;** only keys change. Three places
  show keys and follow:
  - the registry listing;
  - `PUT /api/admin/users/{id}/limits/{key}` (the frontend reads keys from
    the registry);
  - the mail-domain settings page, which hard-codes `mail_domains.*`. It
    moves to the new keys, and its stale `mail_domains.per_account` is fixed.

## 8. Object storage: one key per revision

Bucket versioning becomes unnecessary, so a local-directory backend works.
- Drive revisions, assets, Chat media and backups, and mail objects already
  have one key per revision.
- **Thumbnails are the exception** (overwritten in place). They become
  `files/{file}/thumbnails/{variant}/{revision}`, and the old object is
  deleted after the commit.
- **What goes:**
  - the five version-id columns;
  - the `stored` and `version` kinds of `storage_pending_deletions`;
  - `put_object_versioned`, `get_stored`, `delete_stored`,
    `delete_object_version` and the version listing in `delete` /
    `delete_prefix`;
  - the legacy `original` / `versions/{id}` paths in comments, docs and
    the orphan sweep.
- **Drive's leftovers of the old model:**
  - `storage_path` columns (derived from the ids);
  - `original_pruned` and `original_key_generation`;
  - the always-NULL `drive_uploads.metadata_envelope` /
    `metadata_revision`.
  - `revision_content_envelope` becomes NOT NULL.
  - **To check while building:** `ciphertext_sha256` and `content_hash`
    may now be NOT NULL.

## 9. The squash checklist and leftovers

- **NOT VALID constraints:** the 8 become ordinary checks.
- **`blob_suite` / `suite`** are kept as the rows' format version, without a
  default.
- **No more `DEFAULT 1`** on format-version columns (`metadata_revision`,
  `current_doc_key_id`, `calendars.suite`, `drive_key_binding_epoch`,
  `master_key_generation`, `chain_version`): a writer names its version.
- **CHECK lists** are merged once in the baseline (grant purposes, event
  kinds, record purposes).
- **Repeated enum lists** become Postgres domains, or one Rust-owned list:
  - `('folder','album')`, `('inherit','allow','block')`, `('all','any')`,
    `('on','off')`;
  - the suspended reasons;
  - the client types (§10).

## 10. Rate counters and client types

- **Rate counters:** `chat_anonymous_rate_counters` and
  `chat_media_rate_counters` become one `rate_counters (scope, subject bytea,
  window_start, count, expires_at)` with namespaced scopes
  (`chat.anonymous.recipient`…). There is no CHECK on scope; the Rust enum is
  the list. One sweeper deletes expired rows: today nothing prunes them, a
  bug fixed here. The mail day and hour counters keep their own tables:
  they are per-account quotas shown to the account.
- **Federation outbox:** already one. `drive_federation_mutations` stays as
  Drive's request-id idempotency record. Folding it into `federation_inbound`
  changes the Drive federation protocol, which is not this branch's.
- **Client types:** one domain `client_type`, used by the three CHECKs. The 8
  `android-*` / `ios-*` values go: there is no Rust variant, and native apps
  come later with their own row.

## 11. Account-record purposes and scopes

- **Purposes are renumbered by owner, all below 40.** The third session holds
  40 and up.
  - account: 1 PasswordMasterKey, 2 RecoveryMasterKey, 3 MasterKeyKeyring,
    4 IdentityRoot, 5 ObjectIdKey, 6 AccountHead, 7 AccountLocalAnchor,
    8 RevisionSeen, 9 LocalChainPin;
  - Drive: 10 DriveRoot, 11 IdentityPins, 12 spare;
  - Chat: 13 ChatBackupRoot, 14 ChatProfileKeyWrap, 15 ChatGroupListEntry,
    16 ChatContactListEntry, 17 ChatAttachmentLedger, 18 JoinedMeeting,
    19 GroupPseudonymRoot, 20 CallLinkRoot, 21 ChatStoreKey, 22 spare;
  - Mail: 23 MailAddressPrivateKey, 24 MailName, 25 MailSearchStoreKey,
    26 spare;
  - Pass: 27 PassVaultSecret, 28 spare;
  - Calendar: 29 CalendarSettings, 30 spare;
  - Contacts: 31 ContactCard, 32 ContactGroup, 33 spare;
  - Photos: 34 PhotosLibrary, 35 spare;
  - Organizations: 36 OrganizationPrivateKey, 37 spare;
  - 38–39 spare.
- **What follows:**
  - the account roots' CHECK becomes `purpose IN (3,4,5,10,19,20)`;
  - hashed record ids change (the purpose is in the HMAC), which is fine
    with the wipe;
  - every vector that seals a record is regenerated (13 crypto files and
    Chat's `profile-key-wrap-v1`).
- **Scopes keep 1–9.** No gaps are possible below the third session's 10;
  regrouping them buys nothing.

## 12. Persisted names and labels

- **`MlsGroup`:** `ChatMediaConversationKindV1::MlsGroup = 2` becomes
  `Group = 2` (JSON `group`). The frontend's `'mls_group'` write follows, and
  `note_to_self` → `noteToSelf` with §3. The other `mls` leftovers are
  reserved numbers and negative tests; they stay.
- **Dead labels removed:** `ACCOUNT_MANIFEST_V1` (nothing reads
  manifest/v1), `DEVICE_REGISTRATION_V1`, `DEVICE_REVOCATION_V1` and
  `PASS_VAULT_SECRET_V1`, with their negative tests. That takes the
  registry from 169 to 165. Live labels are untouched.

## 13. Jurisdiction-neutral core (smart 8)

The core has no KVKK / 5651 references; the retention periods are already
settings. What remains:
- **Consent purposes:** `federation_abroad` becomes a neutral `federation`
  ("share data with other servers"). Whether consent is required is a setting
  (`server.federation.consent_required`), and the fork turns it on.
  `marketing` stays.
- **Periods from env or constants become settings:**
  - `TRASH_RETENTION_DAYS` → `drive.trash_retention_days`;
  - `CHAT_SEND_RETENTION_DAYS` → `chat.send_retention_days`;
  - the 30-day session lifetime → `account.session_ttl_days`;
  - the 90 known-client days → `account.known_client_days`.
- **The UI languages** come from the shipped locales, not a list in
  `ui_preferences.rs`.

## 14. Enterprise data (smart 1)

The core has no enterprise tables. **The rule:** the baseline holds only core
tables, and a fork's tables live in their own Postgres schema (`enterprise`)
with their own migrations table. The hook (a second sqlx migrator run on that
schema) is small, so it is built: an optional `ENTERPRISE_MIGRATIONS` path,
off by default, with one live test that migrates an empty extra set.

## Not in W7

- The API version and "client too old", API field and path renames, the
  name-keyed federation routes, a server instance id, client storage names
  (main, after W7).
- Folding the mail rate counters; folding `drive_federation_mutations`.

## Questions for approval

1. `organization_access_requests`: drop (proposed) or keep?
2. Admin log payloads: drop the `username` snapshot (proposed) or keep it?
3. `account_records.record_id` stays text (proposed)?
4. `drive_album_items` (proposed) or `photos_album_items`? **Answer:**
   `photos_album_items`; Photos is its own app.
5. Remote display addresses from `remote_account_renames` re-keyed by
   (server, account_id) (proposed), dropping the share tables' labels?

## Answers and where they land (main session, 2026-11-17)

1. `organization_access_requests` is dropped: in **group 4** (O3 adds what it
   needs after the wipe, as a normal migration).
2. Admin payloads carry ids only (no username snapshot): **group 3**.
3. `account_records.record_id` stays text.
4. `photos_album_items`: built in group 1.
5. `remote_account_renames` re-keyed by (server, account_id), and the share
   tables' `recipient_username` / `owner_account` labels dropped (§1.3):
   **group 4**, with the account rows. Group 1 did only the names.

From the review of group 1 (third session): the 22 index names that still
end in `_user` over `account_id` are renamed in **group 5**.
