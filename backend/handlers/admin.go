package handlers

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/kutup/backend/services"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

var adminUsernameRegexp = regexp.MustCompile(`^[a-z0-9_-]{3,32}$`)

type AdminHandler struct {
	DB *pgxpool.Pool
	// StorageTotalBytes is the configured total storage capacity of this
	// instance (S3 bucket / volume size). 0 means "unknown" — the admin UI
	// hides the capacity readout. Sourced from STORAGE_TOTAL_BYTES env var
	// at startup; used as a fallback when the live SeaweedFS probe is
	// unavailable.
	StorageTotalBytes int64
	// StorageProbe queries the SeaweedFS layer for real capacity + usage.
	// nil when SEAWEEDFS_MASTER_URL is unset — GetStats then falls back to
	// StorageTotalBytes.
	StorageProbe *services.StorageProbe
	// BreakGlassAdminEmail is the protected break-glass admin's email
	// (from the ADMIN_ACCOUNT env var). This account can never be demoted,
	// disabled, or deleted. Empty when ADMIN_ACCOUNT is unset.
	BreakGlassAdminEmail string
}

// isBreakGlass reports whether the given email is the protected
// break-glass admin. Case-insensitive.
func (h *AdminHandler) isBreakGlass(email string) bool {
	return h.BreakGlassAdminEmail != "" && strings.EqualFold(email, h.BreakGlassAdminEmail)
}

// @Summary      List all users
// @Tags         Admin
// @Produce      json
// @Security     BearerAuth
// @Success      200  {array}   UserRow
// @Failure      401  {object}  ErrorResponse
// @Failure      403  {object}  ErrorResponse
// @Router       /admin/users [get]
func (h *AdminHandler) ListUsers(c *fiber.Ctx) error {
	rows, err := h.DB.Query(context.Background(), `
		SELECT id, email, COALESCE(username, ''), storage_quota_bytes, storage_used_bytes,
		       is_admin, is_active, totp_enabled, created_at
		FROM users
		ORDER BY created_at DESC
	`)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}
	defer rows.Close()

	type UserRow struct {
		ID                string    `json:"id"`
		Email             string    `json:"email"`
		Username          string    `json:"username"`
		StorageQuotaBytes int64     `json:"storageQuotaBytes"`
		StorageUsedBytes  int64     `json:"storageUsedBytes"`
		IsAdmin           bool      `json:"isAdmin"`
		IsActive          bool      `json:"isActive"`
		TOTPEnabled       bool      `json:"totpEnabled"`
		CreatedAt         time.Time `json:"createdAt"`
		// IsProtected marks the break-glass admin — the UI disables
		// demote/disable/delete for this user.
		IsProtected bool `json:"isProtected"`
	}

	var users []UserRow
	for rows.Next() {
		var u UserRow
		if err := rows.Scan(
			&u.ID, &u.Email, &u.Username, &u.StorageQuotaBytes, &u.StorageUsedBytes,
			&u.IsAdmin, &u.IsActive, &u.TOTPEnabled, &u.CreatedAt,
		); err != nil {
			continue
		}
		u.IsProtected = h.isBreakGlass(u.Email)
		users = append(users, u)
	}
	if users == nil {
		users = []UserRow{}
	}
	return c.JSON(users)
}

// @Summary      Create a user account (admin)
// @Tags         Admin
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      CreateAdminUserRequest  true  "User details"
// @Success      201   {object}  MessageResponse
// @Failure      400   {object}  ErrorResponse
// @Failure      401   {object}  ErrorResponse
// @Failure      403   {object}  ErrorResponse
// @Failure      409   {object}  ErrorResponse  "Email or username already taken"
// @Router       /admin/users [post]
func (h *AdminHandler) CreateUser(c *fiber.Ctx) error {
	var req struct {
		Email             string `json:"email"`
		Username          string `json:"username"`
		TempPassword      string `json:"tempPassword"`
		StorageQuotaBytes int64  `json:"storageQuotaBytes"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}
	if req.Email == "" || req.TempPassword == "" {
		return c.Status(400).JSON(fiber.Map{"error": "email and tempPassword required"})
	}
	if req.Username == "" {
		return c.Status(400).JSON(fiber.Map{"error": "username required"})
	}
	if !adminUsernameRegexp.MatchString(req.Username) {
		return c.Status(400).JSON(fiber.Map{"error": "invalid username: must be 3-32 chars, lowercase letters, numbers, _ and -"})
	}
	if req.StorageQuotaBytes == 0 {
		req.StorageQuotaBytes = 10 * 1024 * 1024 * 1024 // 10 GB default
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.TempPassword), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}

	_, err = h.DB.Exec(context.Background(), `
		INSERT INTO users (
			email, username, login_key_hash,
			encrypted_master_key, master_key_nonce,
			encrypted_recovery_key, recovery_key_nonce,
			encrypted_private_key, private_key_nonce,
			public_key, kdf_salt, login_key_salt,
			is_admin, is_first_login, storage_quota_bytes
		) VALUES ($1,$2,$3,'','','','','','','','','',false,true,$4)
	`, req.Email, req.Username, string(hash), req.StorageQuotaBytes)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique") {
			errMsg := err.Error()
			if strings.Contains(errMsg, "users_username_unique") {
				return c.Status(409).JSON(fiber.Map{"error": "username already taken"})
			}
			return c.Status(409).JSON(fiber.Map{"error": "email already registered"})
		}
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}

	return c.Status(201).JSON(fiber.Map{"message": "user created"})
}

// @Summary      Get server settings
// @Tags         Admin
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  SettingsResponse
// @Failure      401  {object}  ErrorResponse
// @Failure      403  {object}  ErrorResponse
// @Router       /admin/settings [get]
func (h *AdminHandler) GetSettings(c *fiber.Ctx) error {
	var val string
	h.DB.QueryRow(context.Background(), `SELECT value FROM site_settings WHERE key='registration_enabled'`).Scan(&val)
	return c.JSON(fiber.Map{"registrationEnabled": val != "false"})
}

// @Summary      Update server settings
// @Tags         Admin
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      UpdateAdminSettingsRequest  true  "Settings"
// @Success      200   {object}  SettingsResponse
// @Failure      400   {object}  ErrorResponse
// @Failure      401   {object}  ErrorResponse
// @Failure      403   {object}  ErrorResponse
// @Router       /admin/settings [put]
func (h *AdminHandler) UpdateSettings(c *fiber.Ctx) error {
	var req struct {
		RegistrationEnabled bool `json:"registrationEnabled"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}

	val := "true"
	if !req.RegistrationEnabled {
		val = "false"
	}

	_, err := h.DB.Exec(context.Background(), `
		INSERT INTO site_settings (key, value) VALUES ('registration_enabled', $1)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
	`, val)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}

	return c.JSON(fiber.Map{"registrationEnabled": req.RegistrationEnabled})
}

// @Summary      Update a user (quota, active, admin flag)
// @Tags         Admin
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id    path      string                 true  "User UUID"
// @Param        body  body      UpdateAdminUserRequest  true  "Fields to update (all optional)"
// @Success      200   {object}  MessageResponse
// @Failure      400   {object}  ErrorResponse
// @Failure      401   {object}  ErrorResponse
// @Failure      403   {object}  ErrorResponse
// @Router       /admin/users/{id} [put]
func (h *AdminHandler) UpdateUser(c *fiber.Ctx) error {
	targetID := c.Params("id")

	var req struct {
		StorageQuotaBytes *int64 `json:"storageQuotaBytes"`
		IsActive          *bool  `json:"isActive"`
		IsAdmin           *bool  `json:"isAdmin"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}

	ctx := context.Background()

	// Load the target's current state for the break-glass + last-admin guards.
	var targetEmail string
	var targetIsAdmin, targetIsActive bool
	if err := h.DB.QueryRow(ctx,
		`SELECT email, is_admin, is_active FROM users WHERE id = $1`, targetID,
	).Scan(&targetEmail, &targetIsAdmin, &targetIsActive); err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "not found"})
	}

	wantsDemote := req.IsAdmin != nil && !*req.IsAdmin
	wantsDisable := req.IsActive != nil && !*req.IsActive

	// Break-glass admin is immutable: never demote, disable, or delete it.
	// This guarantees the server maintainer always has a working admin.
	if h.isBreakGlass(targetEmail) && (wantsDemote || wantsDisable) {
		return c.Status(403).JSON(fiber.Map{"error": "break-glass admin is protected"})
	}

	// Last-admin guard (backstop for when no break-glass admin is configured):
	// don't let a demote/disable leave zero usable admins.
	if (wantsDemote || wantsDisable) && targetIsAdmin && targetIsActive {
		var otherUsableAdmins int
		h.DB.QueryRow(ctx,
			`SELECT COUNT(*) FROM users WHERE is_admin AND is_active AND id != $1`,
			targetID,
		).Scan(&otherUsableAdmins)
		if otherUsableAdmins == 0 {
			return c.Status(400).JSON(fiber.Map{"error": "cannot remove the last admin"})
		}
	}

	// NOTE(audit-log): admin promotion/demotion + account disable should be
	// recorded once the audit-log endpoint lands (see docs/roadmap.md).
	// NOTE: isAdmin is baked into the JWT access-token claims, so a
	// promotion/demotion takes full effect on the target's next token
	// refresh (access tokens are short-lived).
	if req.StorageQuotaBytes != nil {
		if _, err := h.DB.Exec(ctx,
			`UPDATE users SET storage_quota_bytes = $1 WHERE id = $2`,
			*req.StorageQuotaBytes, targetID); err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "internal error"})
		}
	}
	if req.IsActive != nil {
		if _, err := h.DB.Exec(ctx,
			`UPDATE users SET is_active = $1 WHERE id = $2`,
			*req.IsActive, targetID); err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "internal error"})
		}
	}
	if req.IsAdmin != nil {
		if _, err := h.DB.Exec(ctx,
			`UPDATE users SET is_admin = $1 WHERE id = $2`,
			*req.IsAdmin, targetID); err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "internal error"})
		}
	}

	return c.JSON(fiber.Map{"message": "updated"})
}

// @Summary      Delete a user and all their data
// @Tags         Admin
// @Security     BearerAuth
// @Param        id  path  string  true  "User UUID"
// @Success      204
// @Failure      401  {object}  ErrorResponse
// @Failure      403  {object}  ErrorResponse
// @Failure      404  {object}  ErrorResponse
// @Router       /admin/users/{id} [delete]
func (h *AdminHandler) DeleteUser(c *fiber.Ctx) error {
	targetID := c.Params("id")
	ctx := context.Background()

	// Break-glass admin can never be deleted.
	var targetEmail string
	if err := h.DB.QueryRow(ctx,
		`SELECT email FROM users WHERE id = $1`, targetID,
	).Scan(&targetEmail); err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "not found"})
	}
	if h.isBreakGlass(targetEmail) {
		return c.Status(403).JSON(fiber.Map{"error": "break-glass admin is protected"})
	}

	result, err := h.DB.Exec(ctx, `DELETE FROM users WHERE id = $1`, targetID)
	if err != nil || result.RowsAffected() == 0 {
		return c.Status(404).JSON(fiber.Map{"error": "not found"})
	}

	return c.SendStatus(204)
}

// @Summary      Force-disable a user's two-factor authentication
// @Description  Admin override for users locked out of their authenticator.
// @Description  Clears the TOTP secret; the account becomes password-only
// @Description  until the user re-enables 2FA from their Security page.
// @Tags         Admin
// @Produce      json
// @Security     BearerAuth
// @Param        id  path  string  true  "User UUID"
// @Success      200  {object}  MessageResponse
// @Failure      401  {object}  ErrorResponse
// @Failure      403  {object}  ErrorResponse
// @Failure      404  {object}  ErrorResponse
// @Router       /admin/users/{id}/2fa [delete]
func (h *AdminHandler) ForceDisable2FA(c *fiber.Ctx) error {
	targetID := c.Params("id")

	// Mirrors auth.DisableTOTP, minus the TOTP-code challenge — the caller
	// is already authenticated and admin-gated. Allowed on the break-glass
	// admin too: it's a recovery aid and can't lock anyone out.
	// NOTE(audit-log): record this once the audit-log endpoint lands.
	result, err := h.DB.Exec(context.Background(),
		`UPDATE users SET totp_enabled = false, totp_secret = NULL WHERE id = $1`,
		targetID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}
	if result.RowsAffected() == 0 {
		return c.Status(404).JSON(fiber.Map{"error": "not found"})
	}
	return c.JSON(fiber.Map{"message": "2fa disabled"})
}

// @Summary      Get aggregate server statistics
// @Tags         Admin
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  StatsResponse
// @Failure      401  {object}  ErrorResponse
// @Failure      403  {object}  ErrorResponse
// @Router       /admin/stats [get]
func (h *AdminHandler) GetStats(c *fiber.Ctx) error {
	var stats struct {
		TotalUsers       int64 `json:"totalUsers"`
		ActiveUsers      int64 `json:"activeUsers"`
		TotalFiles       int64 `json:"totalFiles"`
		TotalStorageUsed int64 `json:"totalStorageUsedBytes"` // DB sum — logical per-account usage
		TotalCollections int64 `json:"totalCollections"`
		// StorageTotalBytes is the storage backend's real total capacity.
		// Resolved from the live SeaweedFS probe; falls back to the
		// STORAGE_TOTAL_BYTES env var, then 0 ("unknown").
		StorageTotalBytes int64 `json:"storageTotalBytes"`
		// StorageBackendUsedBytes is the storage backend's real on-disk
		// usage (from the SeaweedFS probe). 0 when no probe is available.
		StorageBackendUsedBytes int64 `json:"storageBackendUsedBytes"`
	}

	ctx := context.Background()
	h.DB.QueryRow(ctx, `SELECT COUNT(*) FROM users`).Scan(&stats.TotalUsers)
	h.DB.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE is_active = true`).Scan(&stats.ActiveUsers)
	h.DB.QueryRow(ctx, `SELECT COUNT(*) FROM files`).Scan(&stats.TotalFiles)
	h.DB.QueryRow(ctx, `SELECT COALESCE(SUM(storage_used_bytes),0) FROM users`).Scan(&stats.TotalStorageUsed)
	h.DB.QueryRow(ctx, `SELECT COUNT(*) FROM collections`).Scan(&stats.TotalCollections)

	// Storage capacity: prefer the live SeaweedFS probe; fall back to the
	// configured env var.
	stats.StorageTotalBytes = h.StorageTotalBytes
	if h.StorageProbe != nil {
		if probed, ok := h.StorageProbe.Probe(ctx); ok {
			stats.StorageTotalBytes = probed.TotalBytes
			stats.StorageBackendUsedBytes = probed.UsedBytes
		}
	}

	return c.JSON(stats)
}
