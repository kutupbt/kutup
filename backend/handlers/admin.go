package handlers

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

var adminUsernameRegexp = regexp.MustCompile(`^[a-z0-9_-]{3,32}$`)

type AdminHandler struct {
	DB *pgxpool.Pool
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

	result, err := h.DB.Exec(context.Background(),
		`DELETE FROM users WHERE id = $1`, targetID)
	if err != nil || result.RowsAffected() == 0 {
		return c.Status(404).JSON(fiber.Map{"error": "not found"})
	}

	return c.SendStatus(204)
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
		TotalStorageUsed int64 `json:"totalStorageUsedBytes"`
		TotalCollections int64 `json:"totalCollections"`
	}

	h.DB.QueryRow(context.Background(), `SELECT COUNT(*) FROM users`).Scan(&stats.TotalUsers)
	h.DB.QueryRow(context.Background(), `SELECT COUNT(*) FROM users WHERE is_active = true`).Scan(&stats.ActiveUsers)
	h.DB.QueryRow(context.Background(), `SELECT COUNT(*) FROM files`).Scan(&stats.TotalFiles)
	h.DB.QueryRow(context.Background(), `SELECT COALESCE(SUM(storage_used_bytes),0) FROM users`).Scan(&stats.TotalStorageUsed)
	h.DB.QueryRow(context.Background(), `SELECT COUNT(*) FROM collections`).Scan(&stats.TotalCollections)

	return c.JSON(stats)
}
