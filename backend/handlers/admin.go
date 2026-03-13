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

func (h *AdminHandler) GetSettings(c *fiber.Ctx) error {
	var val string
	h.DB.QueryRow(context.Background(), `SELECT value FROM site_settings WHERE key='registration_enabled'`).Scan(&val)
	return c.JSON(fiber.Map{"registrationEnabled": val != "false"})
}

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

	if req.StorageQuotaBytes != nil {
		h.DB.Exec(context.Background(),
			`UPDATE users SET storage_quota_bytes = $1 WHERE id = $2`,
			*req.StorageQuotaBytes, targetID)
	}
	if req.IsActive != nil {
		h.DB.Exec(context.Background(),
			`UPDATE users SET is_active = $1 WHERE id = $2`,
			*req.IsActive, targetID)
	}
	if req.IsAdmin != nil {
		h.DB.Exec(context.Background(),
			`UPDATE users SET is_admin = $1 WHERE id = $2`,
			*req.IsAdmin, targetID)
	}

	return c.JSON(fiber.Map{"message": "updated"})
}

func (h *AdminHandler) DeleteUser(c *fiber.Ctx) error {
	targetID := c.Params("id")

	result, err := h.DB.Exec(context.Background(),
		`DELETE FROM users WHERE id = $1`, targetID)
	if err != nil || result.RowsAffected() == 0 {
		return c.Status(404).JSON(fiber.Map{"error": "not found"})
	}

	return c.SendStatus(204)
}

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
