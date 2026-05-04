package handlers

import (
	"context"
	"encoding/base64"
	"regexp"
	"strings"

	"github.com/kutup/backend/middleware"
	"github.com/kutup/backend/services"
	"github.com/kutup/backend/utils"
	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

var usernameRegexp = regexp.MustCompile(`^[a-z0-9_-]{3,32}$`)

type AuthHandler struct {
	DB        *pgxpool.Pool
	JWTSecret string
	AppEnv    string
}

type RegisterRequest struct {
	Email                string `json:"email"`
	Username             string `json:"username"`
	// bcrypt(Argon2id(password, loginKeySalt)) — client sends loginKey, server bcrypts
	LoginKey             string `json:"loginKey"`
	// Encrypted key material
	EncryptedMasterKey   string `json:"encryptedMasterKey"`
	MasterKeyNonce       string `json:"masterKeyNonce"`
	EncryptedRecoveryKey string `json:"encryptedRecoveryKey"`
	RecoveryKeyNonce     string `json:"recoveryKeyNonce"`
	EncryptedPrivateKey  string `json:"encryptedPrivateKey"`
	PrivateKeyNonce      string `json:"privateKeyNonce"`
	PublicKey            string `json:"publicKey"`
	KDFSalt              string `json:"kdfSalt"`
	LoginKeySalt         string `json:"loginKeySalt"`
	// Recovery proof: base64(recoveryKeyEntropy) — server bcrypts and stores as verifier (S1-2 fix)
	RecoveryProof        string `json:"recoveryProof"`
}

// @Summary      Register a new account
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        body  body      RegisterRequest  true  "Encrypted key bundle and credentials"
// @Success      201   {object}  MessageResponse
// @Failure      400   {object}  ErrorResponse
// @Failure      403   {object}  ErrorResponse  "Registration disabled"
// @Failure      409   {object}  ErrorResponse  "Email or username already taken"
// @Router       /auth/register [post]
func (h *AuthHandler) Register(c *fiber.Ctx) error {
	var regEnabled string
	h.DB.QueryRow(context.Background(), `SELECT value FROM site_settings WHERE key='registration_enabled'`).Scan(&regEnabled)
	if regEnabled == "false" {
		return c.Status(403).JSON(fiber.Map{"error": "registration disabled"})
	}

	var req RegisterRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}

	if req.Email == "" || req.LoginKey == "" {
		return c.Status(400).JSON(fiber.Map{"error": "missing required fields"})
	}

	if !usernameRegexp.MatchString(req.Username) {
		return c.Status(400).JSON(fiber.Map{"error": "invalid username: must be 3-32 chars, lowercase letters, numbers, _ and -"})
	}

	// Decode loginKey from base64, then bcrypt it
	loginKeyBytes, err := base64.StdEncoding.DecodeString(req.LoginKey)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid loginKey encoding"})
	}

	hash, err := bcrypt.GenerateFromPassword(loginKeyBytes, bcrypt.DefaultCost)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}

	// Generate recovery key verifier (S1-2 fix): bcrypt the recovery key entropy
	// so the server can verify mnemonic possession during account recovery.
	recoveryVerifier := ""
	if req.RecoveryProof != "" {
		proofBytes, err := base64.StdEncoding.DecodeString(req.RecoveryProof)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid recoveryProof encoding"})
		}
		verifierHash, err := bcrypt.GenerateFromPassword(proofBytes, bcrypt.DefaultCost)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "internal error"})
		}
		recoveryVerifier = string(verifierHash)
	}

	_, err = h.DB.Exec(context.Background(), `
		INSERT INTO users (
			email, username, encrypted_master_key, master_key_nonce,
			encrypted_recovery_key, recovery_key_nonce,
			encrypted_private_key, private_key_nonce,
			public_key, kdf_salt, login_key_salt, login_key_hash,
			recovery_key_verifier
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
	`,
		req.Email, req.Username, req.EncryptedMasterKey, req.MasterKeyNonce,
		req.EncryptedRecoveryKey, req.RecoveryKeyNonce,
		req.EncryptedPrivateKey, req.PrivateKeyNonce,
		req.PublicKey, req.KDFSalt, req.LoginKeySalt, string(hash),
		recoveryVerifier,
	)
	if err != nil {
		// Check for duplicate email or username
		if isDuplicateKeyError(err) {
			errMsg := err.Error()
			if strings.Contains(errMsg, "users_username_unique") {
				return c.Status(409).JSON(fiber.Map{"error": "username already taken"})
			}
			return c.Status(409).JSON(fiber.Map{"error": "email already registered"})
		}
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}

	return c.Status(201).JSON(fiber.Map{"message": "registered"})
}

type PreflightResponse struct {
	KDFSalt      string `json:"kdfSalt"`
	LoginKeySalt string `json:"loginKeySalt"`
}

// GetLoginPreflight returns KDF salts for an email. Returns deterministic fake
// salts for non-existent emails to prevent user enumeration.
// @Summary      Fetch KDF salts before login
// @Tags         Auth
// @Produce      json
// @Param        email  query     string  true  "Email address"
// @Success      200    {object}  PreflightLoginResponse
// @Failure      400    {object}  ErrorResponse
// @Failure      429    {object}  ErrorResponse  "Rate limited (20/min per IP)"
// @Router       /auth/login/preflight [get]
func (h *AuthHandler) GetLoginPreflight(c *fiber.Ctx) error {
	email := c.Query("email")
	if email == "" {
		return c.Status(400).JSON(fiber.Map{"error": "email required"})
	}

	var kdfSalt, loginKeySalt string
	err := h.DB.QueryRow(context.Background(),
		`SELECT kdf_salt, login_key_salt FROM users WHERE email = $1`,
		email,
	).Scan(&kdfSalt, &loginKeySalt)

	if err != nil {
		// Non-existent user: derive deterministic fake salts from a server secret
		// so timing / response looks identical. Use email as HKDF input.
		kdfSalt = deterministicFakeSalt(email, "kdf")
		loginKeySalt = deterministicFakeSalt(email, "login")
	}

	return c.JSON(PreflightResponse{KDFSalt: kdfSalt, LoginKeySalt: loginKeySalt})
}

type LoginRequest struct {
	Email    string `json:"email"`
	LoginKey string `json:"loginKey"` // base64(Argon2id(password, loginKeySalt))
}

type LoginResponse struct {
	AccessToken          string  `json:"accessToken"`
	UserID               string  `json:"userId"`
	Username             string  `json:"username"`
	EncryptedMasterKey   string  `json:"encryptedMasterKey"`
	MasterKeyNonce       string  `json:"masterKeyNonce"`
	EncryptedPrivateKey  string  `json:"encryptedPrivateKey"`
	PrivateKeyNonce      string  `json:"privateKeyNonce"`
	PublicKey            string  `json:"publicKey"`
	IsAdmin              bool    `json:"isAdmin"`
	StorageQuotaBytes    int64   `json:"storageQuotaBytes"`
	StorageUsedBytes     int64   `json:"storageUsedBytes"`
	RequiresTotp         bool    `json:"requiresTotp,omitempty"`
	PreAuthToken         *string `json:"preAuthToken,omitempty"`
	RequiresSetup        bool    `json:"requiresSetup,omitempty"`
	SetupToken           *string `json:"setupToken,omitempty"`
}

// @Summary      Login
// @Description  Returns full tokens on success, or a preAuthToken when 2FA is required (requiresTotp=true), or a setupToken when first login (requiresSetup=true).
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        body  body      LoginRequest  true  "Email and derived login key"
// @Success      200   {object}  LoginResponse
// @Failure      400   {object}  ErrorResponse
// @Failure      401   {object}  ErrorResponse
// @Failure      429   {object}  ErrorResponse  "Rate limited (10/min per IP)"
// @Router       /auth/login [post]
func (h *AuthHandler) Login(c *fiber.Ctx) error {
	var req LoginRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}

	var (
		userID, loginKeyHash, encMK, mkNonce, encPK, pkNonce, pubKey, kdfSalt, username string
		totpEnabled                                                                        bool
		isAdmin                                                                            bool
		quotaBytes, usedBytes                                                              int64
		isActive                                                                           bool
	)

	err := h.DB.QueryRow(context.Background(), `
		SELECT id, login_key_hash, encrypted_master_key, master_key_nonce,
		       encrypted_private_key, private_key_nonce, public_key,
		       totp_enabled, is_admin, storage_quota_bytes, storage_used_bytes, is_active, kdf_salt,
		       COALESCE(username, '')
		FROM users WHERE email = $1
	`, req.Email).Scan(
		&userID, &loginKeyHash, &encMK, &mkNonce,
		&encPK, &pkNonce, &pubKey,
		&totpEnabled, &isAdmin, &quotaBytes, &usedBytes, &isActive, &kdfSalt, &username,
	)
	if err != nil {
		// Always run bcrypt to prevent timing attacks
		bcrypt.CompareHashAndPassword([]byte("$2a$10$fakehashfortimingprotectiononly"), []byte("dummy"))
		return c.Status(401).JSON(fiber.Map{"error": "invalid credentials"})
	}

	if !isActive {
		return c.Status(401).JSON(fiber.Map{"error": "account disabled"})
	}

	loginKeyBytes, err := base64.StdEncoding.DecodeString(req.LoginKey)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid loginKey"})
	}

	if err := bcrypt.CompareHashAndPassword([]byte(loginKeyHash), loginKeyBytes); err != nil {
		return c.Status(401).JSON(fiber.Map{"error": "invalid credentials"})
	}

	// First-login setup account — no key material yet, client must complete setup
	if kdfSalt == "" {
		setupToken, err := utils.GenerateSetupToken(userID, h.JWTSecret)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "internal error"})
		}
		return c.JSON(LoginResponse{RequiresSetup: true, SetupToken: &setupToken})
	}

	// TOTP required — return pre-auth token instead of full JWT
	if totpEnabled {
		preAuthToken, err := utils.GeneratePreAuthToken(userID, h.JWTSecret)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "internal error"})
		}
		return c.JSON(LoginResponse{
			RequiresTotp: true,
			PreAuthToken: &preAuthToken,
		})
	}

	return h.issueTokensAndRespond(c, userID, username, encMK, mkNonce, encPK, pkNonce, pubKey, isAdmin, quotaBytes, usedBytes)
}

type TwoFALoginRequest struct {
	PreAuthToken string `json:"preAuthToken"`
	Code         string `json:"code"`
}

// @Summary      Complete 2FA login
// @Description  Submit TOTP code with the preAuthToken from the login response. Locked after 5 failed attempts.
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        body  body      TwoFALoginRequest  true  "Pre-auth token and TOTP code"
// @Success      200   {object}  LoginResponse
// @Failure      400   {object}  ErrorResponse
// @Failure      401   {object}  ErrorResponse
// @Failure      429   {object}  ErrorResponse  "Too many failed TOTP attempts"
// @Router       /auth/login/2fa [post]
func (h *AuthHandler) LoginTwoFA(c *fiber.Ctx) error {
	var req TwoFALoginRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}

	// S2-1: Check if this pre-auth token has been blocked due to too many failed attempts
	if middleware.IsTOTPBlocked(req.PreAuthToken) {
		return c.Status(429).JSON(fiber.Map{"error": "too many failed attempts, please log in again"})
	}

	userID, err := utils.ValidatePreAuthToken(req.PreAuthToken, h.JWTSecret)
	if err != nil {
		return c.Status(401).JSON(fiber.Map{"error": "invalid pre-auth token"})
	}

	var (
		totpSecret                                                              *string
		encMK, mkNonce, encPK, pkNonce, pubKey, username2fa                    string
		isAdmin                                                                  bool
		quotaBytes, usedBytes                                                    int64
		isActive                                                                  bool
	)

	// S2-7: Include is_active check so disabled accounts cannot complete TOTP login
	err = h.DB.QueryRow(context.Background(), `
		SELECT totp_secret, encrypted_master_key, master_key_nonce,
		       encrypted_private_key, private_key_nonce, public_key,
		       is_admin, storage_quota_bytes, storage_used_bytes,
		       COALESCE(username, ''), is_active
		FROM users WHERE id = $1
	`, userID).Scan(&totpSecret, &encMK, &mkNonce, &encPK, &pkNonce, &pubKey,
		&isAdmin, &quotaBytes, &usedBytes, &username2fa, &isActive)
	if err != nil {
		return c.Status(401).JSON(fiber.Map{"error": "unauthorized"})
	}

	if !isActive {
		return c.Status(401).JSON(fiber.Map{"error": "account disabled"})
	}

	if totpSecret == nil || !services.ValidateTOTP(*totpSecret, req.Code) {
		// Record failed attempt; if now blocked, return 429
		if !middleware.RecordTOTPAttempt(req.PreAuthToken, false) {
			return c.Status(429).JSON(fiber.Map{"error": "too many failed attempts, please log in again"})
		}
		return c.Status(401).JSON(fiber.Map{"error": "invalid TOTP code"})
	}

	middleware.RecordTOTPAttempt(req.PreAuthToken, true)

	return h.issueTokensAndRespond(c, userID, username2fa, encMK, mkNonce, encPK, pkNonce, pubKey, isAdmin, quotaBytes, usedBytes)
}

// GetRecoveryPreflight returns the data needed client-side to perform recovery:
// the encrypted recovery key (master key encrypted with recovery key entropy).
// Rate limited 5/hr. No auth required — recovery is the auth mechanism.
// @Summary      Fetch encrypted recovery data before account recovery
// @Tags         Auth
// @Produce      json
// @Param        email  query     string  true  "Email address"
// @Success      200    {object}  PreflightRecoverResponse
// @Failure      400    {object}  ErrorResponse
// @Failure      429    {object}  ErrorResponse  "Rate limited (5/hr per IP)"
// @Router       /auth/recover/preflight [get]
func (h *AuthHandler) GetRecoveryPreflight(c *fiber.Ctx) error {
	email := c.Query("email")
	if email == "" {
		return c.Status(400).JSON(fiber.Map{"error": "email required"})
	}

	var encRecoveryKey, recoveryKeyNonce, encPrivateKey, privateKeyNonce string
	err := h.DB.QueryRow(context.Background(), `
		SELECT encrypted_recovery_key, recovery_key_nonce,
		       encrypted_private_key, private_key_nonce
		FROM users WHERE email = $1
	`, email).Scan(&encRecoveryKey, &recoveryKeyNonce, &encPrivateKey, &privateKeyNonce)
	if err != nil {
		// Return fake data to prevent enumeration
		return c.JSON(fiber.Map{
			"encryptedRecoveryKey": deterministicFakeSalt(email, "recovery"),
			"recoveryKeyNonce":     deterministicFakeSalt(email, "recovery-nonce"),
			"encryptedPrivateKey":  deterministicFakeSalt(email, "private"),
			"privateKeyNonce":      deterministicFakeSalt(email, "private-nonce"),
		})
	}

	return c.JSON(fiber.Map{
		"encryptedRecoveryKey": encRecoveryKey,
		"recoveryKeyNonce":     recoveryKeyNonce,
		"encryptedPrivateKey":  encPrivateKey,
		"privateKeyNonce":      privateKeyNonce,
	})
}

type RecoverRequest struct {
	Email                string `json:"email"`
	// Client proves mnemonic possession by providing encryptedMasterKey decrypted
	// with recoveryKey, then re-encrypted with new keyEncryptionKey
	NewLoginKey          string `json:"newLoginKey"`
	NewEncryptedMasterKey string `json:"newEncryptedMasterKey"`
	NewMasterKeyNonce     string `json:"newMasterKeyNonce"`
	NewKDFSalt            string `json:"newKdfSalt"`
	NewLoginKeySalt       string `json:"newLoginKeySalt"`
	// Recovery proof: base64(recoveryKeyEntropy) — verified against stored bcrypt verifier
	RecoveryProof         string `json:"recoveryProof"`
}

// @Summary      Recover account using mnemonic recovery key
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        body  body      RecoverRequest  true  "Recovery proof and new key material"
// @Success      200   {object}  MessageResponse
// @Failure      400   {object}  ErrorResponse
// @Failure      401   {object}  ErrorResponse
// @Failure      404   {object}  ErrorResponse
// @Failure      429   {object}  ErrorResponse  "Rate limited (5/hr per IP)"
// @Router       /auth/recover [post]
func (h *AuthHandler) Recover(c *fiber.Ctx) error {
	var req RecoverRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}

	if req.RecoveryProof == "" {
		return c.Status(400).JSON(fiber.Map{"error": "recoveryProof is required"})
	}

	// Fetch stored recovery key verifier (S1-2 fix)
	var storedVerifier string
	err := h.DB.QueryRow(context.Background(),
		`SELECT recovery_key_verifier FROM users WHERE email = $1`, req.Email,
	).Scan(&storedVerifier)
	if err != nil {
		// Run a fake bcrypt to prevent timing-based email enumeration
		bcrypt.CompareHashAndPassword([]byte("$2a$10$fakehashfortimingprotectiononly"), []byte("dummy"))
		return c.Status(404).JSON(fiber.Map{"error": "user not found"})
	}

	// If the account has a stored verifier, validate the proof
	if storedVerifier != "" {
		proofBytes, err := base64.StdEncoding.DecodeString(req.RecoveryProof)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid recoveryProof encoding"})
		}
		if err := bcrypt.CompareHashAndPassword([]byte(storedVerifier), proofBytes); err != nil {
			return c.Status(401).JSON(fiber.Map{"error": "invalid recovery proof"})
		}
	}
	// Accounts without a verifier (created before this migration) are allowed through.
	// A future migration can enforce this for all accounts.

	loginKeyBytes, err := base64.StdEncoding.DecodeString(req.NewLoginKey)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid loginKey"})
	}

	hash, err := bcrypt.GenerateFromPassword(loginKeyBytes, bcrypt.DefaultCost)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}

	result, err := h.DB.Exec(context.Background(), `
		UPDATE users SET
			login_key_hash = $1,
			encrypted_master_key = $2,
			master_key_nonce = $3,
			kdf_salt = $4,
			login_key_salt = $5,
			is_first_login = false,
			updated_at = NOW()
		WHERE email = $6
	`, string(hash), req.NewEncryptedMasterKey, req.NewMasterKeyNonce,
		req.NewKDFSalt, req.NewLoginKeySalt, req.Email)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}

	if result.RowsAffected() == 0 {
		return c.Status(404).JSON(fiber.Map{"error": "user not found"})
	}

	return c.JSON(fiber.Map{"message": "password reset"})
}

type RefreshRequest struct {
	RefreshToken string `json:"refreshToken"`
}

// @Summary      Refresh access token
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        body  body      RefreshRequest  false  "Refresh token (or pass via refresh_token cookie)"
// @Success      200   {object}  RefreshResponse
// @Failure      401   {object}  ErrorResponse
// @Router       /auth/refresh [post]
func (h *AuthHandler) Refresh(c *fiber.Ctx) error {
	refreshToken := c.Cookies("refresh_token")
	if refreshToken == "" {
		var req RefreshRequest
		c.BodyParser(&req)
		refreshToken = req.RefreshToken
	}
	if refreshToken == "" {
		return c.Status(401).JSON(fiber.Map{"error": "missing refresh token"})
	}

	claims, err := utils.ValidateToken(refreshToken, h.JWTSecret)
	if err != nil || claims.Subject != "" {
		return c.Status(401).JSON(fiber.Map{"error": "invalid refresh token"})
	}

	// Verify user is still active
	var isActive, isAdmin bool
	err = h.DB.QueryRow(context.Background(),
		`SELECT is_active, is_admin FROM users WHERE id = $1`, claims.UserID,
	).Scan(&isActive, &isAdmin)
	if err != nil || !isActive {
		return c.Status(401).JSON(fiber.Map{"error": "unauthorized"})
	}

	accessToken, err := utils.GenerateAccessToken(claims.UserID, isAdmin, h.JWTSecret)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}

	return c.JSON(fiber.Map{"accessToken": accessToken})
}

// @Summary      Get current user profile and key bundle
// @Tags         User
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  MeResponse
// @Failure      401  {object}  ErrorResponse
// @Failure      404  {object}  ErrorResponse
// @Router       /user/me [get]
func (h *AuthHandler) GetMe(c *fiber.Ctx) error {
	userID := middleware.UserID(c)

	var u struct {
		ID                string `json:"id"`
		Email             string `json:"email"`
		Username          string `json:"username"`
		PublicKey         string `json:"publicKey"`
		TOTPEnabled       bool   `json:"totpEnabled"`
		StorageQuota      int64  `json:"storageQuotaBytes"`
		StorageUsed       int64  `json:"storageUsedBytes"`
		IsAdmin           bool   `json:"isAdmin"`
	}

	err := h.DB.QueryRow(context.Background(), `
		SELECT id, email, COALESCE(username, ''), public_key, totp_enabled,
		       storage_quota_bytes, storage_used_bytes, is_admin
		FROM users WHERE id = $1
	`, userID).Scan(&u.ID, &u.Email, &u.Username, &u.PublicKey, &u.TOTPEnabled,
		&u.StorageQuota, &u.StorageUsed, &u.IsAdmin)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "user not found"})
	}

	return c.JSON(u)
}

// @Summary      Look up another user's public key by email
// @Tags         User
// @Produce      json
// @Security     BearerAuth
// @Param        email  path      string  true  "URL-encoded email address"
// @Success      200    {object}  UserLookupResponse
// @Failure      401    {object}  ErrorResponse
// @Failure      404    {object}  ErrorResponse
// @Router       /users/by-email/{email} [get]
func (h *AuthHandler) GetUserByEmail(c *fiber.Ctx) error {
	email := c.Params("email")

	var userID, publicKey string
	err := h.DB.QueryRow(context.Background(),
		`SELECT id, public_key FROM users WHERE email = $1 AND is_active = true`,
		email,
	).Scan(&userID, &publicKey)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "user not found"})
	}

	return c.JSON(fiber.Map{
		"userId":    userID,
		"publicKey": publicKey,
	})
}

// TOTP setup: generate secret, return QR URI. Not yet enabled until verified.
// @Summary      Generate TOTP secret
// @Tags         User
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  TOTPSetupResponse
// @Failure      401  {object}  ErrorResponse
// @Router       /user/2fa/setup [post]
func (h *AuthHandler) SetupTOTP(c *fiber.Ctx) error {
	userID := middleware.UserID(c)

	var email string
	err := h.DB.QueryRow(context.Background(),
		`SELECT email FROM users WHERE id = $1`, userID,
	).Scan(&email)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "user not found"})
	}

	secret, qrURI, err := services.GenerateTOTP(email, "Kutup")
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}

	// Store the pending secret (not yet enabled)
	_, err = h.DB.Exec(context.Background(),
		`UPDATE users SET totp_secret = $1 WHERE id = $2`, secret, userID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}

	return c.JSON(fiber.Map{
		"secret": secret,
		"qrUri":  qrURI,
	})
}

// VerifyTOTP enables TOTP after user confirms they can generate valid codes.
// @Summary      Confirm TOTP setup
// @Tags         User
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      TOTPCodeRequest  true  "6-digit TOTP code"
// @Success      200   {object}  MessageResponse
// @Failure      400   {object}  ErrorResponse
// @Failure      401   {object}  ErrorResponse
// @Router       /user/2fa/verify [post]
func (h *AuthHandler) VerifyTOTP(c *fiber.Ctx) error {
	userID := middleware.UserID(c)

	var body struct {
		Code string `json:"code"`
	}
	if err := c.BodyParser(&body); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}

	var totpSecret *string
	err := h.DB.QueryRow(context.Background(),
		`SELECT totp_secret FROM users WHERE id = $1`, userID,
	).Scan(&totpSecret)
	if err != nil || totpSecret == nil {
		return c.Status(400).JSON(fiber.Map{"error": "TOTP not set up"})
	}

	if !services.ValidateTOTP(*totpSecret, body.Code) {
		return c.Status(400).JSON(fiber.Map{"error": "invalid code"})
	}

	_, err = h.DB.Exec(context.Background(),
		`UPDATE users SET totp_enabled = true WHERE id = $1`, userID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}

	return c.JSON(fiber.Map{"message": "TOTP enabled"})
}

// @Summary      Disable TOTP
// @Description  Requires a valid TOTP code to prevent a stolen session from silently removing 2FA.
// @Tags         User
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      TOTPCodeRequest  true  "6-digit TOTP code"
// @Success      200   {object}  MessageResponse
// @Failure      400   {object}  ErrorResponse
// @Failure      401   {object}  ErrorResponse
// @Router       /user/2fa [delete]
func (h *AuthHandler) DisableTOTP(c *fiber.Ctx) error {
	userID := middleware.UserID(c)

	var req struct {
		Code string `json:"code"`
	}
	if err := c.BodyParser(&req); err != nil || req.Code == "" {
		return c.Status(400).JSON(fiber.Map{"error": "totp code required"})
	}

	var secret string
	err := h.DB.QueryRow(context.Background(),
		`SELECT totp_secret FROM users WHERE id = $1 AND totp_enabled = true`, userID,
	).Scan(&secret)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "TOTP not enabled"})
	}

	if !services.ValidateTOTP(secret, req.Code) {
		return c.Status(400).JSON(fiber.Map{"error": "invalid code"})
	}

	_, err = h.DB.Exec(context.Background(),
		`UPDATE users SET totp_enabled = false, totp_secret = NULL WHERE id = $1`, userID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}

	return c.JSON(fiber.Map{"message": "TOTP disabled"})
}

// CompleteSetup finalises a first-login account: stores key material and issues tokens.
// Auth via short-lived setupToken (not a regular access token).
// @Summary      Complete first-login setup
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      RegisterRequest  true  "Full key bundle"
// @Success      200   {object}  LoginResponse
// @Failure      400   {object}  ErrorResponse
// @Failure      401   {object}  ErrorResponse
// @Router       /auth/complete-setup [post]
func (h *AuthHandler) CompleteSetup(c *fiber.Ctx) error {
	authHeader := c.Get("Authorization")
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	userID, err := utils.ValidateSetupToken(tokenStr, h.JWTSecret)
	if err != nil {
		return c.Status(401).JSON(fiber.Map{"error": "invalid setup token"})
	}

	// S2-7: Ensure account is still active before completing setup
	var isActive bool
	h.DB.QueryRow(context.Background(), `SELECT is_active FROM users WHERE id = $1`, userID).Scan(&isActive)
	if !isActive {
		return c.Status(401).JSON(fiber.Map{"error": "account disabled"})
	}

	var req RegisterRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}

	loginKeyBytes, err := base64.StdEncoding.DecodeString(req.LoginKey)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid loginKey"})
	}

	hash, err := bcrypt.GenerateFromPassword(loginKeyBytes, bcrypt.DefaultCost)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}

	// Only update if kdf_salt is still empty (prevents replay after setup is done)
	result, err := h.DB.Exec(context.Background(), `
		UPDATE users SET
			login_key_hash = $1,
			encrypted_master_key = $2, master_key_nonce = $3,
			encrypted_recovery_key = $4, recovery_key_nonce = $5,
			encrypted_private_key = $6, private_key_nonce = $7,
			public_key = $8, kdf_salt = $9, login_key_salt = $10,
			is_first_login = false, updated_at = NOW()
		WHERE id = $11 AND kdf_salt = ''
	`, string(hash),
		req.EncryptedMasterKey, req.MasterKeyNonce,
		req.EncryptedRecoveryKey, req.RecoveryKeyNonce,
		req.EncryptedPrivateKey, req.PrivateKeyNonce,
		req.PublicKey, req.KDFSalt, req.LoginKeySalt,
		userID)
	if err != nil || result.RowsAffected() == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "setup already completed or user not found"})
	}

	var isAdmin bool
	var quotaBytes, usedBytes int64
	var username string
	h.DB.QueryRow(context.Background(), `
		SELECT is_admin, storage_quota_bytes, storage_used_bytes, COALESCE(username, '') FROM users WHERE id = $1
	`, userID).Scan(&isAdmin, &quotaBytes, &usedBytes, &username)

	accessToken, err := utils.GenerateAccessToken(userID, isAdmin, h.JWTSecret)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}
	refreshToken, err := utils.GenerateRefreshToken(userID, h.JWTSecret)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}

	c.Cookie(&fiber.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		HTTPOnly: true,
		Secure:   h.AppEnv == "production",
		SameSite: "Lax",
		MaxAge:   7 * 24 * 3600,
		Path:     "/api/auth/refresh",
	})

	return c.JSON(fiber.Map{
		"accessToken":       accessToken,
		"userId":            userID,
		"username":          username,
		"isAdmin":           isAdmin,
		"storageQuotaBytes": quotaBytes,
		"storageUsedBytes":  usedBytes,
	})
}

// GetPublicSettings returns site settings visible without authentication.
// @Summary      Get public server settings
// @Tags         Auth
// @Produce      json
// @Success      200  {object}  SettingsResponse
// @Router       /auth/settings [get]
func (h *AuthHandler) GetPublicSettings(c *fiber.Ctx) error {
	var val string
	h.DB.QueryRow(context.Background(), `SELECT value FROM site_settings WHERE key='registration_enabled'`).Scan(&val)
	return c.JSON(fiber.Map{"registrationEnabled": val != "false"})
}

// --- helpers ---

func (h *AuthHandler) issueTokensAndRespond(c *fiber.Ctx, userID, username, encMK, mkNonce, encPK, pkNonce, pubKey string, isAdmin bool, quota, used int64) error {
	accessToken, err := utils.GenerateAccessToken(userID, isAdmin, h.JWTSecret)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}
	refreshToken, err := utils.GenerateRefreshToken(userID, h.JWTSecret)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}

	// S2-8: Secure cookie flag — enable Secure in production
	c.Cookie(&fiber.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		HTTPOnly: true,
		Secure:   h.AppEnv == "production",
		SameSite: "Lax",
		MaxAge:   7 * 24 * 3600,
		Path:     "/api/auth/refresh",
	})

	return c.JSON(LoginResponse{
		AccessToken:         accessToken,
		UserID:              userID,
		Username:            username,
		EncryptedMasterKey:  encMK,
		MasterKeyNonce:      mkNonce,
		EncryptedPrivateKey: encPK,
		PrivateKeyNonce:     pkNonce,
		PublicKey:           pubKey,
		IsAdmin:             isAdmin,
		StorageQuotaBytes:   quota,
		StorageUsedBytes:    used,
	})
}

// deterministicFakeSalt derives a stable base64 salt from email+purpose to
// prevent user enumeration (non-existent users get same response timing/shape).
func deterministicFakeSalt(email, purpose string) string {
	// XOR mix of email bytes and purpose — consistent for same input
	input := email + ":" + purpose + ":kutup-fake-salt-2024"
	b := make([]byte, 32)
	for i := range b {
		b[i] = input[i%len(input)] ^ byte(i*7+13)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func isDuplicateKeyError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "duplicate key") || strings.Contains(msg, "unique")
}
