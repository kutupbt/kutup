package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log"
	"strings"

	"github.com/depo/backend/config"
	"github.com/depo/backend/db"
	"github.com/depo/backend/handlers"
	"github.com/depo/backend/middleware"
	"github.com/depo/backend/services"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	cfg := config.Load()

	// Run migrations
	if err := db.Migrate(cfg.DatabaseURL); err != nil {
		log.Fatalf("migrations failed: %v", err)
	}

	// Connect pool
	pool, err := db.Connect(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("db connect: %v", err)
	}
	defer pool.Close()

	// Seed admin accounts from env
	bootstrapAdmins(pool, cfg.AdminAccounts)

	// Storage service
	storage, err := services.NewStorage(
		cfg.S3Endpoint, cfg.S3AccessKey, cfg.S3SecretKey,
		cfg.S3Bucket, cfg.S3Region,
	)
	if err != nil {
		log.Fatalf("storage init: %v", err)
	}

	// Handlers
	authH := &handlers.AuthHandler{DB: pool, JWTSecret: cfg.JWTSecret, AppEnv: cfg.AppEnv}
	collectionsH := &handlers.CollectionsHandler{DB: pool, ServerURL: cfg.ServerURL, AppEnv: cfg.AppEnv}
	filesH := &handlers.FilesHandler{DB: pool, Storage: storage}
	sharesH := &handlers.SharesHandler{DB: pool, Storage: storage}
	adminH := &handlers.AdminHandler{DB: pool}
	fedH := &handlers.FederationHandler{DB: pool, Storage: storage}
	fedProxyH := &handlers.FedProxyHandler{DB: pool, AppEnv: cfg.AppEnv}

	// Middleware
	authMW := middleware.NewAuth(cfg.JWTSecret)

	app := fiber.New(fiber.Config{
		BodyLimit:             10 * 1024 * 1024 * 1024, // 10 GB
		StreamRequestBody:     true,
		DisableStartupMessage: cfg.AppEnv == "production",
	})

	app.Use(recover.New())
	app.Use(cors.New(cors.Config{
		AllowOrigins:     "*",
		AllowHeaders:     "Origin, Content-Type, Accept, Authorization",
		AllowMethods:     "GET, POST, PUT, PATCH, DELETE, OPTIONS",
		AllowCredentials: false,
	}))

	api := app.Group("/api")

	// Auth routes
	auth := api.Group("/auth")
	auth.Get("/settings", authH.GetPublicSettings)
	auth.Post("/register", authH.Register)
	auth.Get("/login/preflight", middleware.PreflightRateLimit(), authH.GetLoginPreflight)
	auth.Post("/login", middleware.LoginRateLimit(), authH.Login)
	auth.Post("/login/2fa", authH.LoginTwoFA)
	auth.Get("/recover/preflight", middleware.RecoveryRateLimit(), authH.GetRecoveryPreflight)
	auth.Post("/recover", middleware.RecoveryRateLimit(), authH.Recover)
	auth.Post("/refresh", authH.Refresh)
	auth.Post("/complete-setup", authH.CompleteSetup)

	// User routes (authenticated)
	user := api.Group("/user", authMW.Required())
	user.Get("/me", authH.GetMe)
	user.Post("/2fa/setup", authH.SetupTOTP)
	user.Post("/2fa/verify", authH.VerifyTOTP)
	user.Delete("/2fa", authH.DisableTOTP)

	// User lookup (for sharing)
	api.Get("/users/by-email/:email", authMW.Required(), authH.GetUserByEmail)

	// Collections routes (authenticated)
	collections := api.Group("/collections", authMW.Required())
	collections.Get("/", collectionsH.ListCollections)
	collections.Post("/", collectionsH.CreateCollection)
	collections.Get("/fed-pubkey", collectionsH.FetchRemotePubkey)
	collections.Get("/:id", collectionsH.GetCollection)
	collections.Put("/:id", collectionsH.UpdateCollection)
	collections.Delete("/:id", collectionsH.DeleteCollection)
	collections.Patch("/:id/color", collectionsH.UpdateCollectionColor)
	collections.Post("/:id/share", collectionsH.ShareCollection)
	collections.Post("/:id/share-federated", collectionsH.ShareFederated)
	collections.Get("/:id/files", filesH.ListFiles)

	// Federation public endpoints (no auth — token is the auth mechanism)
	fed := api.Group("/fed")
	fed.Get("/users", middleware.FedUsersRateLimit(), fedH.GetUserByUsername)
	fed.Get("/invites/:token", fedH.GetInvite)
	fed.Get("/shares/:token/files", fedH.ListShareFiles)
	fed.Get("/shares/:token/files/:fileId/download", fedH.DownloadShareFile)
	fed.Post("/shares/:token/files", fedH.UploadShareFile)
	fed.Delete("/shares/:token/files/:fileId", fedH.DeleteShareFile)

	// Federation proxy endpoints (authenticated)
	fedProxy := api.Group("/fed-proxy", authMW.Required())
	fedProxy.Post("/incoming", fedProxyH.AddIncomingShare)
	fedProxy.Get("/incoming", fedProxyH.ListIncomingShares)
	fedProxy.Delete("/incoming/:shareId", fedProxyH.RemoveIncomingShare)
	fedProxy.Get("/:shareId/files", fedProxyH.ProxyListFiles)
	fedProxy.Get("/:shareId/files/:fileId/download", fedProxyH.ProxyDownload)
	fedProxy.Post("/:shareId/upload", fedProxyH.ProxyUpload)
	fedProxy.Delete("/:shareId/files/:fileId", fedProxyH.ProxyDelete)

	// Files routes (authenticated)
	files := api.Group("/files", authMW.Required())
	files.Post("/upload", filesH.Upload)
	files.Get("/:id/download", filesH.Download)
	files.Delete("/:id", filesH.Delete)

	// Public share routes (no auth)
	share := api.Group("/share")
	share.Post("/", authMW.Required(), sharesH.CreatePublicShare)
	share.Get("/:token", sharesH.GetPublicShare)
	share.Get("/:token/files", sharesH.ListPublicShareFiles)
	share.Get("/:token/download/:fileId", sharesH.DownloadPublicShareFile)

	// Admin routes
	admin := api.Group("/admin", authMW.Required(), middleware.AdminRequired())
	admin.Get("/users", adminH.ListUsers)
	admin.Post("/users", adminH.CreateUser)
	admin.Put("/users/:id", adminH.UpdateUser)
	admin.Delete("/users/:id", adminH.DeleteUser)
	admin.Get("/stats", adminH.GetStats)
	admin.Get("/settings", adminH.GetSettings)
	admin.Put("/settings", adminH.UpdateSettings)

	log.Println("starting server on :3000")
	if err := app.Listen(":3000"); err != nil {
		log.Fatalf("server: %v", err)
	}
}

// bootstrapAdmins seeds admin accounts from ADMIN_ACCOUNTS env var.
// Format: comma-separated email:username pairs (no password).
// A random one-time password is generated and printed to stdout on first creation.
// Admins must complete setup on first login to establish their E2EE key material.
func bootstrapAdmins(pool *pgxpool.Pool, accountsEnv string) {
	if accountsEnv == "" {
		return
	}
	ctx := context.Background()
	for _, pair := range strings.Split(accountsEnv, ",") {
		parts := strings.SplitN(strings.TrimSpace(pair), ":", 2)
		if len(parts) != 2 {
			log.Printf("bootstrapAdmins: skipping malformed entry (expected email:username)")
			continue
		}
		email := strings.TrimSpace(parts[0])
		username := strings.TrimSpace(parts[1])
		if email == "" || username == "" {
			continue
		}

		var count int
		pool.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE email=$1`, email).Scan(&count)
		if count > 0 {
			continue
		}

		// Generate a cryptographically random one-time password (never stored in env)
		tokenBytes := make([]byte, 16)
		if _, err := rand.Read(tokenBytes); err != nil {
			log.Printf("bootstrapAdmins: failed to generate password for %s: %v", email, err)
			continue
		}
		tempPass := hex.EncodeToString(tokenBytes)

		hash, err := bcrypt.GenerateFromPassword([]byte(tempPass), bcrypt.DefaultCost)
		if err != nil {
			log.Printf("bootstrapAdmins: bcrypt error for %s: %v", email, err)
			continue
		}

		_, err = pool.Exec(ctx, `
			INSERT INTO users (
				email, username, login_key_hash,
				encrypted_master_key, master_key_nonce,
				encrypted_recovery_key, recovery_key_nonce,
				encrypted_private_key, private_key_nonce,
				public_key, kdf_salt, login_key_salt,
				is_admin, is_first_login
			) VALUES ($1,$2,$3,'','','','','','','','','',true,true)
		`, email, username, string(hash))
		if err != nil {
			log.Printf("bootstrapAdmins: insert error for %s: %v", email, err)
		} else {
			log.Printf("bootstrapAdmins: created admin account %s (@%s)", email, username)
			log.Printf("bootstrapAdmins: ONE-TIME PASSWORD for %s: %s", email, tempPass)
			log.Printf("bootstrapAdmins: Sign in with this password once to complete account setup. It cannot be recovered.")
		}
	}
}
