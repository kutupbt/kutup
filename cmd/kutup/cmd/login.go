package cmd

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/kutupbulut/kutup/cmd/kutup/internal/api"
	"github.com/kutupbulut/kutup/cmd/kutup/internal/crypto"
	"github.com/kutupbulut/kutup/cmd/kutup/internal/session"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate and store session",
	RunE:  runLogin,
}

var loginServer string

func init() {
	loginCmd.Flags().StringVar(&loginServer, "server", "", "server URL (e.g. https://kutup.example.com)")
}

func runLogin(cmd *cobra.Command, args []string) error {
	// Prompt for server if not provided
	server := loginServer
	if server == "" {
		fmt.Print("Server URL: ")
		fmt.Scanln(&server)
	}
	server = strings.TrimRight(server, "/")

	fmt.Print("Email: ")
	var email string
	fmt.Scanln(&email)

	fmt.Print("Password: ")
	passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return fmt.Errorf("read password: %w", err)
	}
	password := string(passwordBytes)

	client := api.New(server, "")

	// Step 1: Preflight — get KDF salts
	fmt.Println("Deriving keys…")
	preflight, err := client.LoginPreflight(email)
	if err != nil {
		return fmt.Errorf("preflight: %w", err)
	}

	// Step 2: Derive login key (independent Argon2id from password + loginKeySalt)
	loginKey, err := crypto.DeriveLoginKey(password, preflight.LoginKeySalt)
	if err != nil {
		return fmt.Errorf("derive login key: %w", err)
	}

	// Step 3: Login
	loginResp, err := client.Login(api.LoginRequest{
		Email:    email,
		LoginKey: base64.StdEncoding.EncodeToString(loginKey),
	})
	if err != nil {
		return fmt.Errorf("login: %w", err)
	}

	// Step 4: Handle TOTP if required
	if loginResp.RequiresTotp {
		fmt.Print("TOTP code: ")
		var code string
		fmt.Scanln(&code)
		loginResp, err = client.LoginTOTP(api.TotpRequest{
			PreAuthToken: loginResp.PreAuthToken,
			Code:         code,
		})
		if err != nil {
			return fmt.Errorf("TOTP: %w", err)
		}
	}

	if loginResp.RequiresSetup {
		return fmt.Errorf("account requires first-login setup — use the web UI to complete setup first")
	}

	// Step 5: Derive KEK and decrypt master key + private key
	fmt.Println("Decrypting vault…")
	kek, err := crypto.DeriveKEK(password, preflight.KdfSalt)
	if err != nil {
		return fmt.Errorf("derive KEK: %w", err)
	}

	masterKey, err := crypto.SecretBoxOpenB64(loginResp.EncryptedMasterKey, loginResp.MasterKeyNonce, kek)
	if err != nil {
		return fmt.Errorf("decrypt master key: %w", err)
	}

	privateKey, err := crypto.SecretBoxOpenB64(loginResp.EncryptedPrivateKey, loginResp.PrivateKeyNonce, masterKey)
	if err != nil {
		return fmt.Errorf("decrypt private key: %w", err)
	}

	// Step 6: Persist session
	store, err := session.Open(profile)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer store.Close()

	sess := &session.Session{
		Server:              server,
		Email:               email,
		UserID:              loginResp.UserID,
		Username:            loginResp.Username,
		AccessToken:         loginResp.AccessToken,
		RefreshToken:        loginResp.RefreshToken,
		MasterKey:           base64.StdEncoding.EncodeToString(masterKey),
		PrivateKey:          base64.StdEncoding.EncodeToString(privateKey),
		PublicKey:           loginResp.PublicKey,
		EncryptedMasterKey:  loginResp.EncryptedMasterKey,
		MasterKeyNonce:      loginResp.MasterKeyNonce,
		EncryptedPrivateKey: loginResp.EncryptedPrivateKey,
		PrivateKeyNonce:     loginResp.PrivateKeyNonce,
		StorageQuotaBytes:   loginResp.StorageQuotaBytes,
		StorageUsedBytes:    loginResp.StorageUsedBytes,
	}

	if err := store.SaveSession(profile, sess); err != nil {
		return fmt.Errorf("save session: %w", err)
	}

	fmt.Printf("Logged in as %s (%s)\n", sess.Username, sess.Email)
	return nil
}
