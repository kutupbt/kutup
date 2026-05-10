package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	qrcode "github.com/skip2/go-qrcode"
	"github.com/spf13/cobra"
)

var twoFACmd = &cobra.Command{
	Use:   "2fa",
	Short: "Manage time-based one-time-password (TOTP) two-factor authentication",
}

var twoFAStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show whether 2FA is enabled on your account",
	Args:  cobra.NoArgs,
	RunE:  runTwoFAStatus,
}

var twoFAEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable 2FA: prints a QR + provisioning URI, then verifies a code",
	Args:  cobra.NoArgs,
	RunE:  runTwoFAEnable,
}

var twoFADisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable 2FA (requires a current TOTP code)",
	Args:  cobra.NoArgs,
	RunE:  runTwoFADisable,
}

func init() {
	twoFACmd.AddCommand(twoFAStatusCmd)
	twoFACmd.AddCommand(twoFAEnableCmd)
	twoFACmd.AddCommand(twoFADisableCmd)
}

func runTwoFAStatus(_ *cobra.Command, _ []string) error {
	client, _, cleanup, err := requireSessionFull()
	if err != nil {
		return err
	}
	defer cleanup()
	me, err := client.Me()
	if err != nil {
		return err
	}
	if jsonOut {
		out, _ := json.Marshal(map[string]bool{"totpEnabled": me.TotpEnabled})
		fmt.Println(string(out))
		return nil
	}
	if me.TotpEnabled {
		fmt.Println("2FA: enabled")
	} else {
		fmt.Println("2FA: not enabled")
	}
	return nil
}

func runTwoFAEnable(_ *cobra.Command, _ []string) error {
	client, _, cleanup, err := requireSessionFull()
	if err != nil {
		return err
	}
	defer cleanup()

	res, err := client.SetupTOTP()
	if err != nil {
		return err
	}

	// Render the otpauth:// URI as an ASCII QR code in the terminal.
	// Most authenticator apps scan this directly. Print the URI too for
	// users on terminals that mangle the QR or who type the secret manually.
	q, err := qrcode.New(res.QrURI, qrcode.Medium)
	if err != nil {
		return fmt.Errorf("render QR: %w", err)
	}
	fmt.Println(q.ToSmallString(false))
	fmt.Println()
	fmt.Printf("Provisioning URI: %s\n", res.QrURI)
	fmt.Printf("Or enter this secret manually: %s\n\n", res.Secret)

	// Read the first TOTP code to confirm setup. The backend won't flip
	// totp_enabled until verify succeeds, so an unverified setup is a
	// no-op for login.
	fmt.Print("Enter the 6-digit code from your authenticator: ")
	reader := bufio.NewReader(os.Stdin)
	code, _ := reader.ReadString('\n')
	code = strings.TrimSpace(code)
	if code == "" {
		return fmt.Errorf("aborted (no code entered)")
	}

	if err := client.VerifyTOTP(code); err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	if jsonOut {
		fmt.Println(`{"totpEnabled":true}`)
	} else {
		fmt.Println("2FA enabled. Save your recovery phrase — losing your authenticator without it locks you out.")
	}
	return nil
}

func runTwoFADisable(_ *cobra.Command, _ []string) error {
	client, _, cleanup, err := requireSessionFull()
	if err != nil {
		return err
	}
	defer cleanup()

	// Backend requires a valid TOTP code to disable — prevents a stolen
	// session from silently removing 2FA.
	fmt.Print("Enter your current 6-digit code to confirm: ")
	reader := bufio.NewReader(os.Stdin)
	code, _ := reader.ReadString('\n')
	code = strings.TrimSpace(code)
	if code == "" {
		return fmt.Errorf("aborted (no code entered)")
	}

	if err := client.DisableTOTP(code); err != nil {
		return err
	}
	if jsonOut {
		fmt.Println(`{"totpEnabled":false}`)
	} else {
		fmt.Println("2FA disabled.")
	}
	return nil
}
