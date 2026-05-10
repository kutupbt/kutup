package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

var whoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Show current user info",
	RunE:  runWhoami,
}

func runWhoami(cmd *cobra.Command, args []string) error {
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
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(me)
	}

	fmt.Printf("Username:  %s\n", me.Username)
	fmt.Printf("Email:     %s\n", me.Email)
	fmt.Printf("Storage:   %s / %s\n", formatBytes(me.StorageUsedBytes), formatBytes(me.StorageQuotaBytes))
	fmt.Printf("Admin:     %v\n", me.IsAdmin)
	fmt.Printf("2FA:       %v\n", me.TotpEnabled)
	return nil
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
