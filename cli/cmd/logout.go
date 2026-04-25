package cmd

import (
	"fmt"

	"github.com/alperen-albayrak/kutup/cli/internal/session"
	"github.com/spf13/cobra"
)

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Clear stored session",
	RunE:  runLogout,
}

func runLogout(cmd *cobra.Command, args []string) error {
	store, err := session.Open(profile)
	if err != nil {
		return err
	}
	defer store.Close()
	if err := store.ClearSession(); err != nil {
		return err
	}
	fmt.Println("Logged out.")
	return nil
}
