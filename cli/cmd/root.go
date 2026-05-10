package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	profile string
	jsonOut bool
)

var rootCmd = &cobra.Command{
	Use:   "kutup",
	Short: "Kutup CLI — E2E encrypted file storage",
	Long:  "kutup is the command-line interface for the Kutup self-hosted encrypted file storage service.",
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&profile, "profile", "default", "profile name (for multiple accounts)")
	rootCmd.PersistentFlags().BoolVar(&jsonOut, "json", false, "output as JSON")

	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(logoutCmd)
	rootCmd.AddCommand(whoamiCmd)
	rootCmd.AddCommand(lsCmd)
	rootCmd.AddCommand(mkdirCmd)
	rootCmd.AddCommand(uploadCmd)
	rootCmd.AddCommand(downloadCmd)
	rootCmd.AddCommand(rmCmd)
	rootCmd.AddCommand(syncCmd)
	rootCmd.AddCommand(shareCmd)
	rootCmd.AddCommand(versionsCmd)
	rootCmd.AddCommand(devicesCmd)
	rootCmd.AddCommand(twoFACmd)
	rootCmd.AddCommand(pubCmd)
	rootCmd.AddCommand(mvCmd)
	rootCmd.AddCommand(colorCmd)
}
