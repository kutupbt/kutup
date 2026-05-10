package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var rmFolder bool

var rmCmd = &cobra.Command{
	Use:   "rm <id>",
	Short: "Delete a file or folder",
	Args:  cobra.ExactArgs(1),
	RunE:  runRm,
}

func init() {
	rmCmd.Flags().BoolVar(&rmFolder, "folder", false, "delete a folder (collection) instead of a file")
}

func runRm(cmd *cobra.Command, args []string) error {
	id := args[0]

	client, _, cleanup, err := requireSessionFull()
	if err != nil {
		return err
	}
	defer cleanup()

	if rmFolder {
		if err := client.DeleteCollection(id); err != nil {
			return fmt.Errorf("delete folder: %w", err)
		}
		if jsonOut {
			fmt.Printf(`{"deleted":%q,"type":"folder"}`+"\n", id)
		} else {
			fmt.Printf("Deleted folder %s\n", id)
		}
		return nil
	}

	if err := client.DeleteFile(id); err != nil {
		return fmt.Errorf("delete file: %w", err)
	}
	if jsonOut {
		fmt.Printf(`{"deleted":%q,"type":"file"}`+"\n", id)
	} else {
		fmt.Printf("Deleted file %s\n", id)
	}
	return nil
}
