package cmd

import (
	"fmt"
	"regexp"

	"github.com/spf13/cobra"
)

var colorCmd = &cobra.Command{
	Use:   "color <collection-id> <hex>",
	Short: "Set the display color for a collection (e.g. #ef4444)",
	Long: `Set the display color for a collection. Pass an empty string ("") to clear.

The color drives the Drive UI's per-folder accent. Valid format is
#rrggbb (lowercase hex).`,
	Args: cobra.ExactArgs(2),
	RunE: runColor,
}

var colorHexRE = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

func runColor(_ *cobra.Command, args []string) error {
	collID := args[0]
	color := args[1]

	if color != "" && !colorHexRE.MatchString(color) {
		return fmt.Errorf("color must be #rrggbb hex or empty string to clear")
	}

	client, _, cleanup, err := requireSessionFull()
	if err != nil {
		return err
	}
	defer cleanup()

	if err := client.UpdateCollectionColor(collID, color); err != nil {
		return err
	}
	if jsonOut {
		fmt.Printf(`{"collectionId":%q,"color":%q}`+"\n", collID, color)
	} else if color == "" {
		fmt.Printf("Cleared color on %s\n", collID)
	} else {
		fmt.Printf("Set color of %s to %s\n", collID, color)
	}
	return nil
}
