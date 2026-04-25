package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/alperen-albayrak/kutup/cli/internal/api"
	"github.com/spf13/cobra"
)

var lsTree bool

var lsCmd = &cobra.Command{
	Use:   "ls [folder-id]",
	Short: "List files and folders",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runLs,
}

func init() {
	lsCmd.Flags().BoolVar(&lsTree, "tree", false, "show full folder tree")
}

type lsEntry struct {
	ID      string  `json:"id"`
	Type    string  `json:"type"`
	Name    string  `json:"name"`
	Size    int64   `json:"size,omitempty"`
	Created string  `json:"created,omitempty"`
	Parent  *string `json:"parentId,omitempty"`
	Shared  bool    `json:"shared,omitempty"`
}

func runLs(cmd *cobra.Command, args []string) error {
	client, sess, cleanup, err := requireSessionFull()
	if err != nil {
		return err
	}
	defer cleanup()

	masterKey, err := sess.MasterKeyBytes()
	if err != nil {
		return err
	}

	cols, err := client.ListCollections()
	if err != nil {
		return err
	}
	decryptedCols := decryptCollections(cols, masterKey, sess)

	var filterParent *string
	if len(args) == 1 {
		id := args[0]
		filterParent = &id
	}

	if lsTree && filterParent == nil {
		printColTree(decryptedCols, "", 0)
		return nil
	}

	var entries []lsEntry
	for _, col := range decryptedCols {
		if filterParent == nil {
			if col.ParentCollectionID != nil {
				continue
			}
		} else {
			if col.ParentCollectionID == nil || *col.ParentCollectionID != *filterParent {
				continue
			}
		}
		entries = append(entries, lsEntry{
			ID:     col.ID,
			Type:   "folder",
			Name:   col.Name,
			Parent: col.ParentCollectionID,
			Shared: col.IsShared,
		})
	}

	if filterParent != nil {
		col := findCollection(decryptedCols, *filterParent)
		if col != nil {
			colKey, err := decryptCollectionKey(col, masterKey, sess)
			if err == nil {
				files, _ := client.ListFiles(col.ID)
				for _, f := range files {
					name, size := decryptFileMeta(&f, colKey)
					entries = append(entries, lsEntry{
						ID:      f.ID,
						Type:    "file",
						Name:    name,
						Size:    size,
						Created: formatTime(f.CreatedAt),
					})
				}
			}
		}
	}

	if jsonOut {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(entries)
	}

	for _, e := range entries {
		if e.Type == "folder" {
			shared := ""
			if e.Shared {
				shared = " [shared]"
			}
			fmt.Printf("📁  %-38s  %s%s\n", e.Name, e.ID, shared)
		} else {
			fmt.Printf("    %-38s  %s  %s  %s\n", e.Name, e.ID, formatBytes(e.Size), e.Created)
		}
	}
	return nil
}

func printColTree(cols []api.Collection, parentID string, depth int) {
	prefix := ""
	for i := 0; i < depth; i++ {
		prefix += "  "
	}
	for _, col := range cols {
		pID := ""
		if col.ParentCollectionID != nil {
			pID = *col.ParentCollectionID
		}
		if pID != parentID {
			continue
		}
		fmt.Printf("%s📁  %s  (%s)\n", prefix, col.Name, col.ID)
		printColTree(cols, col.ID, depth+1)
	}
}
