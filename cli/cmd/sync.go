package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	kutupSync "github.com/alperen-albayrak/kutup/cli/internal/sync"
	"github.com/fsnotify/fsnotify"
	"github.com/spf13/cobra"
)

var syncWatch bool

var syncCmd = &cobra.Command{
	Use:   "sync <local-dir> <collection-id>",
	Short: "Bidirectional sync between a local directory and a remote collection",
	Args:  cobra.ExactArgs(2),
	RunE:  runSync,
}

func init() {
	syncCmd.Flags().BoolVar(&syncWatch, "watch", false, "stay running and sync on file changes")
}

func runSync(cmd *cobra.Command, args []string) error {
	localDir := args[0]
	collectionID := args[1]

	if err := os.MkdirAll(localDir, 0755); err != nil {
		return fmt.Errorf("create local dir: %w", err)
	}

	if !syncWatch {
		return doSync(localDir, collectionID)
	}

	// Initial sync before entering watch loop
	if err := doSync(localDir, collectionID); err != nil {
		fmt.Fprintf(os.Stderr, "sync error: %v\n", err)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("watcher: %w", err)
	}
	defer watcher.Close()

	if err := watcher.Add(localDir); err != nil {
		return fmt.Errorf("watch dir: %w", err)
	}

	fmt.Printf("Watching %s for changes… (Ctrl+C to stop)\n", localDir)

	// Debounce: wait 2s after the last event before syncing again
	var debounce *time.Timer
	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			base := filepath.Base(event.Name)
			if len(base) > 0 && (base[0] == '.' || base[len(base)-1] == '~') {
				continue // skip hidden/temp files
			}
			if debounce != nil {
				debounce.Stop()
			}
			debounce = time.AfterFunc(2*time.Second, func() {
				fmt.Printf("\nChange detected, syncing…\n")
				if err := doSync(localDir, collectionID); err != nil {
					fmt.Fprintf(os.Stderr, "sync error: %v\n", err)
				}
			})
		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			fmt.Fprintf(os.Stderr, "watcher error: %v\n", err)
		}
	}
}

func doSync(localDir, collectionID string) error {
	// requireSessionWithStore opens BoltDB once; we pass the same store to the
	// sync engine to avoid a second open (BoltDB is single-writer).
	client, sess, store, cleanup, err := requireSessionWithStore()
	if err != nil {
		return err
	}
	defer cleanup()

	result, err := kutupSync.Sync(client, store, sess, localDir, collectionID)
	if err != nil {
		return err
	}

	fmt.Printf("Sync complete: ↑ %d uploaded, ↓ %d downloaded, ⚠ %d conflicts\n",
		result.Uploaded, result.Downloaded, result.Conflicts)

	for _, e := range result.Errors {
		fmt.Fprintf(os.Stderr, "  error: %v\n", e)
	}
	return nil
}
