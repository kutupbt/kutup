package cmd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/alperen-albayrak/kutup/cli/internal/api"
	"github.com/alperen-albayrak/kutup/cli/internal/crypto"
	"github.com/spf13/cobra"
)

var versionsCmd = &cobra.Command{
	Use:   "versions",
	Short: "List, download, restore, and label snapshot versions of a file",
}

var versionsListCmd = &cobra.Command{
	Use:   "list <file-id>",
	Short: "List snapshot versions of a file (newest first)",
	Args:  cobra.ExactArgs(1),
	RunE:  runVersionsList,
}

var versionsDownloadCmd = &cobra.Command{
	Use:   "download <file-id> <version-id> [dest]",
	Short: "Download a specific snapshot version",
	Args:  cobra.RangeArgs(2, 3),
	RunE:  runVersionsDownload,
}

var versionsRestoreCmd = &cobra.Command{
	Use:   "restore <file-id> <version-id>",
	Short: "Restore a snapshot as the latest version (creates a new snapshot)",
	Args:  cobra.ExactArgs(2),
	RunE:  runVersionsRestore,
}

var (
	versionLabelKeepForever bool
)

var versionsLabelCmd = &cobra.Command{
	Use:   "label <file-id> <version-id> <label>",
	Short: "Set a label on a version (and optionally pin it via --keep-forever)",
	Args:  cobra.ExactArgs(3),
	RunE:  runVersionsLabel,
}

func init() {
	versionsLabelCmd.Flags().BoolVar(&versionLabelKeepForever, "keep-forever", false,
		"pin the version so version_cleanup never expires it")

	versionsCmd.AddCommand(versionsListCmd)
	versionsCmd.AddCommand(versionsDownloadCmd)
	versionsCmd.AddCommand(versionsRestoreCmd)
	versionsCmd.AddCommand(versionsLabelCmd)
}

func runVersionsList(_ *cobra.Command, args []string) error {
	fileID := args[0]
	client, _, cleanup, err := requireSessionFull()
	if err != nil {
		return err
	}
	defer cleanup()

	versions, err := client.ListVersions(fileID)
	if err != nil {
		return err
	}

	if jsonOut {
		out, _ := json.Marshal(versions)
		fmt.Println(string(out))
		return nil
	}
	if len(versions) == 0 {
		fmt.Println("(no snapshot versions for this file)")
		return nil
	}
	fmt.Printf("%-36s  %-20s  %12s  %s  %s\n", "ID", "CREATED", "SIZE", "PIN", "LABEL")
	for _, v := range versions {
		label := ""
		if v.Label != nil {
			label = *v.Label
		}
		pin := " "
		if v.KeepForever {
			pin = "★"
		}
		fmt.Printf("%-36s  %-20s  %12d  %s   %s\n",
			v.ID, v.CreatedAt.Local().Format(time.RFC3339), v.SizeBytes, pin, label)
	}
	return nil
}

func runVersionsDownload(_ *cobra.Command, args []string) error {
	fileID := args[0]
	versionID := args[1]
	destDir := "."
	if len(args) == 3 {
		destDir = args[2]
	}

	client, sess, cleanup, err := requireSessionFull()
	if err != nil {
		return err
	}
	defer cleanup()

	masterKey, err := sess.MasterKeyBytes()
	if err != nil {
		return err
	}

	// Find the file in collections to unwrap its file_key.
	row, fileKey, err := findFileAndKey(client, sess, masterKey, fileID)
	if err != nil {
		return err
	}
	metaBytes, err := crypto.SecretBoxOpenB64(row.EncryptedMetadata, row.MetadataNonce, fileKey)
	if err != nil {
		return fmt.Errorf("decrypt metadata: %w", err)
	}
	var meta struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal(metaBytes, &meta)

	encrypted, err := client.DownloadVersion(fileID, versionID)
	if err != nil {
		return err
	}
	plain, err := crypto.DecryptStream(encrypted, fileKey)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}

	destPath := destDir
	if fi, err := os.Stat(destDir); err == nil && fi.IsDir() {
		destPath = filepath.Join(destDir, fmt.Sprintf("%s.v-%s", meta.Name, versionID[:8]))
	}
	if err := os.WriteFile(destPath, plain, 0644); err != nil {
		return err
	}
	if jsonOut {
		fmt.Printf(`{"fileId":%q,"versionId":%q,"size":%d,"dest":%q}`+"\n",
			fileID, versionID, len(plain), destPath)
	} else {
		fmt.Printf("Downloaded version %s of %s → %s\n", versionID[:8], meta.Name, destPath)
	}
	return nil
}

func runVersionsRestore(_ *cobra.Command, args []string) error {
	fileID := args[0]
	versionID := args[1]

	client, sess, cleanup, err := requireSessionFull()
	if err != nil {
		return err
	}
	defer cleanup()

	masterKey, err := sess.MasterKeyBytes()
	if err != nil {
		return err
	}

	_, fileKey, err := findFileAndKey(client, sess, masterKey, fileID)
	if err != nil {
		return err
	}

	// Mirror frontend/src/pages/FileEditorPage.tsx:325-358 performBlobRestore:
	// download chosen version → decrypt → re-encrypt → POST snapshot-blob
	// → recordSnapshot with "Restored from <date>" label.
	encrypted, err := client.DownloadVersion(fileID, versionID)
	if err != nil {
		return err
	}
	old, err := crypto.DecryptStream(encrypted, fileKey)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}
	reEncrypted, err := crypto.EncryptStream(old, fileKey)
	if err != nil {
		return fmt.Errorf("re-encrypt: %w", err)
	}
	blobRes, err := client.UploadSnapshotBlob(fileID, reEncrypted)
	if err != nil {
		return err
	}
	res, err := client.RecordSnapshot(fileID, api.RecordSnapshotRequest{
		S3VersionID:   blobRes.S3VersionID,
		StoragePath:   blobRes.StoragePath,
		SeqAtSnapshot: 0,
		DocKeyID:      1,
		SizeBytes:     int64(len(reEncrypted)),
		Label:         "Restored from " + time.Now().Local().Format(time.RFC3339),
	})
	if err != nil {
		return err
	}
	if jsonOut {
		fmt.Printf(`{"fileId":%q,"newVersionId":%q,"restoredFrom":%q}`+"\n",
			fileID, res.ID, versionID)
	} else {
		fmt.Printf("Restored: file=%s new-version=%s (from %s)\n", fileID, res.ID, versionID[:8])
	}
	return nil
}

func runVersionsLabel(_ *cobra.Command, args []string) error {
	fileID := args[0]
	versionID := args[1]
	label := args[2]

	client, _, cleanup, err := requireSessionFull()
	if err != nil {
		return err
	}
	defer cleanup()

	patch := api.PatchVersionRequest{Label: &label}
	if versionLabelKeepForever {
		t := true
		patch.KeepForever = &t
	}
	row, err := client.PatchVersion(fileID, versionID, patch)
	if err != nil {
		return err
	}
	if jsonOut {
		out, _ := json.Marshal(row)
		fmt.Println(string(out))
	} else {
		fmt.Printf("Labeled version %s of file %s\n", versionID[:8], fileID)
	}
	return nil
}

// findFileAndKey locates a file row by ID across all accessible
// collections and returns the row + unwrapped file_key. Used by versions
// download / restore where the file's metadata + key are needed.
func findFileAndKey(client *api.Client, _ interface{}, masterKey []byte, fileID string) (*api.File, []byte, error) {
	cols, err := client.ListCollections()
	if err != nil {
		return nil, nil, err
	}
	for _, col := range cols {
		// Decrypt the collection key with the master key. Assumes the
		// collection isn't a federated incoming share — federation
		// versions/restore is out of scope for PR-α.
		colKeyEnc, _ := base64.StdEncoding.DecodeString(col.EncryptedKey)
		_ = colKeyEnc
		// Reuse the existing helper.
		colKey, err := crypto.SecretBoxOpenB64(col.EncryptedKey, col.EncryptedKeyNonce, masterKey)
		if err != nil {
			continue
		}
		files, err := client.ListFiles(col.ID)
		if err != nil {
			continue
		}
		for _, f := range files {
			if f.ID != fileID {
				continue
			}
			fk, err := crypto.SecretBoxOpenB64(f.EncryptedFileKey, f.FileKeyNonce, colKey)
			if err != nil {
				return nil, nil, fmt.Errorf("unwrap file key: %w", err)
			}
			return &f, fk, nil
		}
	}
	return nil, nil, fmt.Errorf("file %s not found in any accessible collection", fileID)
}
