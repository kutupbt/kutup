package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/alperen-albayrak/kutup/cli/internal/crypto"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
)

var downloadCmd = &cobra.Command{
	Use:   "download <file-id> [dest]",
	Short: "Download and decrypt a file",
	Args:  cobra.RangeArgs(1, 2),
	RunE:  runDownload,
}

func runDownload(cmd *cobra.Command, args []string) error {
	fileID := args[0]
	destDir := "."
	if len(args) == 2 {
		destDir = args[1]
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

	// Find the file in collections
	cols, err := client.ListCollections()
	if err != nil {
		return err
	}
	decryptedCols := decryptCollections(cols, masterKey, sess)

	for _, col := range decryptedCols {
		colKey, err := decryptCollectionKey(&col, masterKey, sess)
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
			// Found it
			fileKey, err := crypto.SecretBoxOpenB64(f.EncryptedFileKey, f.FileKeyNonce, colKey)
			if err != nil {
				return fmt.Errorf("decrypt file key: %w", err)
			}
			metaBytes, err := crypto.SecretBoxOpenB64(f.EncryptedMetadata, f.MetadataNonce, fileKey)
			if err != nil {
				return fmt.Errorf("decrypt metadata: %w", err)
			}
			var meta struct {
				Name string `json:"name"`
				Size int64  `json:"size"`
			}
			_ = json.Unmarshal(metaBytes, &meta)

			bar := progressbar.NewOptions64(f.EncryptedSizeBytes,
				progressbar.OptionSetDescription(meta.Name),
				progressbar.OptionSetWidth(30),
				progressbar.OptionShowBytes(true),
				progressbar.OptionClearOnFinish(),
			)

			encrypted, err := client.DownloadFile(fileID)
			if err != nil {
				return fmt.Errorf("download: %w", err)
			}
			_ = bar.Add64(int64(len(encrypted)))

			plaintext, err := crypto.DecryptStream(encrypted, fileKey)
			if err != nil {
				return fmt.Errorf("decrypt: %w", err)
			}

			// Integrity check
			if meta.Size > 0 && int64(len(plaintext)) != meta.Size {
				return fmt.Errorf("size mismatch: expected %d bytes, got %d", meta.Size, len(plaintext))
			}

			destPath := destDir
			if fi, err := os.Stat(destDir); err == nil && fi.IsDir() {
				destPath = filepath.Join(destDir, meta.Name)
			}
			if err := os.WriteFile(destPath, plaintext, 0644); err != nil {
				return fmt.Errorf("write file: %w", err)
			}

			if jsonOut {
				fmt.Printf(`{"id":%q,"name":%q,"size":%d,"dest":%q}`+"\n",
					fileID, meta.Name, len(plaintext), destPath)
			} else {
				fmt.Printf("Downloaded %s → %s\n", meta.Name, destPath)
			}
			return nil
		}
	}

	return fmt.Errorf("file %s not found in any accessible collection", fileID)
}
