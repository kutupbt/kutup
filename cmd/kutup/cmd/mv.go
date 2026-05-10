package cmd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/kutupbulut/kutup/cmd/kutup/internal/api"
	"github.com/kutupbulut/kutup/cmd/kutup/internal/crypto"
	"github.com/spf13/cobra"
)

var mvCmd = &cobra.Command{
	Use:   "mv <file-id> <new-name>",
	Short: "Rename a file (re-encrypts metadata; content untouched)",
	Args:  cobra.ExactArgs(2),
	RunE:  runMv,
}

func runMv(_ *cobra.Command, args []string) error {
	fileID := args[0]
	newName := args[1]

	client, sess, cleanup, err := requireSessionFull()
	if err != nil {
		return err
	}
	defer cleanup()

	masterKey, err := sess.MasterKeyBytes()
	if err != nil {
		return err
	}

	// Find the file + unwrap its file_key, then re-encrypt the
	// {name, mimeType, size} JSON with that key. Mirrors the web rename
	// flow at frontend/src/pages/FileEditorPage.tsx:240 (decrypt-old +
	// merge new fields + re-encrypt).
	row, fileKey, err := findFileAndKey(client, sess, masterKey, fileID)
	if err != nil {
		return err
	}

	// Read existing metadata to preserve mimeType + size.
	metaBytes, err := crypto.SecretBoxOpenB64(row.EncryptedMetadata, row.MetadataNonce, fileKey)
	if err != nil {
		return fmt.Errorf("decrypt existing metadata: %w", err)
	}
	var meta api.FileMetadata
	_ = json.Unmarshal(metaBytes, &meta)
	meta.Name = newName

	updatedBytes, _ := json.Marshal(meta)
	encMeta, metaNonce, err := crypto.SecretBoxSeal(updatedBytes, fileKey)
	if err != nil {
		return fmt.Errorf("encrypt new metadata: %w", err)
	}

	if err := client.UpdateFileMetadata(fileID, api.UpdateFileMetadataRequest{
		EncryptedMetadata: base64.StdEncoding.EncodeToString(encMeta),
		MetadataNonce:     base64.StdEncoding.EncodeToString(metaNonce),
	}); err != nil {
		return err
	}

	if jsonOut {
		fmt.Printf(`{"id":%q,"name":%q}`+"\n", fileID, newName)
	} else {
		fmt.Printf("Renamed file %s → %s\n", fileID, newName)
	}
	return nil
}
