package cmd

import (
	"encoding/base64"
	"fmt"

	"github.com/kutupbulut/kutup/cmd/kutup/internal/api"
	"github.com/kutupbulut/kutup/cmd/kutup/internal/crypto"
	"github.com/spf13/cobra"
)

var mkdirParent string

var mkdirCmd = &cobra.Command{
	Use:   "mkdir <name>",
	Short: "Create a new folder",
	Args:  cobra.ExactArgs(1),
	RunE:  runMkdir,
}

func init() {
	mkdirCmd.Flags().StringVar(&mkdirParent, "parent", "", "parent folder ID (for nested folder)")
}

func runMkdir(cmd *cobra.Command, args []string) error {
	name := args[0]

	client, sess, cleanup, err := requireSessionFull()
	if err != nil {
		return err
	}
	defer cleanup()

	masterKey, err := sess.MasterKeyBytes()
	if err != nil {
		return err
	}

	// Generate a new random collection key
	collectionKey := crypto.NewStreamKey()

	// Encrypt collection key with master key
	encKey, keyNonce, err := crypto.SecretBoxSeal(collectionKey, masterKey)
	if err != nil {
		return fmt.Errorf("encrypt collection key: %w", err)
	}

	// Encrypt folder name with collection key
	encName, nameNonce, err := crypto.SecretBoxSeal([]byte(name), collectionKey)
	if err != nil {
		return fmt.Errorf("encrypt name: %w", err)
	}

	req := api.CreateCollectionRequest{
		EncryptedName:     base64.StdEncoding.EncodeToString(encName),
		NameNonce:         base64.StdEncoding.EncodeToString(nameNonce),
		EncryptedKey:      base64.StdEncoding.EncodeToString(encKey),
		EncryptedKeyNonce: base64.StdEncoding.EncodeToString(keyNonce),
	}
	if mkdirParent != "" {
		req.ParentCollectionID = &mkdirParent
	}

	resp, err := client.CreateCollection(req)
	if err != nil {
		return fmt.Errorf("create folder: %w", err)
	}

	if jsonOut {
		fmt.Printf(`{"id":%q,"name":%q}`+"\n", resp.ID, name)
		return nil
	}
	fmt.Printf("Created folder %q  id=%s\n", name, resp.ID)
	return nil
}
