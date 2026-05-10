package cmd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kutupbulut/kutup/cmd/kutup/internal/api"
	"github.com/kutupbulut/kutup/cmd/kutup/internal/crypto"
	"github.com/kutupbulut/kutup/cmd/kutup/internal/session"
	"github.com/spf13/cobra"
)

var shareFilesCmd = &cobra.Command{
	Use:   "files <share-id>",
	Short: "List files inside an accepted federated share",
	Args:  cobra.ExactArgs(1),
	RunE:  runShareFiles,
}

var shareDownloadCmd = &cobra.Command{
	Use:   "download <share-id> <file-id> [dest]",
	Short: "Download a file from a federated share",
	Args:  cobra.RangeArgs(2, 3),
	RunE:  runShareDownload,
}

func init() {
	shareCmd.AddCommand(shareFilesCmd)
	shareCmd.AddCommand(shareDownloadCmd)
}

// resolveSharedCollectionKey looks up a federated share by id, unwraps
// its sealed-boxed collection key, and returns the unwrapped key bytes.
// Used by both share files and share download — the share's collection
// key is what wraps the file_keys inside.
func resolveSharedCollectionKey(client *api.Client, sess *session.Session, shareID string) (*api.IncomingShare, []byte, error) {
	shares, err := client.ListIncomingShares()
	if err != nil {
		return nil, nil, err
	}
	var match *api.IncomingShare
	for i := range shares {
		if shares[i].ID == shareID {
			match = &shares[i]
			break
		}
	}
	if match == nil {
		return nil, nil, fmt.Errorf("share %s not in your accepted shares (run `kutup share incoming list`)", shareID)
	}
	colKey, err := unwrapSharedCollectionKey(*match, sess)
	if err != nil {
		return nil, nil, err
	}
	return match, colKey, nil
}

func unwrapSharedCollectionKey(s api.IncomingShare, sess *session.Session) ([]byte, error) {
	encColKey, err := base64.StdEncoding.DecodeString(s.EncryptedCollectionKey)
	if err != nil {
		return nil, fmt.Errorf("collection key base64: %w", err)
	}
	priv, err := sess.PrivateKeyBytes()
	if err != nil {
		return nil, err
	}
	pub, err := sess.PublicKeyBytes()
	if err != nil {
		return nil, err
	}
	colKey, err := crypto.OpenAnonymous(encColKey, pub, priv)
	if err != nil {
		return nil, fmt.Errorf("unseal collection key: %w", err)
	}
	return colKey, nil
}

func runShareFiles(_ *cobra.Command, args []string) error {
	shareID := args[0]

	client, sess, cleanup, err := requireSessionFull()
	if err != nil {
		return err
	}
	defer cleanup()

	_, colKey, err := resolveSharedCollectionKey(client, sess, shareID)
	if err != nil {
		return err
	}

	files, err := client.ProxyListFiles(shareID)
	if err != nil {
		return err
	}

	type display struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Size int64  `json:"size,omitempty"`
	}
	out := make([]display, 0, len(files))
	for _, f := range files {
		fileKey, err := crypto.SecretBoxOpenB64(f.EncryptedFileKey, f.FileKeyNonce, colKey)
		if err != nil {
			out = append(out, display{ID: f.ID, Name: "(undecryptable)"})
			continue
		}
		metaBytes, err := crypto.SecretBoxOpenB64(f.EncryptedMetadata, f.MetadataNonce, fileKey)
		if err != nil {
			out = append(out, display{ID: f.ID, Name: "(metadata-undecryptable)"})
			continue
		}
		var meta struct {
			Name string `json:"name"`
			Size int64  `json:"size"`
		}
		_ = json.Unmarshal(metaBytes, &meta)
		out = append(out, display{ID: f.ID, Name: meta.Name, Size: meta.Size})
	}

	if jsonOut {
		b, _ := json.Marshal(out)
		fmt.Println(string(b))
		return nil
	}
	if len(out) == 0 {
		fmt.Println("(no files in this share)")
		return nil
	}
	fmt.Printf("%-36s  %12s  %s\n", "ID", "SIZE", "NAME")
	for _, d := range out {
		fmt.Printf("%-36s  %12d  %s\n", d.ID, d.Size, d.Name)
	}
	return nil
}

func runShareDownload(_ *cobra.Command, args []string) error {
	shareID := args[0]
	fileID := args[1]
	destDir := "."
	if len(args) == 3 {
		destDir = args[2]
	}

	client, sess, cleanup, err := requireSessionFull()
	if err != nil {
		return err
	}
	defer cleanup()

	_, colKey, err := resolveSharedCollectionKey(client, sess, shareID)
	if err != nil {
		return err
	}

	files, err := client.ProxyListFiles(shareID)
	if err != nil {
		return err
	}
	var target *api.File
	for i := range files {
		if files[i].ID == fileID {
			target = &files[i]
			break
		}
	}
	if target == nil {
		return fmt.Errorf("file %s not found in share %s", fileID, shareID)
	}

	fileKey, err := crypto.SecretBoxOpenB64(target.EncryptedFileKey, target.FileKeyNonce, colKey)
	if err != nil {
		return fmt.Errorf("decrypt file key: %w", err)
	}
	metaBytes, err := crypto.SecretBoxOpenB64(target.EncryptedMetadata, target.MetadataNonce, fileKey)
	if err != nil {
		return fmt.Errorf("decrypt metadata: %w", err)
	}
	var meta struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal(metaBytes, &meta)

	encrypted, err := client.ProxyDownload(shareID, fileID)
	if err != nil {
		return err
	}
	plain, err := crypto.DecryptStream(encrypted, fileKey)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}

	destPath := destDir
	if fi, err := os.Stat(destDir); err == nil && fi.IsDir() {
		destPath = filepath.Join(destDir, meta.Name)
	}
	if err := os.WriteFile(destPath, plain, 0644); err != nil {
		return err
	}
	if jsonOut {
		fmt.Printf(`{"shareId":%q,"fileId":%q,"size":%d,"dest":%q}`+"\n",
			shareID, fileID, len(plain), destPath)
	} else {
		fmt.Printf("Downloaded %s → %s\n", meta.Name, destPath)
	}
	return nil
}
