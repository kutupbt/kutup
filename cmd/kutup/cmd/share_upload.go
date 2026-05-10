package cmd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kutupbulut/kutup/cmd/kutup/internal/api"
	"github.com/kutupbulut/kutup/cmd/kutup/internal/crypto"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
)

var shareUploadCmd = &cobra.Command{
	Use:   "upload <share-id> <path>",
	Short: "Upload a file to a federated share you've accepted",
	Long: `Upload a local file to a federated share you've accepted via
` + "`kutup share incoming accept`" + `.

The file is encrypted client-side under the share's collection key
(unwrapped from the sealed-box invite) before being multipart-posted to
the local fed-proxy endpoint, which forwards it to the remote server.

The share must have can_upload=true; otherwise the remote rejects with
403. Federated shares are flat — sub-folders aren't supported, so passing
a directory is rejected client-side before any encryption.`,
	Args: cobra.ExactArgs(2),
	RunE: runShareUpload,
}

func init() {
	shareCmd.AddCommand(shareUploadCmd)
}

func runShareUpload(_ *cobra.Command, args []string) error {
	shareID := args[0]
	localPath := args[1]

	// Pre-flight: directory rejection. Federated shares are flat (single
	// collection_id, no parent traversal — backend/db/migrations/
	// 010_federation.up.sql). Recursive upload would silently flatten the
	// tree, which surprises users. Refuse explicitly.
	fi, err := os.Stat(localPath)
	if err != nil {
		return err
	}
	if fi.IsDir() {
		return fmt.Errorf("federated shares are flat (no sub-folders) — upload one file at a time")
	}

	client, sess, cleanup, err := requireSessionFull()
	if err != nil {
		return err
	}
	defer cleanup()

	share, colKey, err := resolveSharedCollectionKey(client, sess, shareID)
	if err != nil {
		return err
	}

	// Pre-flight: permission check. Surfaced before we burn the
	// encryption round on a forbidden share.
	if !share.CanUpload {
		return fmt.Errorf("share %s doesn't permit uploads (request can_upload from the owner)", shareID)
	}

	data, err := os.ReadFile(localPath)
	if err != nil {
		return fmt.Errorf("read local file: %w", err)
	}

	bar := progressbar.NewOptions64(int64(len(data)),
		progressbar.OptionSetDescription("↑ "+filepath.Base(localPath)),
		progressbar.OptionSetWidth(30),
		progressbar.OptionShowBytes(true),
		progressbar.OptionClearOnFinish(),
	)

	fileKey := crypto.NewStreamKey()
	encrypted, err := crypto.EncryptStream(data, fileKey)
	if err != nil {
		return fmt.Errorf("encrypt content: %w", err)
	}
	_ = bar.Add64(int64(len(data)))

	// Wrap the new file_key under the share's UNWRAPPED collection key
	// (recovered via sealed-box from our keypair). This is the single
	// crypto difference from local upload — locally, we'd wrap under our
	// own collection key.
	encFileKey, fileKeyNonce, err := crypto.SecretBoxSeal(fileKey, colKey)
	if err != nil {
		return fmt.Errorf("wrap file key: %w", err)
	}

	meta := api.FileMetadata{
		Name:     filepath.Base(localPath),
		MimeType: guessMIMEFromPath(localPath),
		Size:     int64(len(data)),
	}
	metaBytes, _ := json.Marshal(meta)
	encMeta, metaNonce, err := crypto.SecretBoxSeal(metaBytes, fileKey)
	if err != nil {
		return fmt.Errorf("encrypt metadata: %w", err)
	}

	resp, err := client.ProxyUploadFile(
		shareID,
		base64.StdEncoding.EncodeToString(encMeta),
		base64.StdEncoding.EncodeToString(metaNonce),
		base64.StdEncoding.EncodeToString(encFileKey),
		base64.StdEncoding.EncodeToString(fileKeyNonce),
		encrypted,
	)
	if err != nil {
		// Translate the most common server-side rejections to actionable
		// CLI messages; the original "HTTP nnn: ..." error is preserved
		// in the wrapped suffix for diagnostic.
		msg := err.Error()
		switch {
		case strings.Contains(msg, "HTTP 403"):
			return fmt.Errorf("share doesn't permit uploads (server: %s)", msg)
		case strings.Contains(msg, "HTTP 413"):
			return fmt.Errorf("share upload quota exceeded (server: %s)", msg)
		default:
			return fmt.Errorf("upload: %w", err)
		}
	}

	if jsonOut {
		fmt.Printf(`{"shareId":%q,"fileId":%q,"name":%q,"size":%d}`+"\n",
			shareID, resp.ID, meta.Name, meta.Size)
	} else {
		if resp.ID != "" {
			fmt.Printf("Uploaded %s → share %s (file %s)\n", meta.Name, shareID, resp.ID)
		} else {
			fmt.Printf("Uploaded %s → share %s\n", meta.Name, shareID)
		}
	}
	return nil
}
