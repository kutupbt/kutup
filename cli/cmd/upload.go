package cmd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/alperen-albayrak/kutup/cli/internal/api"
	"github.com/alperen-albayrak/kutup/cli/internal/crypto"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
)

var uploadRecursive bool

var uploadCmd = &cobra.Command{
	Use:   "upload <path> <collection-id>",
	Short: "Encrypt and upload a file or directory",
	Args:  cobra.ExactArgs(2),
	RunE:  runUpload,
}

func init() {
	uploadCmd.Flags().BoolVarP(&uploadRecursive, "recursive", "r", false, "upload directory recursively")
}

func runUpload(cmd *cobra.Command, args []string) error {
	localPath := args[0]
	collectionID := args[1]

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
	col := findCollection(decryptedCols, collectionID)
	if col == nil {
		return fmt.Errorf("collection %s not found", collectionID)
	}
	collectionKey, err := decryptCollectionKey(col, masterKey, sess)
	if err != nil {
		return fmt.Errorf("decrypt collection key: %w", err)
	}

	fi, err := os.Stat(localPath)
	if err != nil {
		return err
	}

	if fi.IsDir() {
		if !uploadRecursive {
			return fmt.Errorf("%s is a directory — use --recursive to upload directories", localPath)
		}
		return uploadDir(client, localPath, collectionID, masterKey)
	}

	id, err := uploadSingleFile(client, localPath, collectionID, collectionKey)
	if err != nil {
		return err
	}
	if jsonOut {
		fmt.Printf(`{"id":%q,"name":%q}`+"\n", id, filepath.Base(localPath))
	} else {
		fmt.Printf("Uploaded %s  id=%s\n", filepath.Base(localPath), id)
	}
	return nil
}

// uploadDir recursively uploads a directory, creating sub-collections as needed.
func uploadDir(client *api.Client, dir, parentColID string, masterKey []byte) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	dirName := filepath.Base(dir)
	subColID, subColKey, err := createSubCollection(client, dirName, parentColID, masterKey)
	if err != nil {
		return fmt.Errorf("create sub-folder %s: %w", dirName, err)
	}

	for _, entry := range entries {
		fullPath := filepath.Join(dir, entry.Name())
		if entry.IsDir() {
			if err := uploadDir(client, fullPath, subColID, masterKey); err != nil {
				fmt.Fprintf(os.Stderr, "warning: %v\n", err)
			}
		} else {
			if _, err := uploadSingleFile(client, fullPath, subColID, subColKey); err != nil {
				fmt.Fprintf(os.Stderr, "warning: upload %s: %v\n", entry.Name(), err)
			} else {
				fmt.Printf("  ↑ %s\n", fullPath)
			}
		}
	}
	return nil
}

func createSubCollection(client *api.Client, name, parentID string, masterKey []byte) (string, []byte, error) {
	collectionKey := crypto.NewStreamKey()
	encKey, keyNonce, err := crypto.SecretBoxSeal(collectionKey, masterKey)
	if err != nil {
		return "", nil, err
	}
	encName, nameNonce, err := crypto.SecretBoxSeal([]byte(name), collectionKey)
	if err != nil {
		return "", nil, err
	}
	resp, err := client.CreateCollection(api.CreateCollectionRequest{
		EncryptedName:      base64.StdEncoding.EncodeToString(encName),
		NameNonce:          base64.StdEncoding.EncodeToString(nameNonce),
		EncryptedKey:       base64.StdEncoding.EncodeToString(encKey),
		EncryptedKeyNonce:  base64.StdEncoding.EncodeToString(keyNonce),
		ParentCollectionID: &parentID,
	})
	if err != nil {
		return "", nil, err
	}
	return resp.ID, collectionKey, nil
}

func uploadSingleFile(client *api.Client, localPath, collectionID string, collectionKey []byte) (string, error) {
	data, err := os.ReadFile(localPath)
	if err != nil {
		return "", err
	}

	fileKey := crypto.NewStreamKey()

	bar := progressbar.NewOptions64(int64(len(data)),
		progressbar.OptionSetDescription(filepath.Base(localPath)),
		progressbar.OptionSetWidth(30),
		progressbar.OptionShowBytes(true),
		progressbar.OptionClearOnFinish(),
	)

	encrypted, err := crypto.EncryptStream(data, fileKey)
	if err != nil {
		return "", fmt.Errorf("encrypt: %w", err)
	}
	_ = bar.Add64(int64(len(data)))

	encFileKey, fileKeyNonce, err := crypto.SecretBoxSeal(fileKey, collectionKey)
	if err != nil {
		return "", fmt.Errorf("wrap file key: %w", err)
	}

	meta := api.FileMetadata{
		Name:     filepath.Base(localPath),
		MimeType: guessMIMEFromPath(localPath),
		Size:     int64(len(data)),
	}
	metaBytes, _ := json.Marshal(meta)
	encMeta, metaNonce, err := crypto.SecretBoxSeal(metaBytes, fileKey)
	if err != nil {
		return "", fmt.Errorf("encrypt metadata: %w", err)
	}

	resp, err := client.UploadFile(
		collectionID,
		base64.StdEncoding.EncodeToString(encMeta),
		base64.StdEncoding.EncodeToString(metaNonce),
		base64.StdEncoding.EncodeToString(encFileKey),
		base64.StdEncoding.EncodeToString(fileKeyNonce),
		encrypted,
	)
	if err != nil {
		return "", fmt.Errorf("upload: %w", err)
	}
	return resp.ID, nil
}

func guessMIMEFromPath(path string) string {
	switch filepath.Ext(path) {
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".png":
		return "image/png"
	case ".gif":
		return "image/gif"
	case ".pdf":
		return "application/pdf"
	case ".txt":
		return "text/plain"
	case ".mp4":
		return "video/mp4"
	case ".mp3":
		return "audio/mpeg"
	case ".zip":
		return "application/zip"
	default:
		return "application/octet-stream"
	}
}
