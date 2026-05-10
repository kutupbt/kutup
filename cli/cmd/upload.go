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

	// Whiteboard asset extraction. Mirrors web's first-open behavior
	// (WhiteboardEditor.maybeUploadDirtyAssets): for every image element
	// referenced by an inline dataURL, encrypt the binary as an asset blob
	// + upload + flip element status to "saved" + commit a fresh snapshot.
	// The result: the freshly-uploaded whiteboard is ready for live collab
	// without the web needing to re-upload its assets on first open.
	if isExcalidraw(localPath) {
		if assetErr := extractAndUploadWhiteboardAssets(client, id, collectionKey, localPath); assetErr != nil {
			fmt.Fprintf(os.Stderr, "warn: asset extraction failed: %v\n", assetErr)
		}
	}

	if jsonOut {
		fmt.Printf(`{"id":%q,"name":%q}`+"\n", id, filepath.Base(localPath))
	} else {
		fmt.Printf("Uploaded %s  id=%s\n", filepath.Base(localPath), id)
	}
	return nil
}

// extractAndUploadWhiteboardAssets walks the .excalidraw on disk, uploads
// every embedded image binary as an encrypted asset, flips the matching
// image element to status="saved", and commits a fresh snapshot
// containing the modified scene. Best-effort: errors are logged, the
// happy-path main upload is preserved either way.
func extractAndUploadWhiteboardAssets(client *api.Client, fileID string, collectionKey []byte, localPath string) error {
	raw, err := os.ReadFile(localPath)
	if err != nil {
		return fmt.Errorf("re-read excalidraw: %w", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("parse excalidraw json: %w", err)
	}
	rawFiles, _ := doc["files"].(map[string]any)
	rawElements, _ := doc["elements"].([]any)
	if rawFiles == nil || rawElements == nil {
		return nil
	}

	// Map fileId → entry for quick lookup.
	uploaded := 0
	for _, e := range rawElements {
		em, ok := e.(map[string]any)
		if !ok {
			continue
		}
		if em["type"] != "image" {
			continue
		}
		assetID, _ := em["fileId"].(string)
		if assetID == "" {
			continue
		}
		entry, _ := rawFiles[assetID].(map[string]any)
		if entry == nil {
			continue
		}
		dataURL, _ := entry["dataURL"].(string)
		if dataURL == "" {
			continue
		}

		ciphertext, encErr := crypto.EncryptAsset([]byte(dataURL), fileID, assetID, collectionKey)
		if encErr != nil {
			fmt.Fprintf(os.Stderr, "warn: asset %s encrypt: %v\n", assetID, encErr)
			continue
		}
		if upErr := client.UploadAsset(fileID, assetID, ciphertext); upErr != nil {
			fmt.Fprintf(os.Stderr, "warn: asset %s upload: %v\n", assetID, upErr)
			continue
		}
		// Flip status; bump version + versionNonce so reconcileElements on
		// the receiving side picks the change up. Mirrors
		// frontend/src/components/editors/whiteboard/WhiteboardEditor.tsx:
		// flipImageStatus.
		em["status"] = "saved"
		v, _ := em["version"].(float64)
		em["version"] = v + 1
		em["versionNonce"] = float64(time.Now().UnixNano() & 0x7fffffff)
		em["updated"] = float64(time.Now().UnixMilli())
		uploaded++
	}

	if uploaded == 0 {
		return nil
	}

	// Re-encode the modified scene + commit a fresh snapshot. The web
	// reads the latest snapshot on file open (FileEditorPage.tsx:170-188),
	// so the status="saved" flip propagates correctly.
	out, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("re-encode excalidraw json: %w", err)
	}
	// Re-derive the file key from the file's own row — we already have
	// collectionKey, but the file stores its own AEAD key wrapped under
	// the collection key. Easiest path: re-list the file to get the
	// wrapped fileKey + nonce. Or: snapshot blobs are stream-encrypted
	// with file_key (matches main blob); we have file_key implicitly via
	// the upload step but not exposed. Cheap hack: list files in the
	// collection to find ours and unwrap.
	files, err := listFilesContainingID(client, fileID, collectionKey)
	if err != nil {
		return fmt.Errorf("re-fetch file key: %w", err)
	}
	encrypted, err := crypto.EncryptStream(out, files.fileKey)
	if err != nil {
		return fmt.Errorf("encrypt snapshot: %w", err)
	}
	blobRes, err := client.UploadSnapshotBlob(fileID, encrypted)
	if err != nil {
		return fmt.Errorf("upload snapshot blob: %w", err)
	}
	if _, err := client.RecordSnapshot(fileID, api.RecordSnapshotRequest{
		S3VersionID:   blobRes.S3VersionID,
		StoragePath:   blobRes.StoragePath,
		SeqAtSnapshot: 0,
		DocKeyID:      1,
		SizeBytes:     int64(len(encrypted)),
	}); err != nil {
		return fmt.Errorf("record snapshot: %w", err)
	}
	if !jsonOut {
		fmt.Printf("  + uploaded %d image asset(s) and re-snapshotted\n", uploaded)
	}
	return nil
}

// listFilesContainingID is a small lookup helper: given a fileID and the
// collection key, find the file row + unwrap its file_key. Used by the
// post-upload whiteboard re-snapshot path.
type fileRowWithKey struct {
	row     api.File
	fileKey []byte
}

func listFilesContainingID(client *api.Client, fileID string, collectionKey []byte) (*fileRowWithKey, error) {
	cols, err := client.ListCollections()
	if err != nil {
		return nil, err
	}
	for _, col := range cols {
		files, err := client.ListFiles(col.ID)
		if err != nil {
			continue
		}
		for _, f := range files {
			if f.ID != fileID {
				continue
			}
			fk, err := crypto.SecretBoxOpenB64(f.EncryptedFileKey, f.FileKeyNonce, collectionKey)
			if err != nil {
				return nil, fmt.Errorf("unwrap file key: %w", err)
			}
			return &fileRowWithKey{row: f, fileKey: fk}, nil
		}
	}
	return nil, fmt.Errorf("file %s not found after upload", fileID)
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
