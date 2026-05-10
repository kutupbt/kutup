package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/kutupbulut/kutup/cmd/kutup/internal/api"
	"github.com/kutupbulut/kutup/cmd/kutup/internal/crypto"
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

			// Try the latest snapshot version first; fall back to the main
			// /files/:id/download blob if no versions exist. Mirrors
			// frontend/src/pages/FileEditorPage.tsx:170-188 — necessary
			// because the main blob holds only the cold-start state for
			// any collab-edited file (notes / office / whiteboard). The
			// version_size assertion (meta.Size >= 0) holds for the latest
			// snapshot too: snapshot blobs are stream-encrypted with the
			// same per-file key + format as the main blob.
			encrypted, fromVersion, err := client.LatestEncryptedBytes(fileID)
			if err != nil {
				return fmt.Errorf("download: %w", err)
			}
			_ = bar.Add64(int64(len(encrypted)))

			plaintext, err := crypto.DecryptStream(encrypted, fileKey)
			if err != nil {
				return fmt.Errorf("decrypt: %w", err)
			}

			// Integrity check (only meaningful for the cold-start blob;
			// snapshot bytes carry their own size in file_versions.size_bytes
			// and may differ from the file's original meta.Size).
			if !fromVersion && meta.Size > 0 && int64(len(plaintext)) != meta.Size {
				return fmt.Errorf("size mismatch: expected %d bytes, got %d", meta.Size, len(plaintext))
			}

			// Whiteboard asset hydration: if this is a .excalidraw and any
			// image element references a fileId whose dataURL isn't inline
			// in the saved JSON, fetch the corresponding asset blob from
			// /assets/:assetId, decrypt with the per-file content key, and
			// patch it inline so the on-disk file is self-contained.
			if isExcalidraw(meta.Name) {
				patched, hydErr := hydrateWhiteboardAssets(client, fileID, masterKey, plaintext, colKey, fileKey)
				if hydErr != nil {
					// Non-fatal: warn, write the partially-functional blob.
					fmt.Fprintf(os.Stderr, "warn: asset hydration failed: %v\n", hydErr)
				} else if patched != nil {
					plaintext = patched
				}
			}

			destPath := destDir
			if fi, err := os.Stat(destDir); err == nil && fi.IsDir() {
				destPath = filepath.Join(destDir, meta.Name)
			}
			if err := os.WriteFile(destPath, plaintext, 0644); err != nil {
				return fmt.Errorf("write file: %w", err)
			}

			if jsonOut {
				fmt.Printf(`{"id":%q,"name":%q,"size":%d,"dest":%q,"fromVersion":%t}`+"\n",
					fileID, meta.Name, len(plaintext), destPath, fromVersion)
			} else {
				suffix := ""
				if fromVersion {
					suffix = " (latest snapshot)"
				}
				fmt.Printf("Downloaded %s → %s%s\n", meta.Name, destPath, suffix)
			}
			return nil
		}
	}

	return fmt.Errorf("file %s not found in any accessible collection", fileID)
}

func isExcalidraw(name string) bool {
	return strings.HasSuffix(strings.ToLower(name), ".excalidraw")
}

// hydrateWhiteboardAssets parses the .excalidraw JSON, finds image
// elements with status "saved" whose corresponding files[fileId].dataURL
// is missing, fetches each asset blob via the API + decrypts it, and
// inlines the dataURL. Returns the patched JSON bytes, or nil if no
// hydration was needed (current web saves are self-contained, so this is
// usually a no-op).
//
// Errors fetching individual assets are non-fatal — the function returns
// the bytes patched as far as it could, and the caller surfaces a warning.
//
// `colKey` is the collection master key (used for the asset HKDF). For
// kutup, file content keys are derived from the COLLECTION master key,
// not the per-file file_key — see frontend/src/collab/cryptoFrame.ts.
// hkdf input is fileID (the parent file UUID).
func hydrateWhiteboardAssets(
	client *api.Client,
	fileID string,
	masterKey []byte,
	jsonBytes []byte,
	colKey []byte,
	fileKey []byte,
) ([]byte, error) {
	_ = masterKey
	_ = fileKey
	// Parse loosely — preserve unknown fields by round-tripping through a
	// raw map. Excalidraw JSON has elements + appState + files (the binary
	// map). We only touch files.
	var doc map[string]any
	if err := json.Unmarshal(jsonBytes, &doc); err != nil {
		return nil, fmt.Errorf("parse excalidraw json: %w", err)
	}
	rawFiles, _ := doc["files"].(map[string]any)
	rawElements, _ := doc["elements"].([]any)
	if rawFiles == nil || rawElements == nil {
		return nil, nil
	}

	// Find all image-element fileIds that have status="saved" but no
	// inline dataURL in files[fileId].
	missing := map[string]struct{}{}
	for _, e := range rawElements {
		em, ok := e.(map[string]any)
		if !ok {
			continue
		}
		if em["type"] != "image" || em["status"] != "saved" {
			continue
		}
		fid, _ := em["fileId"].(string)
		if fid == "" {
			continue
		}
		entry, _ := rawFiles[fid].(map[string]any)
		if entry == nil {
			missing[fid] = struct{}{}
			continue
		}
		dataURL, _ := entry["dataURL"].(string)
		if dataURL == "" {
			missing[fid] = struct{}{}
		}
	}
	if len(missing) == 0 {
		return nil, nil
	}

	// Asset blobs are encrypted with the per-file content key derived
	// from the COLLECTION master key (HKDF info=fileID). The CLI's
	// concept of "collection key" is the unwrapped collection master.
	mimeRE := regexp.MustCompile(`^data:([^;]+);`)
	for assetID := range missing {
		blob, err := client.DownloadAsset(fileID, assetID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: skip asset %s: %v\n", assetID, err)
			continue
		}
		plain, err := crypto.DecryptAsset(blob, fileID, assetID, colKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: decrypt asset %s: %v\n", assetID, err)
			continue
		}
		dataURL := string(plain)
		mime := "image/png"
		if m := mimeRE.FindStringSubmatch(dataURL); m != nil {
			mime = m[1]
		}
		rawFiles[assetID] = map[string]any{
			"id":       assetID,
			"mimeType": mime,
			"dataURL":  dataURL,
			"created":  0,
		}
	}
	doc["files"] = rawFiles
	out, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("re-encode excalidraw json: %w", err)
	}
	return out, nil
}
