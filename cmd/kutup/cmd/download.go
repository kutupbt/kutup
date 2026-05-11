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
	"github.com/kutupbulut/kutup/cmd/kutup/internal/download"
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

			destPath := destDir
			if fi, err := os.Stat(destDir); err == nil && fi.IsDir() {
				destPath = filepath.Join(destDir, meta.Name)
			}

			// Streaming download path: pull the encrypted body in 5 MB
			// frames and decrypt straight to disk. Replaces the previous
			// `LatestEncryptedBytes → DecryptStream(buffer)` pattern that
			// held the full ciphertext AND plaintext in RAM. Memory peak
			// is now ~10 MB regardless of file size.
			//
			// Same fallback as before: prefer the newest version snapshot
			// (collab-edited files only carry their post-load state there),
			// fall back to the main /files/:id/download blob otherwise.
			rc, fromVersion, err := client.LatestEncryptedStream(fileID)
			if err != nil {
				return fmt.Errorf("download: %w", err)
			}
			defer rc.Close()

			out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
			if err != nil {
				return fmt.Errorf("open dest: %w", err)
			}
			plainWritten, derr := download.Stream(rc, fileKey, out, func(n int64) {
				_ = bar.Set64(n)
			})
			if cerr := out.Close(); cerr != nil && derr == nil {
				derr = cerr
			}
			if derr != nil {
				_ = os.Remove(destPath)
				return fmt.Errorf("decrypt-write: %w", derr)
			}

			// Integrity check (only meaningful for the cold-start blob;
			// snapshot bytes carry their own size in file_versions.size_bytes
			// and may differ from the file's original meta.Size).
			if !fromVersion && meta.Size > 0 && plainWritten != meta.Size {
				_ = os.Remove(destPath)
				return fmt.Errorf("size mismatch: expected %d bytes, got %d", meta.Size, plainWritten)
			}

			// Whiteboard asset hydration: a .excalidraw written above may
			// reference assets stored separately as /assets/<id> blobs.
			// hydrateWhiteboardAssets parses the JSON, fetches each missing
			// blob, and patches it inline. We read the just-written file
			// back into RAM for this — Excalidraw files are small in
			// practice (a few MB even with images), so the temporary
			// non-streaming step is acceptable here.
			if isExcalidraw(meta.Name) {
				plaintext, rerr := os.ReadFile(destPath)
				if rerr == nil {
					patched, hydErr := hydrateWhiteboardAssets(client, fileID, masterKey, plaintext, colKey, fileKey)
					if hydErr != nil {
						fmt.Fprintf(os.Stderr, "warn: asset hydration failed: %v\n", hydErr)
					} else if patched != nil {
						if werr := os.WriteFile(destPath, patched, 0644); werr != nil {
							fmt.Fprintf(os.Stderr, "warn: rewrite after hydration failed: %v\n", werr)
						}
						plainWritten = int64(len(patched))
					}
				}
			}

			if jsonOut {
				fmt.Printf(`{"id":%q,"name":%q,"size":%d,"dest":%q,"fromVersion":%t}`+"\n",
					fileID, meta.Name, plainWritten, destPath, fromVersion)
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
