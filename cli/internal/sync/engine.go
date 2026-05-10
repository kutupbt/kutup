// Sync engine: bidirectional sync between a local directory and a Kutup collection.
package sync

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/alperen-albayrak/kutup/cli/internal/api"
	"github.com/alperen-albayrak/kutup/cli/internal/crypto"
	"github.com/alperen-albayrak/kutup/cli/internal/session"
	"github.com/schollz/progressbar/v3"
)

// Result summarises a sync run.
type Result struct {
	Uploaded  int
	Downloaded int
	Conflicts int
	Errors    []error
}

func (r *Result) AddError(err error) { r.Errors = append(r.Errors, err) }

// Sync performs a bidirectional sync between localDir and a remote collection.
func Sync(
	client *api.Client,
	store *session.Store,
	sess *session.Session,
	localDir, collectionID string,
) (*Result, error) {
	result := &Result{}

	// Decrypt collection key
	masterKey, err := sess.MasterKeyBytes()
	if err != nil {
		return nil, fmt.Errorf("master key: %w", err)
	}

	// Get collection to decrypt its key
	cols, err := client.ListCollections()
	if err != nil {
		return nil, fmt.Errorf("list collections: %w", err)
	}
	var col *api.Collection
	for i := range cols {
		if cols[i].ID == collectionID {
			col = &cols[i]
			break
		}
	}
	if col == nil {
		return nil, fmt.Errorf("collection %s not found", collectionID)
	}

	collectionKey, err := crypto.SecretBoxOpenB64(col.EncryptedKey, col.EncryptedKeyNonce, masterKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt collection key: %w", err)
	}

	// Fetch remote files
	remoteFiles, err := client.ListFiles(collectionID)
	if err != nil {
		return nil, fmt.Errorf("list files: %w", err)
	}

	// Decrypt remote file metadata
	for i := range remoteFiles {
		f := &remoteFiles[i]
		fileKey, err := crypto.SecretBoxOpenB64(f.EncryptedFileKey, f.FileKeyNonce, collectionKey)
		if err != nil {
			result.AddError(fmt.Errorf("decrypt key for %s: %w", f.ID, err))
			continue
		}
		metaBytes, err := crypto.SecretBoxOpenB64(f.EncryptedMetadata, f.MetadataNonce, fileKey)
		if err != nil {
			result.AddError(fmt.Errorf("decrypt metadata for %s: %w", f.ID, err))
			continue
		}
		var meta api.FileMetadata
		if err := json.Unmarshal(metaBytes, &meta); err != nil {
			result.AddError(fmt.Errorf("parse metadata for %s: %w", f.ID, err))
			continue
		}
		f.Name = meta.Name
		f.MimeType = meta.MimeType
		f.Size = meta.Size
	}

	// Build remote index: remote ID → file
	remoteIndex := make(map[string]*api.File, len(remoteFiles))
	for i := range remoteFiles {
		if remoteFiles[i].Name != "" {
			remoteIndex[remoteFiles[i].ID] = &remoteFiles[i]
		}
	}

	// Pull: download remote files not yet synced locally
	for _, f := range remoteIndex {
		synced, _ := store.GetSyncedFile(collectionID, f.ID)
		if synced != nil {
			continue // already synced
		}
		localPath := filepath.Join(localDir, sanitizeName(f.Name))
		if err := downloadFile(client, f, collectionKey, localPath); err != nil {
			result.AddError(fmt.Errorf("download %s: %w", f.Name, err))
			continue
		}
		fi, _ := os.Stat(localPath)
		var modTime, size int64
		if fi != nil {
			modTime = fi.ModTime().Unix()
			size = fi.Size()
		}
		_ = store.SaveSyncedFile(collectionID, f.ID, &session.SyncedFile{
			LocalPath: localPath,
			Size:      size,
			ModTime:   modTime,
			SyncedAt:  time.Now().Unix(),
		})
		fmt.Printf("  ↓ %s\n", f.Name)
		result.Downloaded++
	}

	// Push: upload local files not yet in remote
	entries, err := os.ReadDir(localDir)
	if err != nil {
		return nil, fmt.Errorf("read dir: %w", err)
	}

	// Build local path → remote ID index (reverse of sync store)
	localToRemote := make(map[string]string)
	for remoteID := range remoteIndex {
		synced, _ := store.GetSyncedFile(collectionID, remoteID)
		if synced != nil {
			localToRemote[synced.LocalPath] = remoteID
		}
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		localPath := filepath.Join(localDir, entry.Name())
		if _, alreadySynced := localToRemote[localPath]; alreadySynced {
			continue
		}
		remoteID, err := uploadFile(client, localPath, collectionID, collectionKey)
		if err != nil {
			result.AddError(fmt.Errorf("upload %s: %w", entry.Name(), err))
			continue
		}
		fi, _ := entry.Info()
		_ = store.SaveSyncedFile(collectionID, remoteID, &session.SyncedFile{
			LocalPath: localPath,
			Size:      fi.Size(),
			ModTime:   fi.ModTime().Unix(),
			SyncedAt:  time.Now().Unix(),
		})
		fmt.Printf("  ↑ %s\n", entry.Name())
		result.Uploaded++
	}

	return result, nil
}

func downloadFile(client *api.Client, f *api.File, collectionKey []byte, localPath string) error {
	fileKey, err := crypto.SecretBoxOpenB64(f.EncryptedFileKey, f.FileKeyNonce, collectionKey)
	if err != nil {
		return fmt.Errorf("decrypt file key: %w", err)
	}
	bar := progressbar.NewOptions64(f.EncryptedSizeBytes,
		progressbar.OptionSetDescription("↓ "+f.Name),
		progressbar.OptionSetWidth(30),
		progressbar.OptionShowBytes(true),
		progressbar.OptionClearOnFinish(),
	)
	// Version-aware download: try the latest /versions snapshot first.
	// Necessary for collab-edited files where /files/:id/download alone
	// returns only the cold-start initial state.
	encrypted, _, err := client.LatestEncryptedBytes(f.ID)
	if err != nil {
		return err
	}
	_ = bar.Add64(int64(len(encrypted)))

	plaintext, err := crypto.DecryptStream(encrypted, fileKey)
	if err != nil {
		return fmt.Errorf("decrypt stream: %w", err)
	}
	return os.WriteFile(localPath, plaintext, 0644)
}

func uploadFile(client *api.Client, localPath, collectionID string, collectionKey []byte) (string, error) {
	data, err := os.ReadFile(localPath)
	if err != nil {
		return "", err
	}

	fileKey := crypto.NewStreamKey()

	bar := progressbar.NewOptions64(int64(len(data)),
		progressbar.OptionSetDescription("↑ "+filepath.Base(localPath)),
		progressbar.OptionSetWidth(30),
		progressbar.OptionShowBytes(true),
		progressbar.OptionClearOnFinish(),
	)

	encrypted, err := crypto.EncryptStream(data, fileKey)
	if err != nil {
		return "", fmt.Errorf("encrypt: %w", err)
	}
	_ = bar.Add64(int64(len(data)))

	// Encrypt file key with collection key
	encFileKey, fileKeyNonce, err := crypto.SecretBoxSeal(fileKey, collectionKey)
	if err != nil {
		return "", fmt.Errorf("wrap file key: %w", err)
	}

	// Encrypt metadata
	meta := api.FileMetadata{
		Name:     filepath.Base(localPath),
		MimeType: guessMIME(localPath),
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

func sanitizeName(name string) string {
	// Remove path separators to prevent directory traversal
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.ReplaceAll(name, "\\", "_")
	if name == "" || name == "." || name == ".." {
		return "_file"
	}
	return name
}

func guessMIME(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
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
	default:
		return "application/octet-stream"
	}
}

// ReadFrom is a helper to satisfy io.Reader interface for progress bars.
type readFrom struct {
	r   io.Reader
	bar *progressbar.ProgressBar
}

func (rf readFrom) Read(p []byte) (int, error) {
	n, err := rf.r.Read(p)
	_ = rf.bar.Add(n)
	return n, err
}
