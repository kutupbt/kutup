package cmd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/alperen-albayrak/kutup/cli/internal/api"
	"github.com/alperen-albayrak/kutup/cli/internal/crypto"
	"github.com/spf13/cobra"
)

var pubCmd = &cobra.Command{
	Use:   "pub",
	Short: "Consume a public share link (no login required for the link)",
}

var pubGetCmd = &cobra.Command{
	Use:   "get <url>",
	Short: "Show metadata for a public share URL",
	Args:  cobra.ExactArgs(1),
	RunE:  runPubGet,
}

var pubLsCmd = &cobra.Command{
	Use:   "ls <url>",
	Short: "List files in a public share",
	Args:  cobra.ExactArgs(1),
	RunE:  runPubLs,
}

var pubDownloadCmd = &cobra.Command{
	Use:   "download <url> <file-id> [dest]",
	Short: "Download a file from a public share",
	Args:  cobra.RangeArgs(2, 3),
	RunE:  runPubDownload,
}

func init() {
	pubCmd.AddCommand(pubGetCmd)
	pubCmd.AddCommand(pubLsCmd)
	pubCmd.AddCommand(pubDownloadCmd)
}

// pubURL holds the parsed pieces of a kutup public-share URL.
//   serverBase: scheme + host (used to bypass the local config base if the
//               URL isn't pointing at the configured server)
//   token:      the path segment after /p/
//   linkKey:    the base64 ?key= value from the URL #fragment
type pubURL struct {
	serverBase string
	token      string
	linkKey    []byte
}

// parsePubURL accepts a URL of the form
//
//	https://example.com/p/<token>#key=<base64-link-key>
//
// Mirrors frontend/src/pages/PublicShare.tsx:54-67.
func parsePubURL(s string) (*pubURL, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("parse url: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("URL must include scheme + host")
	}

	// Token: last non-empty path segment after `/p/`.
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 || parts[0] != "p" {
		return nil, fmt.Errorf("URL path must be /p/<token>")
	}
	token := parts[1]

	// Key: ?key=<b64> inside the URL fragment (URLSearchParams style).
	frag := u.Fragment
	q, err := url.ParseQuery(frag)
	if err != nil {
		return nil, fmt.Errorf("parse fragment: %w", err)
	}
	keyB64 := q.Get("key")
	if keyB64 == "" {
		return nil, fmt.Errorf("URL fragment missing #key=...")
	}
	linkKey, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return nil, fmt.Errorf("link key base64: %w", err)
	}

	return &pubURL{
		serverBase: u.Scheme + "://" + u.Host,
		token:      token,
		linkKey:    linkKey,
	}, nil
}

// pubClient builds an unauthenticated api.Client pointing at the URL's
// own host. The bearer token is left empty — public-share endpoints
// don't require auth, and forwarding our local token to a foreign host
// would leak it.
func pubClient(p *pubURL) *api.Client {
	return api.New(p.serverBase, "")
}

// unwrapCollectionKey decrypts the wrapped collection key with linkKey.
func unwrapCollectionKey(share *api.PublicShare, linkKey []byte) ([]byte, error) {
	if share.EncryptedCollectionKey == nil || share.EncryptedCollectionKeyNonce == nil {
		return nil, fmt.Errorf("share has no wrapped collection key")
	}
	return crypto.SecretBoxOpenB64(*share.EncryptedCollectionKey, *share.EncryptedCollectionKeyNonce, linkKey)
}

func runPubGet(_ *cobra.Command, args []string) error {
	p, err := parsePubURL(args[0])
	if err != nil {
		return err
	}
	client := pubClient(p)
	share, err := client.GetPublicShare(p.token)
	if err != nil {
		return err
	}
	// Validate linkKey works by attempting an unwrap.
	if _, err := unwrapCollectionKey(share, p.linkKey); err != nil {
		return fmt.Errorf("link key from URL fragment doesn't unwrap the share: %w", err)
	}
	if jsonOut {
		b, _ := json.Marshal(share)
		fmt.Println(string(b))
		return nil
	}
	fmt.Printf("Share:    %s\n", share.ID)
	fmt.Printf("Type:     %s\n", share.ShareType)
	fmt.Printf("Target:   %s\n", share.TargetID)
	if share.ExpiresAt != nil {
		fmt.Printf("Expires:  %s\n", share.ExpiresAt.Local().Format(time.RFC3339))
	} else {
		fmt.Println("Expires:  (never)")
	}
	return nil
}

func runPubLs(_ *cobra.Command, args []string) error {
	p, err := parsePubURL(args[0])
	if err != nil {
		return err
	}
	client := pubClient(p)
	share, err := client.GetPublicShare(p.token)
	if err != nil {
		return err
	}
	if share.ShareType != "collection" {
		return fmt.Errorf("not a collection share (type=%s)", share.ShareType)
	}
	colKey, err := unwrapCollectionKey(share, p.linkKey)
	if err != nil {
		return err
	}
	files, err := client.ListPublicShareFiles(p.token)
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

func runPubDownload(_ *cobra.Command, args []string) error {
	p, err := parsePubURL(args[0])
	if err != nil {
		return err
	}
	fileID := args[1]
	destDir := "."
	if len(args) == 3 {
		destDir = args[2]
	}

	client := pubClient(p)
	share, err := client.GetPublicShare(p.token)
	if err != nil {
		return err
	}
	colKey, err := unwrapCollectionKey(share, p.linkKey)
	if err != nil {
		return err
	}
	files, err := client.ListPublicShareFiles(p.token)
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
		return fmt.Errorf("file %s not found in this public share", fileID)
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

	urlRes, err := client.PublicShareDownloadURL(p.token, fileID)
	if err != nil {
		return err
	}
	encrypted, err := api.FetchPresignedURL(urlRes.URL)
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
		fmt.Printf(`{"fileId":%q,"size":%d,"dest":%q}`+"\n", fileID, len(plain), destPath)
	} else {
		fmt.Printf("Downloaded %s → %s\n", meta.Name, destPath)
	}
	return nil
}
