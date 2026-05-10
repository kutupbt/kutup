package cmd

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/kutupbulut/kutup/cmd/kutup/internal/api"
	"github.com/kutupbulut/kutup/cmd/kutup/internal/crypto"
	"github.com/kutupbulut/kutup/cmd/kutup/internal/session"
	"github.com/spf13/cobra"
)

var shareIncomingCmd = &cobra.Command{
	Use:   "incoming",
	Short: "List, accept, or remove federated shares received from other servers",
}

var shareIncomingListCmd = &cobra.Command{
	Use:   "list",
	Short: "List federated shares accepted on this account",
	Args:  cobra.NoArgs,
	RunE:  runShareIncomingList,
}

var shareIncomingAcceptCmd = &cobra.Command{
	Use:   "accept <invite-url>",
	Short: "Accept a federated share invite (URL of the form .../invite/{token})",
	Args:  cobra.ExactArgs(1),
	RunE:  runShareIncomingAccept,
}

var (
	shareIncomingRemoveYes bool
)

var shareIncomingRemoveCmd = &cobra.Command{
	Use:   "remove <share-id>",
	Short: "Forget a federated share (doesn't notify the remote owner)",
	Args:  cobra.ExactArgs(1),
	RunE:  runShareIncomingRemove,
}

func init() {
	shareIncomingRemoveCmd.Flags().BoolVar(&shareIncomingRemoveYes, "yes", false,
		"skip the confirmation prompt")
	shareIncomingCmd.AddCommand(shareIncomingListCmd)
	shareIncomingCmd.AddCommand(shareIncomingAcceptCmd)
	shareIncomingCmd.AddCommand(shareIncomingRemoveCmd)
}

func runShareIncomingList(_ *cobra.Command, _ []string) error {
	client, sess, cleanup, err := requireSessionFull()
	if err != nil {
		return err
	}
	defer cleanup()

	shares, err := client.ListIncomingShares()
	if err != nil {
		return err
	}

	// Try to decrypt each share's name. Failures are non-fatal — the
	// share still exists and is browsable; we just can't render its name.
	type display struct {
		ID           string `json:"id"`
		RemoteServer string `json:"remoteServer"`
		Name         string `json:"name"`
		CanUpload    bool   `json:"canUpload"`
		CanDelete    bool   `json:"canDelete"`
		CreatedAt    string `json:"createdAt"`
	}
	out := make([]display, 0, len(shares))
	for _, s := range shares {
		d := display{
			ID:           s.ID,
			RemoteServer: s.RemoteServer,
			Name:         "(undecryptable)",
			CanUpload:    s.CanUpload,
			CanDelete:    s.CanDelete,
			CreatedAt:    s.CreatedAt.Local().Format(time.RFC3339),
		}
		if name, err := decryptIncomingShareName(s, sess); err == nil {
			d.Name = name
		}
		out = append(out, d)
	}

	if jsonOut {
		b, _ := json.Marshal(out)
		fmt.Println(string(b))
		return nil
	}
	if len(out) == 0 {
		fmt.Println("(no incoming federated shares)")
		return nil
	}
	fmt.Printf("%-36s  %-30s  %-30s  %s\n", "ID", "REMOTE", "NAME", "PERMS")
	for _, d := range out {
		perms := ""
		if d.CanUpload {
			perms += "upload "
		}
		if d.CanDelete {
			perms += "delete"
		}
		if perms == "" {
			perms = "read-only"
		}
		fmt.Printf("%-36s  %-30s  %-30s  %s\n", d.ID, d.RemoteServer, d.Name, perms)
	}
	return nil
}

// decryptIncomingShareName unwraps the sealed-boxed collection key with
// the session's keypair, then decrypts the share name with that key.
// Mirrors the web's federation receive flow — the inviter sealed the
// collection key under our public key, so we open it with our private.
func decryptIncomingShareName(s api.IncomingShare, sess *session.Session) (string, error) {
	encColKey, err := base64.StdEncoding.DecodeString(s.EncryptedCollectionKey)
	if err != nil {
		return "", fmt.Errorf("base64: %w", err)
	}
	priv, err := sess.PrivateKeyBytes()
	if err != nil {
		return "", err
	}
	pub, err := sess.PublicKeyBytes()
	if err != nil {
		return "", err
	}
	colKey, err := crypto.OpenAnonymous(encColKey, pub, priv)
	if err != nil {
		return "", fmt.Errorf("unseal collection key: %w", err)
	}
	name, err := crypto.SecretBoxOpenB64(s.EncryptedName, s.NameNonce, colKey)
	if err != nil {
		return "", err
	}
	return string(name), nil
}

func runShareIncomingAccept(_ *cobra.Command, args []string) error {
	inviteURL := args[0]
	if !strings.Contains(inviteURL, "/invite/") {
		return fmt.Errorf("invalid invite URL: must contain /invite/")
	}

	client, _, cleanup, err := requireSessionFull()
	if err != nil {
		return err
	}
	defer cleanup()

	share, err := client.AddIncomingShare(inviteURL)
	if err != nil {
		return err
	}
	if jsonOut {
		b, _ := json.Marshal(share)
		fmt.Println(string(b))
	} else {
		fmt.Printf("Accepted federated share %s from %s\n", share.ID, share.RemoteServer)
	}
	return nil
}

func runShareIncomingRemove(_ *cobra.Command, args []string) error {
	shareID := args[0]

	client, _, cleanup, err := requireSessionFull()
	if err != nil {
		return err
	}
	defer cleanup()

	if !shareIncomingRemoveYes {
		fmt.Fprintf(os.Stderr,
			"Remove incoming share %s? This forgets your local pointer; the remote owner is not notified. [y/N]: ", shareID)
		reader := bufio.NewReader(os.Stdin)
		ans, _ := reader.ReadString('\n')
		ans = strings.ToLower(strings.TrimSpace(ans))
		if ans != "y" && ans != "yes" {
			return fmt.Errorf("aborted")
		}
	}

	if err := client.RemoveIncomingShare(shareID); err != nil {
		return err
	}
	if jsonOut {
		fmt.Printf(`{"shareId":%q,"removed":true}`+"\n", shareID)
	} else {
		fmt.Printf("Removed incoming share %s\n", shareID)
	}
	return nil
}
