package cmd

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/alperen-albayrak/kutup/cli/internal/api"
	"github.com/alperen-albayrak/kutup/cli/internal/crypto"
	"github.com/spf13/cobra"
)

var shareCmd = &cobra.Command{
	Use:   "share",
	Short: "Share folders",
}

var (
	shareCanUpload bool
	shareCanDelete bool
)

var shareFolderCmd = &cobra.Command{
	Use:   "folder <collection-id> <email>",
	Short: "Share a folder with a Kutup user",
	Args:  cobra.ExactArgs(2),
	RunE:  runShareFolder,
}

var shareFederatedCmd = &cobra.Command{
	Use:   "federated <collection-id> <user@server>",
	Short: "Share a folder with a user on another Kutup server",
	Args:  cobra.ExactArgs(2),
	RunE:  runShareFederated,
}

var sharePublicCmd = &cobra.Command{
	Use:   "public <collection-id>",
	Short: "Create a public link for a folder",
	Args:  cobra.ExactArgs(1),
	RunE:  runSharePublic,
}

func init() {
	shareFolderCmd.Flags().BoolVar(&shareCanUpload, "upload", false, "allow recipient to upload")
	shareFolderCmd.Flags().BoolVar(&shareCanDelete, "delete", false, "allow recipient to delete their uploads")
	shareFederatedCmd.Flags().BoolVar(&shareCanUpload, "upload", false, "allow recipient to upload")
	shareFederatedCmd.Flags().BoolVar(&shareCanDelete, "delete", false, "allow recipient to delete their uploads")

	shareCmd.AddCommand(shareFolderCmd)
	shareCmd.AddCommand(shareFederatedCmd)
	shareCmd.AddCommand(sharePublicCmd)
}

func runShareFolder(cmd *cobra.Command, args []string) error {
	collectionID := args[0]
	recipientEmail := args[1]

	client, sess, cleanup, err := requireSessionFull()
	if err != nil {
		return err
	}
	defer cleanup()

	masterKey, err := sess.MasterKeyBytes()
	if err != nil {
		return err
	}

	// Get collection key
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

	// Look up recipient's public key
	recipient, err := client.GetUserByEmail(recipientEmail)
	if err != nil {
		return fmt.Errorf("look up user %s: %w", recipientEmail, err)
	}

	recipientPubKey, err := base64.StdEncoding.DecodeString(recipient.PublicKey)
	if err != nil {
		return fmt.Errorf("decode recipient public key: %w", err)
	}

	// Seal the collection key for the recipient
	sealedKey, err := crypto.SealAnonymous(collectionKey, recipientPubKey)
	if err != nil {
		return fmt.Errorf("seal collection key: %w", err)
	}

	if err := client.ShareCollection(collectionID, api.ShareRequest{
		RecipientUserID:        recipient.UserID,
		EncryptedCollectionKey: base64.StdEncoding.EncodeToString(sealedKey),
		CanUpload:              shareCanUpload,
		CanDelete:              shareCanDelete,
	}); err != nil {
		return fmt.Errorf("share: %w", err)
	}

	if jsonOut {
		fmt.Printf(`{"shared":%q,"with":%q}`+"\n", collectionID, recipientEmail)
	} else {
		fmt.Printf("Shared folder with %s\n", recipientEmail)
	}
	return nil
}

func runShareFederated(cmd *cobra.Command, args []string) error {
	collectionID := args[0]
	target := args[1] // format: user@server or alice@https://other.com

	client, sess, cleanup, err := requireSessionFull()
	if err != nil {
		return err
	}
	defer cleanup()

	masterKey, err := sess.MasterKeyBytes()
	if err != nil {
		return err
	}

	// Parse user@server
	at := strings.LastIndex(target, "@")
	if at < 1 {
		return fmt.Errorf("format must be username@server-url (e.g. alice@https://other.com)")
	}
	recipientUsername := target[:at]
	recipientServer := target[at+1:]

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

	// Fetch remote user's public key via federation endpoint
	remotePubKeyResp, err := client.GetFedPubKey(recipientUsername, recipientServer)
	if err != nil {
		return fmt.Errorf("fetch remote public key: %w", err)
	}
	recipientPubKey, err := base64.StdEncoding.DecodeString(remotePubKeyResp.PublicKey)
	if err != nil {
		return fmt.Errorf("decode remote public key: %w", err)
	}

	sealedKey, err := crypto.SealAnonymous(collectionKey, recipientPubKey)
	if err != nil {
		return fmt.Errorf("seal collection key: %w", err)
	}

	resp, err := client.ShareFederated(collectionID, api.FederatedShareRequest{
		RecipientUsername:      recipientUsername,
		RecipientServer:        recipientServer,
		EncryptedCollectionKey: base64.StdEncoding.EncodeToString(sealedKey),
		CanUpload:              shareCanUpload,
		CanDelete:              shareCanDelete,
	})
	if err != nil {
		return fmt.Errorf("federated share: %w", err)
	}

	if jsonOut {
		fmt.Printf(`{"inviteUrl":%q}`+"\n", resp.InviteURL)
	} else {
		fmt.Printf("Invite link (send to %s):\n%s\n", target, resp.InviteURL)
	}
	return nil
}

func runSharePublic(cmd *cobra.Command, args []string) error {
	collectionID := args[0]

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

	// Generate a random link key (never sent to server)
	linkKey := make([]byte, 32)
	if _, err := rand.Read(linkKey); err != nil {
		return err
	}

	// Encrypt the collection key with the link key
	encKey, keyNonce, err := crypto.SecretBoxSeal(collectionKey, linkKey)
	if err != nil {
		return err
	}

	resp, err := client.CreatePublicShare(api.PublicShareRequest{
		ShareType:                   "collection",
		TargetID:                    collectionID,
		EncryptedCollectionKey:      base64.StdEncoding.EncodeToString(encKey),
		EncryptedCollectionKeyNonce: base64.StdEncoding.EncodeToString(keyNonce),
	})
	if err != nil {
		return fmt.Errorf("create public share: %w", err)
	}

	linkKeyB64 := base64.StdEncoding.EncodeToString(linkKey)
	shareURL := fmt.Sprintf("%s/s/%s#key=%s", sess.Server, resp.Token, linkKeyB64)

	if jsonOut {
		fmt.Printf(`{"url":%q}`+"\n", shareURL)
	} else {
		fmt.Println("Public link (the decryption key is in the URL fragment):")
		fmt.Println(shareURL)
	}
	return nil
}
