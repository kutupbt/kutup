// Session persistence: Device Key in OS keyring, sensitive data encrypted in BoltDB.
// Follows the same two-tier model used by ente CLI.
package session

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/adrg/xdg"
	"github.com/zalando/go-keyring"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	keyringService = "kutup-cli"
	keyringAccount = "device-key"
	dbFileName     = "kutup.db"
	appName        = "kutup"
)

var (
	bucketSession     = []byte("session")
	bucketCollections = []byte("collections")
	bucketSync        = []byte("sync")
)

// Session holds all in-memory session state for a single profile.
type Session struct {
	Server      string `json:"server"`
	Email       string `json:"email"`
	UserID      string `json:"userId"`
	Username    string `json:"username"`
	AccessToken string `json:"accessToken"`
	// Refresh token stored encrypted
	RefreshToken string `json:"refreshToken"`
	// Derived keys (base64) — decrypted from server-returned encrypted blobs at login
	MasterKey  string `json:"masterKey"`
	PrivateKey string `json:"privateKey"`
	PublicKey  string `json:"publicKey"`
	// Server-returned encrypted blobs (for re-derivation if needed)
	EncryptedMasterKey  string `json:"encryptedMasterKey"`
	MasterKeyNonce      string `json:"masterKeyNonce"`
	EncryptedPrivateKey string `json:"encryptedPrivateKey"`
	PrivateKeyNonce     string `json:"privateKeyNonce"`
	// Quota
	StorageQuotaBytes int64 `json:"storageQuotaBytes"`
	StorageUsedBytes  int64 `json:"storageUsedBytes"`
}

// MasterKeyBytes returns the decoded master key.
func (s *Session) MasterKeyBytes() ([]byte, error) {
	return base64.StdEncoding.DecodeString(s.MasterKey)
}

// PrivateKeyBytes returns the decoded private key.
func (s *Session) PrivateKeyBytes() ([]byte, error) {
	return base64.StdEncoding.DecodeString(s.PrivateKey)
}

// PublicKeyBytes returns the decoded public key.
func (s *Session) PublicKeyBytes() ([]byte, error) {
	return base64.StdEncoding.DecodeString(s.PublicKey)
}

// Store manages session persistence.
type Store struct {
	db        *bolt.DB
	deviceKey [32]byte
}

// Open opens (or creates) the BoltDB store and loads the device key from keyring.
func Open(profile string) (*Store, error) {
	dataDir, err := xdg.DataFile(filepath.Join(appName, profile))
	if err != nil {
		return nil, fmt.Errorf("data dir: %w", err)
	}
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, err
	}

	dbPath := filepath.Join(dataDir, dbFileName)
	db, err := bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	if err := db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bucketSession, bucketCollections, bucketSync} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		db.Close()
		return nil, err
	}

	s := &Store{db: db}
	if err := s.loadDeviceKey(profile); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

// loadDeviceKey gets the device key from: keyring → KUTUP_DEVICE_KEY env var → file fallback.
func (s *Store) loadDeviceKey(profile string) error {
	// Try keyring first
	stored, err := keyring.Get(keyringService+"/"+profile, keyringAccount)
	if err == nil {
		key, err := base64.StdEncoding.DecodeString(stored)
		if err == nil && len(key) == 32 {
			copy(s.deviceKey[:], key)
			return nil
		}
	}

	// Env var fallback (for Docker / CI)
	if envKey := os.Getenv("KUTUP_DEVICE_KEY"); envKey != "" {
		key, err := base64.StdEncoding.DecodeString(envKey)
		if err == nil && len(key) == 32 {
			copy(s.deviceKey[:], key)
			return nil
		}
	}

	// File fallback (chmod 600)
	keyFile, _ := xdg.DataFile(filepath.Join(appName, profile, "device.key"))
	if data, err := os.ReadFile(keyFile); err == nil {
		key, err := base64.StdEncoding.DecodeString(string(data))
		if err == nil && len(key) == 32 {
			copy(s.deviceKey[:], key)
			return nil
		}
	}

	return nil // no existing key — will be created at login
}

// createDeviceKey generates and persists a new device key.
func (s *Store) createDeviceKey(profile string) error {
	if _, err := rand.Read(s.deviceKey[:]); err != nil {
		return err
	}
	encoded := base64.StdEncoding.EncodeToString(s.deviceKey[:])

	// Try keyring
	if err := keyring.Set(keyringService+"/"+profile, keyringAccount, encoded); err == nil {
		return nil
	}

	// Fall back to file
	keyFile, err := xdg.DataFile(filepath.Join(appName, profile, "device.key"))
	if err != nil {
		return err
	}
	return os.WriteFile(keyFile, []byte(encoded), 0600)
}

// HasDeviceKey returns true if a device key has been loaded.
func (s *Store) HasDeviceKey() bool {
	var zero [32]byte
	return s.deviceKey != zero
}

// SaveSession encrypts and persists the session.
func (s *Store) SaveSession(profile string, sess *Session) error {
	if !s.HasDeviceKey() {
		if err := s.createDeviceKey(profile); err != nil {
			return fmt.Errorf("create device key: %w", err)
		}
	}
	data, err := json.Marshal(sess)
	if err != nil {
		return err
	}
	encrypted, err := s.encrypt(data)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketSession).Put([]byte("data"), encrypted)
	})
}

// LoadSession decrypts and returns the stored session, or nil if none.
func (s *Store) LoadSession() (*Session, error) {
	var encrypted []byte
	if err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketSession).Get([]byte("data"))
		if v != nil {
			encrypted = make([]byte, len(v))
			copy(encrypted, v)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	if encrypted == nil {
		return nil, nil
	}
	if !s.HasDeviceKey() {
		return nil, errors.New("no device key — run 'kutup login' first")
	}
	data, err := s.decrypt(encrypted)
	if err != nil {
		return nil, fmt.Errorf("session decrypt failed: %w", err)
	}
	var sess Session
	if err := json.Unmarshal(data, &sess); err != nil {
		return nil, err
	}
	return &sess, nil
}

// ClearSession removes all session data from the DB.
func (s *Store) ClearSession() error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketSession).Delete([]byte("data"))
	})
}

// --- Sync state ---

// SyncMeta holds per-collection sync metadata.
type SyncMeta struct {
	LastSync int64 `json:"lastSync"` // unix timestamp
}

func (s *Store) GetSyncMeta(collectionID string) (*SyncMeta, error) {
	var meta SyncMeta
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketSync).Get([]byte(collectionID + "/meta"))
		if v == nil {
			return nil
		}
		return json.Unmarshal(v, &meta)
	})
	return &meta, err
}

func (s *Store) SaveSyncMeta(collectionID string, meta *SyncMeta) error {
	data, _ := json.Marshal(meta)
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketSync).Put([]byte(collectionID+"/meta"), data)
	})
}

// SyncedFile tracks a file that has been synced.
type SyncedFile struct {
	LocalPath string `json:"localPath"`
	Size      int64  `json:"size"`
	ModTime   int64  `json:"modTime"`
	SyncedAt  int64  `json:"syncedAt"`
}

func (s *Store) GetSyncedFile(collectionID, remoteID string) (*SyncedFile, error) {
	var f SyncedFile
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketSync).Get([]byte(collectionID + "/files/" + remoteID))
		if v == nil {
			return nil
		}
		return json.Unmarshal(v, &f)
	})
	if f.LocalPath == "" {
		return nil, err
	}
	return &f, err
}

func (s *Store) SaveSyncedFile(collectionID, remoteID string, f *SyncedFile) error {
	data, _ := json.Marshal(f)
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketSync).Put([]byte(collectionID+"/files/"+remoteID), data)
	})
}

func (s *Store) DeleteSyncedFile(collectionID, remoteID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketSync).Delete([]byte(collectionID + "/files/" + remoteID))
	})
}

// --- Encryption helpers using device key ---

func (s *Store) encrypt(data []byte) ([]byte, error) {
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	sealed := secretbox.Seal(nonce[:], data, &nonce, &s.deviceKey)
	return sealed, nil
}

func (s *Store) decrypt(data []byte) ([]byte, error) {
	if len(data) < 24 {
		return nil, errors.New("session data too short")
	}
	var nonce [24]byte
	copy(nonce[:], data[:24])
	plain, ok := secretbox.Open(nil, data[24:], &nonce, &s.deviceKey)
	if !ok {
		return nil, errors.New("session decryption failed — wrong device key")
	}
	return plain, nil
}
