// Shared session loading and token refresh logic used by all commands.
package cmd

import (
	"fmt"
	"time"

	"github.com/kutupbulut/kutup/cmd/kutup/internal/api"
	"github.com/kutupbulut/kutup/cmd/kutup/internal/session"
)

func requireSessionFull() (*api.Client, *session.Session, func(), error) {
	client, sess, _, cleanup, err := requireSessionWithStore()
	return client, sess, cleanup, err
}

// requireSessionWithStore is like requireSessionFull but also returns the open
// store. The caller is responsible for closing it via the cleanup func.
// Use this when you need to pass the store to another package (e.g. sync engine)
// to avoid opening BoltDB twice — BoltDB allows only one writer at a time.
func requireSessionWithStore() (*api.Client, *session.Session, *session.Store, func(), error) {
	store, err := session.Open(profile)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("open store: %w", err)
	}

	sess, err := store.LoadSession()
	if err != nil {
		store.Close()
		return nil, nil, nil, nil, fmt.Errorf("load session: %w", err)
	}
	if sess == nil {
		store.Close()
		return nil, nil, nil, nil, fmt.Errorf("not logged in — run 'kutup login' first")
	}

	client := api.New(sess.Server, sess.AccessToken)

	// Proactively refresh the access token on every command to avoid clock skew issues.
	if sess.RefreshToken != "" {
		if refreshed, err := client.RefreshToken(sess.RefreshToken); err == nil && refreshed.AccessToken != "" {
			sess.AccessToken = refreshed.AccessToken
			client.SetToken(refreshed.AccessToken)
			_ = store.SaveSession(profile, sess)
		}
	}

	cleanup := func() { store.Close() }
	return client, sess, store, cleanup, nil
}

func formatTime(ts string) string {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return ts
	}
	return t.Format("2006-01-02 15:04")
}
