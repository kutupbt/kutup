// Shared session loading and token refresh logic used by all commands.
package cmd

import (
	"fmt"
	"time"

	"github.com/alperen-albayrak/kutup/cli/internal/api"
	"github.com/alperen-albayrak/kutup/cli/internal/session"
)

func requireSessionFull() (*api.Client, *session.Session, func(), error) {
	store, err := session.Open(profile)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open store: %w", err)
	}

	sess, err := store.LoadSession()
	if err != nil {
		store.Close()
		return nil, nil, nil, fmt.Errorf("load session: %w", err)
	}
	if sess == nil {
		store.Close()
		return nil, nil, nil, fmt.Errorf("not logged in — run 'kutup login' first")
	}

	client := api.New(sess.Server, sess.AccessToken)

	// Transparently refresh the access token if it looks expired.
	// We attempt a refresh proactively every time rather than parsing the JWT,
	// which avoids clock skew issues and keeps the token fresh.
	if sess.RefreshToken != "" {
		refreshed, err := client.RefreshToken(sess.RefreshToken)
		if err == nil && refreshed.AccessToken != "" {
			sess.AccessToken = refreshed.AccessToken
			client.SetToken(refreshed.AccessToken)
			_ = store.SaveSession(profile, sess)
		}
	}

	cleanup := func() {
		store.Close()
	}

	return client, sess, cleanup, nil
}

func formatTime(ts string) string {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return ts
	}
	return t.Format("2006-01-02 15:04")
}
