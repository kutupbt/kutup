// Package testdb provides per-test Postgres schema isolation for handler
// tests. It points at the running compose stack's Postgres on port 5432
// (override via KUTUP_TEST_DB env var) and creates a uniquely-named schema
// per test. The schema is migrated to head and dropped via t.Cleanup so each
// test starts on a clean DB without paying the cost of spinning up a
// container.
//
// Usage:
//
//	pool := testdb.Setup(t)
//	// pool is *pgxpool.Pool with search_path locked to the test schema.
//
// If Postgres isn't reachable (e.g. running unit tests outside the dev
// stack), Setup calls t.Skip — handler tests are integration tests and not
// expected to run in vacuum.
package testdb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/kutup/backend/db"
)

// Setup connects to the running compose Postgres, creates a fresh schema,
// runs migrations on it, and returns a pool whose every connection has
// search_path set to that schema. The schema is dropped on test cleanup.
//
// To override the DSN, set KUTUP_TEST_DB to a postgres:// URL.
func Setup(t *testing.T) *pgxpool.Pool {
	t.Helper()

	baseURL := os.Getenv("KUTUP_TEST_DB")
	if baseURL == "" {
		// docker-compose.override.yml maps Postgres to 127.0.0.1:5433 so we
		// don't collide with a system Postgres on 5432.
		baseURL = "postgres://kutup:kutup_dev_password@localhost:5433/kutup?sslmode=disable"
	}

	if !reachable(baseURL) {
		t.Skipf("Postgres not reachable at %s — start the compose stack to run handler tests", redact(baseURL))
	}

	schema := "test_" + strings.ReplaceAll(t.Name(), "/", "_") + "_" + randSuffix()
	schema = sanitizeIdent(schema)

	// Connect once with the base DB to create the schema.
	bootstrapPool, err := pgxpool.New(context.Background(), baseURL)
	if err != nil {
		t.Fatalf("testdb: bootstrap connect: %v", err)
	}
	defer bootstrapPool.Close()

	if _, err := bootstrapPool.Exec(context.Background(), fmt.Sprintf(`CREATE SCHEMA "%s"`, schema)); err != nil {
		t.Fatalf("testdb: create schema %q: %v", schema, err)
	}

	// Run migrations against the new schema. golang-migrate's postgres driver
	// honours `search_path` from the connection string, so we tack it on.
	migURL, err := withSearchPath(baseURL, schema)
	if err != nil {
		t.Fatalf("testdb: build migrate URL: %v", err)
	}
	if err := runMigrations(migURL); err != nil {
		// Best-effort cleanup before failing.
		_, _ = bootstrapPool.Exec(context.Background(), fmt.Sprintf(`DROP SCHEMA "%s" CASCADE`, schema))
		t.Fatalf("testdb: migrate: %v", err)
	}

	// Build the pool the test will use.
	cfg, err := pgxpool.ParseConfig(migURL)
	if err != nil {
		t.Fatalf("testdb: parse pool config: %v", err)
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("testdb: pool: %v", err)
	}

	t.Cleanup(func() {
		pool.Close()
		// Reconnect with the original URL to drop the schema (the pool we
		// just closed used the schema-scoped URL, which is fine for cleanup
		// too but easier to reason about with the bootstrap URL).
		clean, err := pgxpool.New(context.Background(), baseURL)
		if err == nil {
			defer clean.Close()
			_, _ = clean.Exec(context.Background(), fmt.Sprintf(`DROP SCHEMA "%s" CASCADE`, schema))
		}
	})

	return pool
}

// reachable does a quick TCP probe so tests skip rather than time-out when
// Postgres isn't running locally.
func reachable(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		host += ":5432"
	}
	conn, err := net.DialTimeout("tcp", host, 500*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func withSearchPath(rawURL, schema string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func runMigrations(databaseURL string) error {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	sqlDB := stdlib.OpenDB(*cfg.ConnConfig)
	defer sqlDB.Close()

	driver, err := postgres.WithInstance(sqlDB, &postgres.Config{})
	if err != nil {
		return fmt.Errorf("driver: %w", err)
	}
	migFS := db.MigrationsFS()
	src, err := iofs.New(migFS, "migrations")
	if err != nil {
		return fmt.Errorf("source: %w", err)
	}
	m, err := migrate.NewWithInstance("iofs", src, "postgres", driver)
	if err != nil {
		return fmt.Errorf("instance: %w", err)
	}
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("up: %w", err)
	}
	return nil
}

// Sanitise an identifier — Postgres allows up to 63 chars and we only want
// alphanumerics + underscores. Anything else becomes _.
func sanitizeIdent(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	out := strings.ToLower(b.String())
	if len(out) > 63 {
		out = out[:63]
	}
	return out
}

func randSuffix() string {
	// Use a cheap pseudo-random suffix — schema collisions only matter
	// across concurrent tests, and `go test` runs tests in a single package
	// serially by default. Adding nanos handles the same-name-in-table case.
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

func redact(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	if u.User != nil {
		u.User = url.UserPassword(u.User.Username(), "***")
	}
	return u.String()
}

// Compile-time check we can still use database/sql (stdlib) below.
var _ *sql.DB
