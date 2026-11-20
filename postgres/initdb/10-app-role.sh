#!/bin/sh
# The server's own database role (docs/self-hosting.md, "Database roles"):
# made once, when the database is first created, if POSTGRES_APP_USER is set.
# The server then runs as it, and as POSTGRES_USER (the tables' owner) only
# for migrations, grants and pruning; the security and admin logs are
# append-only for it. An existing database gets the role by hand (the same
# page).
set -eu
[ -n "${POSTGRES_APP_USER:-}" ] || exit 0
: "${POSTGRES_APP_PASSWORD:?POSTGRES_APP_USER needs POSTGRES_APP_PASSWORD}"
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v app="$POSTGRES_APP_USER" -v password="$POSTGRES_APP_PASSWORD" <<'SQL'
CREATE ROLE :"app" LOGIN PASSWORD :'password';
SQL
