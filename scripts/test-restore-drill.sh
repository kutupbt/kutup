#!/usr/bin/env bash
# Self-test for scripts/restore-drill.sh, with no network, Docker or bucket:
# --dry-run against a fake configuration (a fake lane file, .env and
# identity), with docker, age and openssl replaced by stubs that record any
# call. Checks that a dry run prints every step and runs nothing, and that
# the guards refuse what they must.
#
#   scripts/test-restore-drill.sh
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
drill="$root_dir/scripts/restore-drill.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# Stubs: any call is a failure of the dry run.
mkdir -p "$tmp/bin" "$tmp/lanes"
for tool in docker age openssl aws rclone; do
  printf '#!/bin/sh\necho "%s $*" >> "%s/calls"\nexit 97\n' "$tool" "$tmp" > "$tmp/bin/$tool"
  chmod +x "$tmp/bin/$tool"
done
cat > "$tmp/lanes/lane2.sh" <<'EOF'
export KUTUP_LANE=2 COMPOSE_PROJECT_NAME=kutup-l2 KUTUP_HTTP_PORT=40080 KUTUP_HTTPS_PORT=40443
EOF
cat > "$tmp/prod.env" <<'EOF'
POSTGRES_PASSWORD=fake
JWT_SECRET=fake-fake-fake-fake-fake-fake-fake-fake
OPAQUE_SETUP_KEYS=1:ZmFrZQ==
S3_ENDPOINT=https://fake.r2.example
S3_ACCESS_KEY=fake-data-key
S3_SECRET_KEY=fake-data-secret
S3_BUCKET=kutup-files
BACKUP_S3_ENDPOINT=https://fake.r2.example
BACKUP_S3_BUCKET=kutup-backups
BACKUP_S3_ACCESS_KEY=fake-backup-key
BACKUP_S3_SECRET_KEY=fake-backup-secret
KUTUP_BACKUP_AGE_RECIPIENT=age1fake
EOF
echo "AGE-SECRET-KEY-1FAKE" > "$tmp/backup.key"
chmod 600 "$tmp/backup.key"

failures=0
check() {
  if "$@"; then
    echo "ok: ${desc}"
  else
    echo "FAIL: ${desc}" >&2
    failures=$((failures + 1))
  fi
}

# Runs the drill with the fakes; $out and $status are its output and code.
drill() {
  status=0
  out="$(PATH="$tmp/bin:$PATH" KUTUP_LANES_DIR="$tmp/lanes" XDG_STATE_HOME="$tmp/state" \
    KUTUP_LANE='' DOCKER_HOST='' "$drill" "$@" 2>&1)" || status=$?
}

base=(--lane 2 --env "$tmp/prod.env" --identity "$tmp/backup.key" --images 0123456789ab
  --source-bucket kutup-files --scratch-bucket kutup-drill-files --dry-run)

drill "${base[@]}"
desc="a full dry run succeeds"; check [ "$status" -eq 0 ]
for expected in \
  "== 1. An empty stack: kutup-drill-l2" \
  "docker compose up --detach --wait postgres" \
  "ghcr.io/kutupbt/*:0123456789ab" \
  "scripts/backup-postgres.sh --list" \
  "scripts/backup-postgres.sh --restore kutup-\\<newest\\>.dump.age $tmp/backup.key" \
  "deleted blobs wait 7776000 s in the drill" \
  "rclone/rclone:1.68.2 sync --config /dev/null --log-level NOTICE drill:kutup-files drill:kutup-drill-files" \
  "echo BACKGROUND_JOBS=... >> $tmp/state/kutup-restore-drill/l2/drill.env" \
  "echo OUTBOUND_DELIVERY=... >> $tmp/state/kutup-restore-drill/l2/drill.env" \
  "Stalwart: STALWART_RECOVERY_MODE=1, its queue held" \
  "Outbound delivery:   held (OUTBOUND_DELIVERY=false, Stalwart in recovery mode)" \
  "== 4. Stalwart's volume" \
  "scripts/backup-stalwart.sh --restore stalwart-\\<newest\\>.tar.gz.age $tmp/backup.key" \
  "== Background jobs on" \
  "--force-recreate backend" \
  "http://backend:3000/api/health/ready" \
  "backend check-config" \
  "_sqlx_migrations" \
  "https://<app>.localhost:40543" \
  "Data-loss window:" \
  "== Summary"; do
  desc="the dry run prints: $expected"
  check grep -qF -- "$expected" <<<"$out"
done
no_secret() { ! grep -qE "fake-data-secret|fake-backup-secret|AGE-SECRET" <<<"$out"; }
desc="the dry run prints no secret"; check no_secret
desc="the dry run ran no docker, age or openssl"; check [ ! -e "$tmp/calls" ]
desc="the dry run wrote nothing"; check [ ! -e "$tmp/state" ]

drill "${base[@]}" --no-mail --jobs-stay-off --dump kutup-20261101T030000Z.dump.age
desc="--no-mail skips Stalwart"; check grep -qF "Stalwart's volume: skipped" <<<"$out"
desc="--jobs-stay-off keeps the jobs off"; check grep -qF "Background jobs stay off" <<<"$out"
desc="--dump restores the named dump"; check grep -qF -- "--restore kutup-20261101T030000Z.dump.age" <<<"$out"
desc="a named dump gives the data-loss window"; check grep -qE "Data-loss window: +[0-9]+h" <<<"$out"

refuses() {
  local why="$1"
  shift
  drill "$@"
  desc="refuses: $why"
  check [ "$status" -ne 0 ]
  desc="refuses with a reason: $why"
  check grep -q "restore drill:" <<<"$out"
}
refuses "the scratch bucket is the source" "${base[@]/kutup-drill-files/kutup-files}"
refuses "a scratch bucket without drill in its name" "${base[@]/kutup-drill-files/kutup-copy}"
refuses "the backup bucket as scratch" "${base[@]}" --set BACKUP_S3_BUCKET=kutup-drill-files
desc="names the backup bucket"; check grep -qF "is BACKUP_S3_BUCKET" <<<"$out"
refuses "--set S3_BUCKET" "${base[@]}" --set S3_BUCKET=kutup-files
refuses "--set BACKGROUND_JOBS" "${base[@]}" --set BACKGROUND_JOBS=true
refuses "--set OUTBOUND_DELIVERY" "${base[@]}" --set OUTBOUND_DELIVERY=true
refuses "--set STALWART_RECOVERY_MODE" "${base[@]}" --set STALWART_RECOVERY_MODE=0
status=0
out="$(PATH="$tmp/bin:$PATH" KUTUP_LANES_DIR="$tmp/lanes" XDG_STATE_HOME="$tmp/state" \
  DOCKER_HOST=ssh://prod.example "$drill" "${base[@]}" 2>&1)" || status=$?
desc="refuses a remote DOCKER_HOST"; check grep -qF "DOCKER_HOST is ssh://prod.example" <<<"$out"
drill --lane 2 --dry-run
desc="missing options are a usage error (2)"; check [ "$status" -eq 2 ]
drill "${base[@]}" --lane 4
desc="a lane outside 1-3 is a usage error"; check [ "$status" -eq 2 ]
drill --help
desc="--help prints the usage"; check grep -qF "Usage: scripts/restore-drill.sh" <<<"$out"

drill --down --lane 2 --dry-run
desc="--down --dry-run succeeds"; check [ "$status" -eq 0 ]
desc="--down removes only the drill's project"; check grep -qF "com.docker.compose.project=kutup-drill-l2" <<<"$out"
desc="--down leaves the buckets"; check grep -qF "the scratch bucket is left" <<<"$out"
desc="--down ran nothing"; check [ ! -e "$tmp/calls" ]

if [ "$failures" -gt 0 ]; then
  echo "test-restore-drill: $failures failed" >&2
  exit 1
fi
echo "test-restore-drill: all passed"
