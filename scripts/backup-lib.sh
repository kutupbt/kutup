# shellcheck shell=bash
# label, prefix and keep_days are set by the caller.
# shellcheck disable=SC2154
# Shared by scripts/backup-postgres.sh and scripts/backup-stalwart.sh; not
# run on its own. The caller sets `label` (its name in messages) and runs
# from the deployment's directory, where .env is. KUTUP_ENV_FILE names
# another settings file instead (scripts/restore-drill.sh, whose stack's
# settings are its own; it also points Compose there with COMPOSE_ENV_FILES).
#
# Backups go to their own bucket with their own key (BACKUP_S3_* in .env),
# never the bucket Kutup's data is in: one lost bucket or one leaked key
# must not take both. They are encrypted with age to a recipient (a public
# key, KUTUP_BACKUP_AGE_RECIPIENT); its identity (the private key) stays
# offline, so this server cannot read its own backups. age authenticates
# every chunk, so a changed or cut backup fails to decrypt instead of
# restoring something else (docs/self-hosting.md, "Backups").

fail() {
  echo "$label: $*" >&2
  exit 1
}

env_file="${KUTUP_ENV_FILE:-.env}"

setting() {
  # The last assignment of a key in .env, taken literally (never evaluated).
  sed -n "s/^$1=//p" "$env_file" | tail -n 1
}

required() {
  local value
  value="$(setting "$1")"
  [ -n "$value" ] || fail "set $1 in .env"
  printf '%s' "$value"
}

[ -f "$env_file" ] || fail "no $env_file in $(pwd)"

# The backup bucket and its key. Unset: refuse, never the data bucket.
backup_store() {
  local name missing=()
  for name in BACKUP_S3_ENDPOINT BACKUP_S3_BUCKET BACKUP_S3_ACCESS_KEY BACKUP_S3_SECRET_KEY; do
    [ -n "$(setting "$name")" ] || missing+=("$name")
  done
  if [ "${#missing[@]}" -gt 0 ]; then
    fail "set ${missing[*]} in .env: backups go to their own bucket with their own key, never the data bucket (docs/self-hosting.md, \"Backups\")"
  fi
  endpoint="$(setting BACKUP_S3_ENDPOINT)"
  bucket="$(setting BACKUP_S3_BUCKET)"
  region="$(setting BACKUP_S3_REGION)"
  if [ "$bucket" = "$(setting S3_BUCKET)" ] && [ "$endpoint" = "$(setting S3_ENDPOINT)" ]; then
    fail "BACKUP_S3_BUCKET is the data bucket (S3_BUCKET); give backups a bucket of their own"
  fi
  if [ "$(setting BACKUP_S3_ACCESS_KEY)" = "$(setting S3_ACCESS_KEY)" ]; then
    fail "BACKUP_S3_ACCESS_KEY is the data bucket's key (S3_ACCESS_KEY); give backups a key of their own"
  fi
  export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
  AWS_ACCESS_KEY_ID="$(setting BACKUP_S3_ACCESS_KEY)"
  AWS_SECRET_ACCESS_KEY="$(setting BACKUP_S3_SECRET_KEY)"
}

need_age() {
  command -v age >/dev/null 2>&1 \
    || fail "age is not installed on this machine (Debian and Ubuntu: apt install age; docs/self-hosting.md, \"Backups\")"
}

# The recipients a backup is encrypted to: one or more public keys
# (age1…, or an ssh-ed25519/ssh-rsa line), separated by commas.
recipient_args=()
backup_recipients() {
  local value recipient list
  value="$(required KUTUP_BACKUP_AGE_RECIPIENT)"
  IFS=',' read -r -a list <<<"$value"
  for recipient in "${list[@]}"; do
    recipient="$(printf '%s' "$recipient" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
    [ -n "$recipient" ] || continue
    case "$recipient" in
      age1*|ssh-ed25519\ *|ssh-rsa\ *) recipient_args+=(-r "$recipient") ;;
      AGE-SECRET-KEY-*) fail "KUTUP_BACKUP_AGE_RECIPIENT holds a secret key: put the public key (age1…) there and keep the identity offline" ;;
      *) fail "KUTUP_BACKUP_AGE_RECIPIENT: not an age recipient: $recipient" ;;
    esac
  done
  [ "${#recipient_args[@]}" -gt 0 ] || fail "set KUTUP_BACKUP_AGE_RECIPIENT in .env"
}

encrypt() {
  age "${recipient_args[@]}" -o "$2" "$1"
}

# Decrypts and checks $1 with the identity file $3, into $2. Nothing is
# written to $2 unless every chunk authenticated: age stops at the first
# changed or missing byte, and a cut file fails at its end.
decrypt_checked() {
  local source="$1" target="$2" identity="$3" partial
  [ -r "$identity" ] || fail "cannot read the identity file $identity"
  partial="$(mktemp "${work_dir:?}/decrypt.XXXXXX")"
  if ! age -d -i "$identity" -o "$partial" "$source"; then
    rm -f "$partial"
    fail "the backup failed its integrity check, or $identity does not open it; nothing was written"
  fi
  mv "$partial" "$target"
}

# Checksums only where S3 requires one, as the server does: several
# S3-compatible stores reject the CLI's default trailers.
s3() {
  docker run --rm \
    -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY \
    -e AWS_DEFAULT_REGION="${region:-us-east-1}" \
    -e AWS_REQUEST_CHECKSUM_CALCULATION=when_required \
    -e AWS_RESPONSE_CHECKSUM_VALIDATION=when_required \
    -v "${work_dir:?}:/work" \
    amazon/aws-cli:2.37.9 --endpoint-url "$endpoint" "$@"
}

# The stored keys under $prefix ending in $1, oldest first.
stored_with() {
  s3 s3api list-objects-v2 --bucket "$bucket" --prefix "$prefix/" \
    --query 'Contents[].Key' --output text | tr '\t' '\n' | grep -E "$1" | sort || true
}

# A backup by its name from --list, or a local file, as a path on this
# machine (downloaded into the work directory).
encrypted_backup() {
  local name="$1"
  if [ -f "$name" ]; then
    printf '%s' "$name"
    return
  fi
  s3 s3 cp --only-show-errors "s3://$bucket/$prefix/$name" /work/fetched.age >&2
  printf '%s' "$work_dir/fetched.age"
}

# Records the backup just stored in the database (backup_runs), where
# /api/health/ready reads the newest backup's age.
# True when the database is an older chain's, not the wipe-2 baseline's: it has
# `users` and no `accounts`. That happens exactly once, for the backup a deploy
# takes right before it wipes such a database; it has no backup_runs table and
# no account_keys schema. A baseline database never matches, so nothing is
# skipped there.
database_predates_baseline() {
  local user database answer
  user="$(setting POSTGRES_USER)"
  database="$(setting POSTGRES_DB)"
  answer="$(docker compose exec -T postgres psql -tA -U "${user:-kutup}" -d "${database:-kutup}" \
    -c "SELECT to_regclass('public.users') IS NOT NULL AND to_regclass('public.accounts') IS NULL" \
    | tr -d '[:space:]')"
  [ "$answer" = t ]
}

record_run() {
  local kind="$1" name="$2" size="$3" user database
  if database_predates_baseline; then
    echo "backup: the database predates the baseline (no backup_runs); $name stored, not recorded"
    return 0
  fi
  user="$(setting POSTGRES_USER)"
  database="$(setting POSTGRES_DB)"
  printf '%s\n' \
    "INSERT INTO backup_runs (kind, name, size_bytes, finished_at) VALUES (:'kind', :'name', :size, now())" \
    "ON CONFLICT (kind) DO UPDATE SET name = EXCLUDED.name, size_bytes = EXCLUDED.size_bytes, finished_at = EXCLUDED.finished_at;" \
    | docker compose exec -T postgres psql --quiet -v ON_ERROR_STOP=1 \
      -v kind="$kind" -v name="$name" -v size="$size" \
      -U "${user:-kutup}" -d "${database:-kutup}" >/dev/null \
    || fail "stored $name, but could not record it for the readiness check"
}

# Removes backups older than $keep_days by the date in each name; the
# newest is never removed. $1: the name's pattern before the stamp, $2 after.
prune() {
  local before="$1" after="$2" cutoff key stamp
  cutoff="$(date -u -d "$keep_days days ago" +%Y%m%dT%H%M%SZ)"
  stored_with "${after//./\\.}\$" | sed '$d' | while read -r key; do
    stamp="$(basename "$key" | sed -n "s/^$before\([0-9]\{8\}T[0-9]\{6\}Z\)${after//./\\.}\$/\1/p")"
    if [ -n "$stamp" ] && [ "$stamp" \< "$cutoff" ]; then
      s3 s3 rm --only-show-errors "s3://$bucket/$key"
      echo "$label: removed $key (older than $keep_days days)"
    fi
  done
}
