#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mode="${1:-}"
project="${2:-}"
output_dir="${KUTUP_E2E_DIAGNOSTICS_DIR:-$root_dir/tests/e2e/sanitized-results}"
if [[ "$output_dir" != /* ]]; then
  output_dir="$root_dir/tests/e2e/$output_dir"
fi

case "$mode" in
  single)
    compose_file="$root_dir/docker-compose.yml"
    services=(postgres)
    backends=(backend)
    gateways=(nginx)
    ;;
  federation)
    compose_file="$root_dir/docker-compose.chat-federation.yml"
    services=(postgres-a postgres-b)
    backends=(backend-a backend-b)
    gateways=(edge-a edge-b)
    ;;
  *)
    echo "usage: $0 single|federation [compose-project]" >&2
    exit 2
    ;;
esac

mkdir -p "$output_dir"

# The class of an error text (stdin, one per line) as a fixed label, with a
# constraint's name when it names one; counted. Nothing else of the text.
error_classes() {
  local line class constraint
  while IFS= read -r line; do
    constraint=""
    case "$line" in
      *"pool timed out"*) class=pool_timed_out ;;
      *"pool closed"*) class=pool_closed ;;
      *"deadlock detected"*) class=deadlock ;;
      *"could not serialize"*) class=serialization_failure ;;
      *"canceling statement due to lock timeout"*) class=lock_timeout ;;
      *"canceling statement due to statement timeout"*) class=statement_timeout ;;
      *"canceling statement"*) class=statement_canceled ;;
      *"violates unique constraint"*) class=unique_violation ;;
      *"violates check constraint"*) class=check_violation ;;
      *"violates foreign key constraint"*) class=foreign_key_violation ;;
      *"violates not-null constraint"*) class=not_null_violation ;;
      *"violates exclusion constraint"*) class=exclusion_violation ;;
      *"too many connections"* | *"remaining connection slots"*) class=too_many_connections ;;
      *"connection"*"closed"* | *"connection"*"lost"* | *"connection reset"* | *"broken pipe"* | *"Connection refused"*) class=connection_lost ;;
      *"invalid input syntax"* | *"invalid byte sequence"*) class=invalid_input ;;
      *"value too long"* | *"out of range"*) class=value_out_of_range ;;
      *"does not exist"*) class=missing_object ;;
      *"database error"*) class=database_other ;;
      *) class=other ;;
    esac
    if [[ "$line" =~ constraint\ \\?\"([a-z0-9_]{1,63})\\?\" ]]; then
      constraint=" constraint=${BASH_REMATCH[1]}"
    fi
    printf '%s%s\n' "$class" "$constraint"
  done | sort | uniq -c | awk '{ $1 = $1; n = $1; $1 = ""; sub(/^ /, ""); print $0 " count=" n }'
}

# A server request-failure line: its status (a number) and its class.
classify_request_failures() {
  local line status
  while IFS= read -r line; do
    status=""
    [[ "$line" =~ status=([0-9]{3}) ]] && status="${BASH_REMATCH[1]}"
    printf 'status=%s %s\n' "${status:-unknown}" "$(error_classes <<<"$line" | sed 's/ count=1$//')"
  done | sort | uniq -c | awk '{ n = $1; $1 = ""; sub(/^ /, ""); print $0 " count=" n }'
}

# A database log line: its severity and class.
classify_database_errors() {
  local line severity
  while IFS= read -r line; do
    severity=ERROR
    [[ "$line" =~ (FATAL|PANIC): ]] && severity="${BASH_REMATCH[1]}"
    printf 'severity=%s %s\n' "$severity" "$(error_classes <<<"$line" | sed 's/ count=1$//')"
  done | sort | uniq -c | awk '{ n = $1; $1 = ""; sub(/^ /, ""); print $0 " count=" n }'
}

compose=(docker compose)
if [[ -n "$project" ]]; then
  compose+=(--project-name "$project")
fi
compose+=(--file "$compose_file")

for service in "${services[@]}"; do
  # Only aggregate numbers and fixed labels leave the database. No account,
  # object, operation, digest, envelope, ciphertext, or storage-path value is
  # selected into the failure artifact.
  "${compose[@]}" exec -T "$service" psql -U kutup -d kutup -Atc "
    SELECT 'backup_accounts=' || COUNT(*) FROM chat_backups
    UNION ALL SELECT 'cursor_total=' || COALESCE(SUM(current_cursor), 0) FROM chat_backups
    UNION ALL SELECT 'generation_total=' || COALESCE(SUM(current_generation), 0) FROM chat_backups
    UNION ALL SELECT 'segment_count=' || COUNT(*) FROM chat_backup_segments
    UNION ALL SELECT 'base_count=' || COUNT(*) FROM chat_backup_bases
    UNION ALL SELECT 'media_object_count=' || COUNT(*) FROM chat_backup_media_objects
    UNION ALL SELECT 'media_reference_count=' || COUNT(*) FROM chat_backup_media_references
    UNION ALL SELECT 'storage_bytes_used=' || COALESCE(SUM(storage_used_bytes), 0) FROM accounts
    UNION ALL SELECT 'storage_bytes_quota_own=' || COALESCE(SUM(value), 0) FROM account_entitlements
                     WHERE key = 'account.storage_quota_bytes';
  " >"$output_dir/$service-database-counts.txt" 2>/dev/null ||
    printf '%s\n' 'database_counts_unavailable=1' >"$output_dir/$service-database-counts.txt"
done

for service in "${gateways[@]}"; do
  # Gateway logs can contain request paths and addresses, so retain only fixed
  # lifecycle/error counts. This distinguishes a crashed edge from an
  # unavailable upstream without publishing request data.
  logs="$("${compose[@]}" logs --no-color "$service" 2>/dev/null || true)"
  {
    printf 'emergency_lines=%s\n' "$(grep -Eic '(^|[^a-z])emerg([^a-z]|$)' <<<"$logs" || true)"
    printf 'fatal_lines=%s\n' "$(grep -Eic '(^|[^a-z])fatal([^a-z]|$)' <<<"$logs" || true)"
    printf 'connection_refused_lines=%s\n' "$(grep -Eic 'connection refused' <<<"$logs" || true)"
    printf 'upstream_unavailable_lines=%s\n' "$(grep -Eic 'host not found in upstream|no live upstreams' <<<"$logs" || true)"
  } >"$output_dir/$service-gateway-counts.txt"
  unset logs
done

for service in "${backends[@]}"; do
  # Logs are inspected in memory but never retained. Only severity/category
  # counts with fixed labels are safe to publish.
  logs="$("${compose[@]}" logs --no-color "$service" 2>/dev/null || true)"
  {
    printf 'error_lines=%s\n' "$(grep -Eic '(^|[^a-z])error([^a-z]|$)' <<<"$logs" || true)"
    printf 'warning_lines=%s\n' "$(grep -Eic '(^|[^a-z])warn(ing)?([^a-z]|$)' <<<"$logs" || true)"
    printf 'backup_failure_lines=%s\n' "$(grep -Eic 'chat[_ -]?backup.*(fail|error)|(fail|error).*chat[_ -]?backup' <<<"$logs" || true)"
    printf 'quota_lines=%s\n' "$(grep -Eic 'quota|storage[_ -]?full' <<<"$logs" || true)"
    printf 'timeout_lines=%s\n' "$(grep -Eic 'timeout|timed out' <<<"$logs" || true)"
  } >"$output_dir/$service-log-counts.txt"
  # What each failed request (a 5xx the server logged) failed on, as fixed
  # classes and the HTTP status only: never the message, a path or a value.
  # A constraint's name is schema, not data, so it is kept.
  grep -E 'request failed' <<<"$logs" | classify_request_failures >"$output_dir/$service-request-failures.txt" || true
  [[ -s "$output_dir/$service-request-failures.txt" ]] || echo 'request_failures=0' >"$output_dir/$service-request-failures.txt"
  unset logs
done

for service in "${services[@]}"; do
  # The database's own errors, by class (its log can quote statements and
  # values, so only the class and a constraint's name are kept).
  logs="$("${compose[@]}" logs --no-color "$service" 2>/dev/null || true)"
  grep -E '(ERROR|FATAL|PANIC):' <<<"$logs" | classify_database_errors >"$output_dir/$service-database-errors.txt" || true
  [[ -s "$output_dir/$service-database-errors.txt" ]] || echo 'database_errors=0' >"$output_dir/$service-database-errors.txt"
  unset logs
  # Who is waiting on what when the run failed: counts by state, wait event
  # and lock mode (fixed labels from the server's catalogs, no query text).
  "${compose[@]}" exec -T "$service" psql -U kutup -d kutup -Atc "
    SELECT 'activity ' || COALESCE(state, 'none') || ' ' || COALESCE(wait_event_type, '-') || '/' || COALESCE(wait_event, '-')
           || ' oldest_s=' || COALESCE(round(max(extract(epoch FROM now() - query_start)))::text, '-')
           || ' count=' || COUNT(*)
      FROM pg_stat_activity WHERE datname = current_database() AND pid <> pg_backend_pid()
     GROUP BY state, wait_event_type, wait_event
    UNION ALL
    SELECT 'locks ' || locktype || ' ' || mode || ' granted=' || granted || ' count=' || COUNT(*)
      FROM pg_locks GROUP BY locktype, mode, granted
    UNION ALL
    SELECT 'deadlocks=' || deadlocks || ' conflicts=' || conflicts || ' rollbacks=' || xact_rollback
      FROM pg_stat_database WHERE datname = current_database();
  " >"$output_dir/$service-database-activity.txt" 2>/dev/null ||
    printf '%s\n' 'database_activity_unavailable=1' >"$output_dir/$service-database-activity.txt"
done
