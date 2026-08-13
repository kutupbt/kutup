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
    ;;
  federation)
    compose_file="$root_dir/docker-compose.chat-federation.yml"
    services=(postgres-a postgres-b)
    backends=(backend-a backend-b)
    ;;
  *)
    echo "usage: $0 single|federation [compose-project]" >&2
    exit 2
    ;;
esac

mkdir -p "$output_dir"

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
    UNION ALL SELECT 'chat_bytes_used=' || COALESCE(SUM(chat_storage_used_bytes), 0) FROM users
    UNION ALL SELECT 'chat_bytes_quota=' || COALESCE(SUM(chat_storage_quota_bytes), 0) FROM users;
  " >"$output_dir/$service-database-counts.txt" 2>/dev/null ||
    printf '%s\n' 'database_counts_unavailable=1' >"$output_dir/$service-database-counts.txt"
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
  unset logs
done
