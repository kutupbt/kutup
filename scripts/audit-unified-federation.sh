#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

feature_modules=(
  crates/kutup-server/src/chat_federation.rs
  crates/kutup-server/src/drive_federation.rs
)
runtime_paths=(
  crates/kutup-server/src
  frontend/src
  docker-compose.yml
  .env.example
)

fail_if_present() {
  local description="$1"
  local pattern="$2"
  shift 2
  if rg --quiet "$pattern" "$@"; then
    echo "unified federation audit failed: $description" >&2
    rg -n "$pattern" "$@" >&2
    return 1
  fi
}

require_present() {
  local description="$1"
  local pattern="$2"
  shift 2
  if ! rg --quiet "$pattern" "$@"; then
    echo "unified federation audit failed: $description" >&2
    return 1
  fi
}

fail_if_present \
  "feature-specific federation identity or signing-key configuration remains" \
  '(CHAT|DRIVE)_FEDERATION_(SERVER_NAME|SIGNING_KEY)' \
  "${runtime_paths[@]}"

fail_if_present \
  "a feature adapter creates its own HTTP client" \
  'reqwest::Client::(new|builder)|Client::(new|builder)\(' \
  "${feature_modules[@]}"

fail_if_present \
  "a feature adapter reads environment configuration or signing keys" \
  'std::env|env::var|get_env\(|SigningKey|signing_key' \
  "${feature_modules[@]}"

fail_if_present \
  "a feature adapter owns shared trust or admission-policy persistence" \
  'federation_(policy|feature_policies|domain_rules|peer_identities|peer_identity_documents)' \
  "${feature_modules[@]}"

fail_if_present \
  "a new raw remote federation URL field is present" \
  'remote_(api_base|server_url)|federated_(api_base|base_url)|remoteApiBase|remoteServerUrl|federatedBaseUrl' \
  "${runtime_paths[@]}"

fail_if_present \
  "a removed unsigned Drive federation route is registered" \
  '"/api/(fed-proxy|fed/users|fed/invites|fed/shares)' \
  crates/kutup-server/src frontend/src

require_present \
  "Chat is not wired to the shared FederationStack" \
  'configured_stack\(.*FederationStack|FederationStack' \
  crates/kutup-server/src/chat_federation.rs

require_present \
  "Drive is not wired to the shared FederationStack" \
  'configured_stack\(.*FederationStack|FederationStack' \
  crates/kutup-server/src/drive_federation.rs

require_present \
  "the common transport does not own HTTP client construction" \
  'reqwest::Client::builder' \
  crates/kutup-server/src/federation/transport.rs

require_present \
  "the server does not expose exactly one shared federation stack" \
  'federation: Option<Arc<federation::FederationStack>>' \
  crates/kutup-server/src/main.rs

echo "unified federation architecture audit passed"
