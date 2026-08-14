# Current-state documentation refresh

**Status:** complete

**Written:** 2026-08-14

**Completed:** 2026-08-14

**Scope:** repository entry points, current-state architecture and operations,
continuous E2EE Chat backup, contributor/E2E instructions, roadmap status, and
superseded design records

## Outcome

Make the Markdown tree describe the code and required gates merged through
continuous Chat backup PR #41. A new reader should be able to distinguish:

- shipped/current behavior in `README.md` and `docs/*.md`;
- operational requirements and exact local test commands;
- historical design records under `docs/plans/`, `docs/draft/`, and
  `docs/rust-conversion/`; and
- genuinely deferred product work in `docs/roadmap.md`.

This refresh does not change a wire format, API, retention policy, quota, or
runtime behavior. When prose and code disagree, the merged migrations, route
tree, frontend behavior, and required CI workflow are authoritative.

## Audit findings

1. `README.md` presents Kutup primarily as Drive/collaboration and omits the
   shipped Direct/MLS Chat, encrypted media, and automatic continuous-history
   recovery. Its clone URL still targets the former GitHub organization.
2. `docs/contributing.md` and `docs/self-hosting.md` use the same old clone URL.
   The contributor OpenAPI paragraph says path annotations are deferred even
   though route coverage is now enforced.
3. `docs/self-hosting.md` says the bundled proxy is HTTP-only and that TLS is a
   manual second server block. The actual Compose stack exposes 38080/38443,
   redirects HTTP to HTTPS, mounts `nginx/certs`, and cannot become healthy
   without `fullchain.pem` and `privkey.pem`.
4. `docs/chat-media.md`, `docs/self-hosting.md`, and part of
   `docs/roadmap.md` say Drive and Chat share one 10 GiB account quota.
   Migration 042 moved all Chat media and backup bytes to the dedicated
   `chat_storage_*` quota, whose default is 2 GiB.
5. `docs/architecture.md` still lists attachments, receipts, typing,
   disappearing messages, and backup as future roadmap work and omits Chat
   backup from the key hierarchy, object-storage model, and database summary.
6. The backup design and hardening plans retain pre-completion status text even
   though their implementation and required PR gates landed. Only the ten-run
   default-branch rollout observation remains open.
7. `tests/e2e/README.md` ends at spec 31, says spec 05 is currently failing,
   and omits the clean-browser and two-server backup gates, sanitized-artifact
   mode, TLS setup, and zero-retry policy.
8. Current backup behavior is spread across an implementation plan, API list,
   and isolated threat-model rows. There is no concise current-state protocol
   document or dedicated backup threat model to serve as the stable reference.
9. The self-hosting backup recipe omits SeaweedFS filer/S3 namespace metadata.
   In the checked-in topology the upstream embedded filer store is
   container-local at `/filerldb2`, so archiving only `data/` is not a complete
   recovery point.

## Completion record

The refresh updated the repository entry points, API/curl base URLs, desktop
development URL guidance, architecture, Chat protocol/media/security docs,
self-hosting TLS/quota/retention/backup procedures, contributor and E2E guides,
roadmap claims, backup implementation records, the partially implemented media
preview plan, and the superseded device-transfer draft.

`docs/chat-backup.md` and `docs/chat-backup-security-threat-model.md` now provide
the concise current-state contract. The self-hosting guide explicitly includes
the container-local filer metadata in a recovery set and identifies durable
filer storage as a production prerequisite; changing that runtime topology and
migrating existing filer metadata remains a separate infrastructure change.

Verification passed for every repository-local Markdown link target,
`docker compose config --quiet`, the exact required CI job-name references,
active-document stale-claim searches, and `git diff --check`. Compose emitted
only its pre-existing warning that the top-level `version` attribute is
obsolete.

## Work plan

### 1. Entry points

- Update `README.md` to cover Chat, dedicated Chat storage, continuous recovery,
  current URLs, and links to the normative Chat documents.
- Update `CLAUDE.md` and `docs/contributing.md` so their architecture, OpenAPI,
  local-stack, and required backup/federation test guidance matches the repo.

### 2. Current-state Chat backup references

- Add `docs/chat-backup.md` as the concise current-state product/protocol and
  lifecycle reference. Link to `docs/api.md` for HTTP shapes and retain the
  large implementation plan as a historical design record.
- Add `docs/chat-backup-security-threat-model.md` for archive confidentiality,
  integrity, rollback, quota, compaction, media, deletion, diagnostics, and the
  residual fresh-device rollback limitation.
- Link both documents from the architecture, Chat protocol, media protocol,
  security models, API reference, and V1 format inventory where relevant.

### 3. Operations and product-state corrections

- Correct the bundled TLS/certificate procedure and reverse-proxy examples in
  `docs/self-hosting.md`.
- Document the dedicated default 2 GiB Chat quota, its three UI categories,
  30-day mailbox and 45-day temporary-media defaults, protected-media
  exemption, account-purge behavior, and operator backup requirements.
- Update architecture and media descriptions to the shipped feature boundary.
- Remove branch-name status claims and contradictory 10 GiB shared-quota text.

### 4. Plans, roadmap, and superseded records

- Mark the continuous-backup and test-hardening plans as implemented and
  required-PR-gate complete, while retaining the ten consecutive default-branch
  runs as rollout observation rather than claiming it happened.
- Add a completion record with the merged CI job names and local repetition
  evidence.
- Keep the device-transfer draft as a clearly historical, non-implementable
  record and point it at the current backup reference.
- Reconcile the roadmap's shipped Chat phase and quota text without converting
  the roadmap into release history.

### 5. Test documentation

- Expand `tests/e2e/README.md` through specs 32–34 and document exact commands
  for single-server recovery, isolated Postgres/SeaweedFS lifecycle, and the
  full two-server gate.
- Document `retries: 0`, bounded readiness, safe-artifact mode, sanitized
  diagnostics, disposable Compose projects, and local-first CI reproduction.

## Verification

The refresh is complete when:

- repository-local Markdown links and referenced paths resolve;
- no active/current-state document claims that device transfer is available;
- no active/current-state document says Chat media is charged to the Drive
  quota or that the bundled Nginx is HTTP-only;
- clone URLs match the configured `origin` repository;
- documented commands and CI job names match scripts and `.github/workflows/ci.yml`;
- Markdown formatting and `git diff --check` pass; and
- the plan status is changed to complete with a concise completion record.

## Non-goals

- Rewriting historical research and Rust-conversion journals as current docs.
- Claiming the ten consecutive default-branch rollout runs before the evidence
  exists.
- Adding a user-visible backup export/download or restoring device transfer.
- Changing production configuration merely to make an old document true.
