# Repository-wide documentation audit

**Status:** complete

**Written and completed:** 2026-08-20

**Scope:** every tracked `*.md`/`*.mdx` file, plus repository entry points,
current implementation/configuration surfaces, and a new documentation index

## Outcome

Make the Markdown tree accurately separate:

- the shipped responsive web product and its Drive, collaboration, Office,
  Chat, federation, media, and continuous-recovery features;
- the implemented but pre-release Tauri desktop shell;
- the dedicated iOS and Android apps that are actively being developed but are
  not release-ready;
- current operational, protocol, security, API, and test contracts; and
- historical research/plans whose old paths and pre-fix statements are useful
  records but not current instructions.

This audit changes documentation only. It does not change runtime behavior,
wire formats, database schemas, CI policy, quotas, retention, or licensing.

## Findings corrected

1. The README mentioned Chat but compressed its shipped feature set into one
   paragraph; it now presents Direct, MLS, trust, messaging mutations, media,
   dedicated quota, and continuous recovery as a first-class product surface.
2. The README linked an interactive Swagger UI that the Rust server does not
   bundle. It now points to the actual generated OpenAPI JSON.
3. There was no documentation index explaining which files are current,
   normative, research, draft, completed plans, or conversion history.
4. Mobile documentation described Tauri iOS/Android wrappers as the product
   apps. The dedicated native apps actually live in sibling repositories, are
   work in progress, and are not release-ready; retained Tauri mobile commands
   are experimental.
5. The contributor tree omitted the Chat, federation, WASM, native-FFI, fuzz,
   and browser-test surfaces and documented older toolchain versions.
6. The self-hosting configuration example omitted stable account-domain,
   database-name/user, S3-region, federation-rotation, and MLS configuration
   variables present in `.env.example` and Compose.
7. The roadmap still called shipped collaboration and version history open
   research and mixed responsive-web mobile gaps with native-app readiness.
8. The research index omitted several records; the Office lock/formatting
   investigations still said resolved regressions were open.
9. Go-to-Rust conversion pages still presented a scaffold, old branch, deleted
   Go backend, and differential oracle as active instructions.
10. Older collaboration, UI, Office, crypto-agility, and media plans lacked
    clear implemented/superseded/baseline notices.
11. The Tauri icon guide said real icons had not landed although the complete
    generated desktop set is checked in.

## Files intentionally preserved

- Legal and attribution records (`TRADEMARK.md`, license and OnlyOffice notice
  files) were checked but not editorially rewritten beyond already-current
  integration status; their wording is not a feature-status surface.
- Verbatim external-review inputs under `docs/draft/v1/comments/` remain
  unchanged because their directory README and per-file headers already state
  that they are preserved, non-normative inputs.
- Normative protocol/threat-model/API documents that already matched routes,
  migrations, current implementation, and test gates were not churned merely
  to make every file appear in the diff.
- Time-stamped research bodies and implementation plans retain historical code
  excerpts and paths after prominent status notices; rewriting those excerpts
  would erase the evidence the archive exists to preserve.

## Verification

- Audited all 92 tracked Markdown files and the new `docs/README.md`.
- Checked every repository-local Markdown link target.
- Compared living setup/config claims with `.env.example`, Compose, package
  manifests, Cargo workspace membership, the Axum route tree, frontend routes,
  test scripts, and `.github/workflows/ci.yml`.
- Searched current-state docs for the former organization URL, shared
  Drive/Chat quota, HTTP-only proxy, optional Compose Office installation,
  supported device transfer, nonexistent Swagger UI, shipped-native-app, and
  unresolved Office-stall claims.
- Ran `docker compose config --quiet` and `git diff --check`.

No application test suite is required for prose-only changes; executable
configuration validation and documentation consistency checks are the relevant
gates.
