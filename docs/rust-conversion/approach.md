# Approach & conventions

## Methodology (from the Bun Zig→Rust port lessons)

- **Oracle-first / behavioral equivalence.** The frontend stays TypeScript and the Go
  code keeps working, so we port for **byte-identical** output, not "it compiles." The
  oracles are: vectors emitted by the real Go packages, the existing Go test suites, and
  the live Go services.
- **Default-deny verification.** A slice isn't "done" until its parity test (citing the
  Go lines it mirrors) passes.
- **Incremental, reviewable commits.** One slice per commit; never a squash that hides
  the per-slice history.

## Mirroring discipline

- Each Rust file opens with a `//! … mirrors <go file>` doc comment.
- Preserve wire formats **exactly**:
  - JSON keys camelCase (serde `rename_all = "camelCase"`).
  - printf-style JSON key **order** — `serde_json`'s `preserve_order` feature is enabled
    so `json!` output matches the Go CLI's `fmt.Printf` ordering.
  - HTTP header names, JWT claims + lifetimes, tus header semantics, AAD strings.
  - Identity: keychain service `kutup-cli`, binary name `kutup`.
- **No silent stubs.** If a slice can't be wired end-to-end yet, defer it **and** add an
  entry to `docs/roadmap.md` (precedent: the `.excalidraw` asset entry).

## Build / test / lint / commit

```sh
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt
```

- The server compiles offline (no DB needed unless using compile-checked `query!` macros).
- One reviewable slice per commit; the commit message ends with the session URL line.
- Develop only on `claude/go-rust-rewrite-G16zO`; push with `git push -u origin <branch>`.

## Known deferrals / open items

- `.excalidraw` asset extraction (upload) + hydration (download) in the CLI — needs the
  asset/snapshot API; regular files are fully correct. Tracked in `docs/roadmap.md`.
- Full Go test-suite port (Rust unit tests exist; parity suites pending).
- Live differential testing — needs a running stack on a VM (`scripts/verify-cli.sh`).
- utoipa ↔ Axum 0.7 version-matching (verify when adding OpenAPI).

## Environment facts

- Go modules: backend `github.com/kutup/backend`, CLI
  `github.com/kutupbulut/kutup/cmd/kutup`.
- Backend env vars: `DATABASE_URL`, `JWT_SECRET` (≥32 chars), `S3_ENDPOINT` /
  `S3_ACCESS_KEY` / `S3_SECRET_KEY` / `S3_BUCKET` / `S3_REGION`, `APP_ENV`,
  `ADMIN_ACCOUNT`, `SERVER_URL`, `ALLOWED_ORIGINS`, `STORAGE_TOTAL_BYTES`.
- Backend listens on `:3000`; nginx fronts it; the dev stack is at
  `https://localhost:38443` (self-signed cert).
