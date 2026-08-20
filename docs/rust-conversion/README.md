# Go → Rust rewrite (historical record)

**Status:** complete. The former `backend/` and `cmd/kutup/` Go trees were
removed after the Rust cutover. Current development happens in `crates/`.

This directory preserves the conversion methodology, phase plans, parity
notes, and old route inventory. Old branch names, Go paths, command counts, and
“next slice” instructions describe the conversion at the time they were
written; they are not current contribution instructions.

## Current replacements

| Former component | Current implementation | Current documentation |
|---|---|---|
| Go backend | `crates/kutup-server` | [`../api.md`](../api.md), [`../architecture.md`](../architecture.md) |
| Go CLI | `crates/kutup-cli` | [`../../README.md`](../../README.md#cli) |
| Duplicated Go/TypeScript formats | `crates/kutup-crypto` + `kutup-crypto-wasm` | [`../cryptographic-dependencies.md`](../cryptographic-dependencies.md) |

The root workspace gate is:

```sh
cargo test --locked --workspace --all-targets
cargo fmt --all -- --check
```

The standalone Chat core, native FFI, and fuzz workspaces have their own gates
in [`../contributing.md`](../contributing.md) and the CI workflow.

## Historical index

- [`resume-here.md`](resume-here.md) contains the final cutover record followed
  by the original slice journal.
- [`approach.md`](approach.md) and [`decisions.md`](decisions.md) record the
  parity methodology and dependency choices.
- [`crypto/`](crypto/README.md), [`cli/`](cli/README.md), and
  [`server/`](server/README.md) contain component-specific records.
