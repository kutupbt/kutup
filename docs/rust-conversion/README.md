# Go → Rust rewrite

Rewriting kutup's Go (`backend/`, `cmd/kutup/`) into Rust under a root Cargo workspace
(`crates/`). Order: **crypto → CLI → backend**. The Go code stays the source of truth
until each Rust piece passes its parity/test gate.

**Resuming with no prior context? Open [`resume-here.md`](resume-here.md).**

## Status

| Phase | Crate | State |
|---|---|---|
| 1 | `kutup-crypto` | ✅ complete, byte-verified vs Go (11 vector tests) |
| 2 | `kutup-cli` (`kutup`) | ✅ all 16 commands; live VM test pending |
| 3 | `kutup-server` | 🟡 scaffold only (config + db + `/health`) |

## Map

- [`approach.md`](approach.md) — how we work (mirroring rules, build/test/commit, deferrals, env)
- [`decisions.md`](decisions.md) — library choices + rationale + critical crypto facts
- [`crypto/`](crypto/README.md) · [`cli/`](cli/README.md) · [`server/`](server/README.md) — per-component docs
- [`resume-here.md`](resume-here.md) — start here next session

## One-liners

```sh
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt
```

Every commit must be clippy-`-D warnings` + `rustfmt` clean with tests passing.
Branch: `claude/go-rust-rewrite-G16zO`.
