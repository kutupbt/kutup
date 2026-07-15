# Spike: libsignal-protocol on wasm32 — **verdict: GO**

Phase-1 gate of the federated-chat track (`docs/research/11-federated-chat.md` §5).
Question: does `libsignal-protocol` v0.97.2 (PQXDH + Triple Ratchet + SPQR) compile and
run on wasm32, so the web chat client can share `kutup-chat-core` with native clients?

**Answer: yes, on both axes** (run 2026-07-12, host rustc 1.96.0 stable):

| Check | Result |
|---|---|
| Compile for `wasm32-unknown-unknown` (browser target, getrandom `wasm_js` backend) | ✅ 831 KB `.wasm` (release, `opt-level=z`, LTO, stripped) |
| Compile for `wasm32-wasip1` | ✅ 527 KB `.wasm` |
| Execute full protocol round-trip **in wasm** (Node 22 built-in WASI) | ✅ 28 ms: PQXDH (Kyber1024) session establishment + 8 bidirectional Triple-Ratchet round-trips, wire-format re-parse each hop, `SessionUsabilityRequirements::all()` (`NotStale \| EstablishedWithPqxdh \| Spqr`) satisfied on both sides after ratcheting |
| Nightly toolchain needed? | ❌ No — libsignal pins `nightly-2026-07-07` for its own dev tooling, but the crates are edition-2024 / MSRV 1.85–1.88 and build on stable |

Wire-size data points: `PreKeySignalMessage` = 1762 B (Kyber1024 ciphertext dominates),
steady-state `SignalMessage` = 105 B for a 13 B plaintext.

## Run it

```sh
# protoc must be on PATH (libsignal's prost-build codegen)
cargo run --release                                    # native sanity check
cargo build --release --target wasm32-wasip1
node run-wasi.mjs                                      # the wasm proof
cargo build --release --target wasm32-unknown-unknown  # browser-target compile proof
```

## Friction log (everything phase 2 needs to know)

1. **protoc** is required at build time (`prost-build`); a prebuilt release binary on PATH
   suffices — no system install needed.
2. **Two getrandom majors** are in the tree and both need browser opt-ins:
   getrandom 0.3 (via rand 0.9) needs feature `wasm_js` **plus**
   `--cfg getrandom_backend="wasm_js"` in rustflags (see `.cargo/config.toml`);
   getrandom 0.2 (via RustCrypto's rand_core 0.6) needs feature `js`.
3. **Clock discipline for browsers**: `std::time::SystemTime::now()` panics on
   `wasm32-unknown-unknown`. libsignal's production API takes `now: SystemTime` as a
   parameter almost everywhere — the one exception found is the convenience constructor
   `KyberPreKeyRecord::generate` (`state/kyber_prekey.rs`). Rule for `kutup-chat-core`:
   always use explicit-timestamp constructors and derive `now` from `Date.now()` at the
   JS boundary.
4. **Async stores**: the libsignal store traits are async; with in-memory stores every
   future is immediately ready, so `now_or_never()` drives them (works in a browser
   too). Real IndexedDB-backed stores are genuinely async ⇒ the wasm-bindgen wrapper
   must run on `wasm-bindgen-futures`. Not a risk, just an architecture note.
5. **Not exercised here** (phase-2 work, low risk): the wasm-bindgen JS glue itself,
   IndexedDB store implementations, and Safari/Firefox smoke tests. The crypto — the
   actual go/no-go risk — is proven above.

This crate is intentionally **outside the root Cargo workspace** (like `src-tauri/`) so
the app's `cargo build`/`cargo test` never pays for the libsignal dependency tree.
