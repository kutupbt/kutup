# Account-protection Rust/WASM baseline — 2026-07-29

This is an implementation-selection baseline, not a mobile performance claim.
It checks the V1 rule in `docs/cryptographic-dependencies.md`: Kutup retains a
narrow browser-only primitive adapter only when the canonical Rust/WASM
operation is at least ten times slower or cannot complete.

## Compared operation

- Argon2id, 64 MiB, three iterations, one lane, 32-byte output;
- identical password bytes and 16-byte salt;
- release Rust/WASM from `kutup-crypto`/`kutup-crypto-wasm` using `argon2`;
- the previously used `libsodium-wrappers-sumo` WASM implementation using
  `crypto_pwhash` and `crypto_pwhash_ALG_ARGON2ID13`.

The timed Rust operation also performs the two HKDF-SHA-256 subkey expansions,
so this comparison slightly favors the primitive-only libsodium measurement.

## Result

Environment: local x86-64 Node.js runtime, one warm module load, one timed
operation per implementation.

| Implementation | Time |
| --- | ---: |
| canonical Rust/WASM | 187.9 ms |
| libsodium WASM | 158.5 ms |
| Rust/libsodium ratio | 1.19× |

The measured ratio is far below the 10× exception threshold. V1 therefore
keeps the canonical Rust/WASM path and does not retain a second Argon2id
implementation.

## Remaining gate

Before a stable V1 tag, repeat this measurement in a Web Worker on a mid-range
Android browser and record peak linear memory, failure behavior under memory
pressure, and UI responsiveness. A browser or device failure can justify the
narrow adapter even when the desktop ratio does not; it cannot move envelope
format, validation, derivation labels, or policy ownership out of Rust.
