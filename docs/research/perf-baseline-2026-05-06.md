# Performance baseline — 2026-05-06

Captured by Phase 6 benchmarks. Hardware: Intel Core Ultra 7 155U (linux/amd64).

Re-run with:

```sh
# backend
cd backend && go test -bench=. -benchmem -benchtime=1s ./services/envelope/

# frontend
cd frontend && pnpm vitest bench --run
```

## Backend — envelope (Pack / Unpack / Sign / Verify)

```
goos: linux
goarch: amd64
pkg: github.com/kutup/backend/services/envelope
cpu: Intel(R) Core(TM) Ultra 7 155U
BenchmarkPack_64B-7     16186342    62.93 ns/op    192 B/op    1 allocs/op
BenchmarkPack_4KB-7      1221266   981.3  ns/op   4864 B/op    1 allocs/op
BenchmarkPack_64KB-7       83050 16438    ns/op  73728 B/op    1 allocs/op
BenchmarkUnpack_4KB-7    1000000  1153    ns/op   4096 B/op    1 allocs/op
BenchmarkSign_4KB-7        51045 23777    ns/op      0 B/op    0 allocs/op
BenchmarkVerify_4KB-7      32623 38192    ns/op      0 B/op    0 allocs/op
```

Pack of a 4 KB frame is ~1 µs (single alloc — the output buffer).
Verify of an Ed25519 signature on a 4 KB body is ~38 µs — that's the
floor on backend WS frame ingest (~26 K verifies/sec/core).

## Frontend — symmetric (libsodium AEAD)

```
secretbox encrypt
  1 KB    26,088 hz   ~38 us/op
  1 MB       391 hz   ~2.5 ms/op

secretbox decrypt
  1 KB   261,851 hz   ~3.8 us/op
  1 MB       396 hz   ~2.5 ms/op

secretstream (file content, 5 MB chunks)
  encrypt 1 MB    ~2.3 ms/op
  encrypt 5 MB   ~13.4 ms/op
  decrypt 1 MB    ~2.4 ms/op
  decrypt 5 MB   ~13.6 ms/op
```

A 5 MB file chunk costs ~13 ms each direction. A 100 MB upload (20
chunks) is ~260 ms of crypto — dwarfed by network. Acceptable.

## Frontend — Argon2id KDF

64 MB / 3 iterations / 4 threads. Single-op only — bench at
`frontend/src/crypto/kdf.bench.ts`. Expect **800 ms – 2 s per op** on
this hardware. Run on demand:

```sh
cd frontend && pnpm vitest bench --run src/crypto/kdf.bench.ts
```

The slowness is intentional and load-bearing for password-attack
resistance. A regression dropping this below ~250 ms would mean the
KDF parameters got weakened — that's the canary case for kdf.bench.ts.

## Regression policy

2x slowdown on any of the above is a flag. Re-run before declaring any
performance milestone. The bench files don't gate CI (too slow for
per-commit) but `bin/test-all` (Phase 7) runs them in capture mode for
release notes.
