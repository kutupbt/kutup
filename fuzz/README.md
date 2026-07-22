# Chat security parser fuzzing

This standalone `cargo-fuzz` package drives every untrusted parser introduced
by the authenticated-policy, transparency, and sealed-sender milestones. It is
excluded from the normal workspace so release builds do not acquire a nightly
toolchain or libFuzzer dependency.

The targets are:

- `policy_transparency_parsers`: authenticated feature-policy envelopes and
  histories, both typed Chat policies, checkpoints, manifest range proofs,
  witness views, and fork evidence;
- `sealed_sender_parsers`: anonymous and federated sealed-send JSON, sender
  certificates, libsignal unidentified-sender content, and raw libsignal
  sealed-sender outer envelopes through the real decrypt/parser entry point.

Install `cargo-fuzz`, then run both targets with a nightly toolchain:

```sh
cargo install cargo-fuzz
cd fuzz
cargo +nightly fuzz run policy_transparency_parsers -- -max_len=2097152
cargo +nightly fuzz run sealed_sender_parsers -- -max_len=1048576
```

CI and phase-gate smoke runs should add a bounded `-runs=10000`; scheduled
campaigns should use `-max_total_time` and retain a private evolving corpus.
Corpus and crash artifacts are deliberately ignored, while `Cargo.lock` is
committed so the harness uses the same pinned libsignal release on every run.

LeakSanitizer normally remains enabled. A process supervisor that ptraces the
fuzzer can make LeakSanitizer itself fail at shutdown; only in that environment,
set `ASAN_OPTIONS=detect_leaks=0` while retaining the address sanitizer and
coverage instrumentation.
