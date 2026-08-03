# Chat security parser fuzzing

This standalone `cargo-fuzz` package drives the untrusted account-envelope,
Drive/collaboration/profile-envelope, account-manifest,
authenticated service-policy, sealed-sender, and MLS-control parsers. It is
excluded from the normal workspace so release builds do not acquire a nightly
toolchain or libFuzzer dependency.

The targets are:

- `account_envelope_parser`: strict suite/purpose/context/length parsing plus
  authenticated open attempts for every V1 account-envelope purpose;
- `drive_envelope_parser`: strict suite/purpose/UUID/epoch/revision/length
  parsing and authenticated open attempts for every V1 Drive-envelope purpose,
  signed collection-epoch statements, authenticated named-share envelopes and
  canonical encrypted collaboration frames;
- `profile_envelope_parser`: strict canonical profile-envelope base64/framing
  plus owner and peer encrypted-profile JSON DTO parsing;
- `account_policy_parsers`: account-signed manifests and bounded history pages,
  authenticated feature-policy envelopes and histories, and both typed Chat
  service policies;
- `sealed_sender_parsers`: anonymous and federated sealed-send JSON, sender
  certificates, libsignal unidentified-sender content, and raw libsignal
  sealed-sender outer envelopes through the real decrypt/parser entry point;
- `mls_control_parsers`: authority changes, old/new vote requests, finalized
  blocks, replicas, destination-private deliveries, bootstrap/history pages,
  and the mandatory private control state.

Install `cargo-fuzz`, then run both targets with a nightly toolchain:

```sh
cargo install cargo-fuzz
cd fuzz
cargo +nightly fuzz run account_envelope_parser -- -max_len=8192
cargo +nightly fuzz run drive_envelope_parser -- -max_len=131072
cargo +nightly fuzz run profile_envelope_parser -- -max_len=1048576
cargo +nightly fuzz run account_policy_parsers -- -max_len=2097152
cargo +nightly fuzz run sealed_sender_parsers -- -max_len=1048576
cargo +nightly fuzz run mls_control_parsers -- -max_len=8388608
```

CI and phase-gate smoke runs should add a bounded `-runs=10000`; scheduled
campaigns should use `-max_total_time` and retain a private evolving corpus.
Corpus and crash artifacts are deliberately ignored, while `Cargo.lock` is
committed so the harness uses the same pinned libsignal release on every run.

LeakSanitizer normally remains enabled. A process supervisor that ptraces the
fuzzer can make LeakSanitizer itself fail at shutdown; only in that environment,
set `ASAN_OPTIONS=detect_leaks=0` while retaining the address sanitizer and
coverage instrumentation.
