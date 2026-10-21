# Load test: what one box carries

Status: partly measured 2026-10-20 (second session), at the user's request, to
replace the estimate of ~1–3k active users with numbers. Never run against
kutup.dev. **Deferred on 2026-10-21 (the user: finish the product first):**
the runs at 1000+ users and at 4 and 6–8 vCPU are still to do; the
generator, the stack and the results so far are kept here.

## How it was measured

**The generator** (`crates/kutup-loadtest`, a Cargo root of its own because it
links Chat core) drives virtual users through the real client code paths, so
the crypto and the request shapes are what browsers send:
- **Accounts:** OPAQUE sign-up with the identity keys, a full OPAQUE sign-in
  that opens the master key, and session refreshes.
- **Drive:** a folder of the user's own; files encrypted as the apps do (the
  typed file blob, 5 MiB secretstream chunks) and uploaded with tus, one
  encrypted chunk per PATCH; downloads decrypted and checked; folder listings.
- **Chat:** Chat core's engine (as `WasmChatClient` runs it in the browser:
  device registration, identity pins, sealed sending as the server advertises
  it, the signed manifest, the profile) on an in-memory store; users in pairs,
  one writing first (a message request) and the other accepting it; texts and
  typing at Poisson-random times; every text answered with delivery and read
  receipts; the WebSocket held open, its nudges answered with the web's
  reconcile pass. Each text carries its send time, so delivery is timed from
  sender to reader.
- **Mail:** the address's OpenPGP key made and published with its signed key
  list; messages between users encrypted to both ends (`encrypt_split`); the
  inbox listed; messages downloaded and decrypted.
- **Idle clients:** signed-in users that only hold the Chat WebSocket open.

A **busy user's minute** (`scenario.rs` defaults): 2 texts and 2 typing
indicators (each text answered with 2 receipts), 1 folder listing, 0.4
downloads, 0.2 uploads (16 KiB 50%, 256 KiB 30%, 2 MiB 15%, 12 MiB 5%), 0.5
inbox listings, 0.3 opened messages, 0.1 sent messages, a refresh every 15
minutes and a full sign-in now and then. That is far busier than an average
account: most accounts are idle most of the day.

**The stack** (`tests/load/docker-compose.load.yml`, run by `tests/load/run.sh`)
is the production compose with every container that runs on the box pinned to
the same cores (`cpuset`), so they share exactly that much CPU, as on one VM.
SeaweedFS stands in for R2, which is off the box, so it has cores of its own.
The generator runs on the remaining cores, and is sampled too, to show it never
was the bottleneck. There was no sudo for one 4 GB cgroup, so memory isn't
capped: each container's is recorded, and their total is compared with the
box's 4 GB. The runs hit the backend directly; nginx, the frontend, Stalwart
and LiveKit run on the production box too, and their idle memory is added
below.

The dev VM has 8 cores, so the stack is measured at 2 vCPU (the box) and 4;
an 8-vCPU stack would leave the generator no cores.

## Results

Measured at 2 vCPU (the box), the steady scenario (five minutes of ramp, ten
held). Both runs had **no errors**.

**Resources** (CPU in cores; memory of the services the box runs):

| | 200 users | 500 users |
| --- | --- | --- |
| backend CPU, mean / peak | 0.08 / 0.17 | 0.19 / 0.29 |
| Postgres CPU, mean / peak | 0.10 / 0.22 | 0.19 / 0.34 |
| backend memory, peak | 38 MiB | 54 MiB |
| Postgres memory, peak | 419 MiB | 683 MiB |
| box services' memory, peak | 452 MiB of 4096 | 731 MiB of 4096 |
| Postgres connections, peak (active) | 18 (2) | 18 (2) |
| Postgres commits a second | 466 | 1165 |
| generator CPU, peak | — | 0.39 cores |

**Latency, p50 / p95 / p99 in ms** (500 users; the 200-user run within a few
milliseconds of it):

| operation | p50 | p95 | p99 |
| --- | --- | --- | --- |
| chat delivered, sender to reader | 9 | 24 | 99 |
| chat text sent | 4.6 | 10.7 | 42 |
| chat receipt | 4.6 | 9.9 | 16.9 |
| chat reconcile pass | 4.6 | 10.3 | 19.6 |
| Drive folder listing | 1.2 | 3.4 | 26.7 |
| Drive download | 3.8 | 25.6 | 49.2 |
| Drive upload, 16 KiB / 2 MiB / 12 MiB | 10.7 / 28.3 / 116.7 | 19.2 / 46.9 / 165.4 | 97.5 / 120.2 / 197.4 |
| Mail inbox listing | 1.4 | 3.7 | 15.6 |
| Mail send | 10.1 | 20.0 | 43.0 |
| sign-in (OPAQUE, full) | 88.6 | 178.6 | 236.7 |
| sign-up | 127.9 | 238.0 | 305.2 |

From 200 to 500 users CPU and Postgres memory grew about in proportion and
latencies hardly moved: at 2 vCPU the box is far from its ceiling at 500
busy users (each far busier than an average account), using about a fifth of
its CPU.

**Not counted:** a first 1000-user run reused the 500-user stack, and the
isolated stack's explicit `RATE_LIMIT_REGISTER_PER_HOUR=1000` (which wins over
`RATE_LIMITS_RELAXED`) refused half its sign-ups. `tests/load/run.sh` now
starts every run on a fresh stack, and the load compose raises every limit the
isolated stack pins.

## Still to do

- 2 vCPU at 1000 and 2000 users, to find where p95s or errors break.
- 4 vCPU from 1000 users up, and a 6-vCPU stack: the dev VM has 8 cores, and
  the generator and SeaweedFS need two, so 8 vCPU is extrapolated from 2, 4
  and 6 (the method stated with the numbers).
- The sockets scenario (idle connected clients) for memory per connection.
- Idle memory of nginx, the frontend, Stalwart and LiveKit, added to the
  box's total; a LiveKit load test (`lk`) and a TURN check.
- Replace the estimate table in the planning notes with these numbers.

`tests/load/run.sh <label> --scenario tests/load/scenarios/steady.toml
--users N` runs one; the cores are set by `KUTUP_LOAD_STACK_CPUS`,
`KUTUP_LOAD_STORE_CPUS` and `KUTUP_LOAD_GEN_CPUS`; `tests/load/summarize.py`
prints the tables.
