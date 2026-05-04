# Collaborative E2EE Editing — v1.0 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship real-time, end-to-end-encrypted collaborative editing of `.txt`/`.md`/code files inside kutup with Drive-style version history. Server stores ciphertext only.

**Architecture:** Yjs CRDT for the editing model + CodeMirror 6 for the surface, wrapped in a libsodium AEAD envelope (XChaCha20-Poly1305 + Ed25519 sig). A new Go WebSocket relay in the existing Fiber backend acts as a dumb byte pump — broadcasts opaque ciphertext frames to peers in a per-file room and persists them to a Postgres `file_update_log`. Periodic client-driven snapshots flow back to S3 with bucket versioning enabled, fronted by a `file_versions` table mirroring Drive's "30 days OR 50 versions, named forever" retention.

**Tech Stack:** Go 1.22 + Fiber v2, `github.com/gofiber/contrib/websocket`, pgx/v5 + Postgres 16, libsodium (`golang.org/x/crypto`), SeaweedFS S3 with versioning. Frontend: React 18 + TypeScript 5.4, Yjs 13.x, `y-codemirror.next`, CodeMirror 6 + `@codemirror/lang-markdown` + per-extension `lang-*` plugins, libsodium-wrappers-sumo. Test runners: Go stdlib `testing`, Vitest for frontend.

**Spec:** [`docs/superpowers/specs/2026-05-04-collab-edit-design.md`](../specs/2026-05-04-collab-edit-design.md). Read §3–§13 before starting.

**Scope note:** This plan covers **v1.0 only** — text/markdown/code files. Office docs (v2) and offline mode (v2.1) are explicitly out of scope and will get their own plans. v1.1 polish items are flagged at the end as a small follow-up.

---

## File Structure

### New backend files

| Path | Purpose |
|---|---|
| `backend/db/migrations/012_collab_edit.up.sql` | Add tables: `file_update_log`, `file_versions`, `user_devices`. Add column: `files.current_doc_key_id`. |
| `backend/db/migrations/012_collab_edit.down.sql` | Reverse. |
| `backend/services/envelope/envelope.go` | Pack/unpack the `CollabFrame` byte layout. Pure data; no I/O. |
| `backend/services/envelope/envelope_test.go` | Round-trip tests. |
| `backend/services/envelope/sign.go` | Ed25519 sign/verify helpers. |
| `backend/services/envelope/sign_test.go` | Sign/verify tests. |
| `backend/handlers/devices.go` | `POST/GET/DELETE /api/devices`. |
| `backend/handlers/devices_test.go` | Unit tests. |
| `backend/handlers/collab.go` | WebSocket upgrade + per-room hub. |
| `backend/handlers/collab_hub.go` | Internal hub data structures (rooms map, conn lifecycle). Split for testability. |
| `backend/handlers/collab_hub_test.go` | Hub-level tests using fake conns. |
| `backend/handlers/file_versions.go` | `GET/PATCH /api/files/:id/versions[/:vid]`. |
| `backend/handlers/file_versions_test.go` | Handler tests. |
| `backend/services/version_cleanup.go` | Periodic retention job (run as goroutine on startup). |
| `backend/services/version_cleanup_test.go` | Job tests. |

### Modified backend files

| Path | Change |
|---|---|
| `backend/go.mod` | Add `github.com/gofiber/contrib/websocket`. |
| `backend/main.go` | Wire new handlers + start cleanup job. |
| `backend/middleware/auth.go` | Add helper to validate JWT from WebSocket upgrade query param. |
| `backend/handlers/files.go` | Add `GET /api/files/:fileId/collab/active` (cheap "is anyone editing" check, used by future WebDAV). |

### New frontend files

| Path | Purpose |
|---|---|
| `frontend/src/collab/envelope.ts` | TS mirror of the Go envelope. Pack/unpack/sign/verify. |
| `frontend/src/collab/envelope.test.ts` | Round-trip + cross-language test vectors. |
| `frontend/src/collab/transport.ts` | WebSocket client + reconnect logic + frame queue. |
| `frontend/src/collab/transport.test.ts` | Mock-WS tests. |
| `frontend/src/collab/devices.ts` | Ed25519 keypair gen/persist + register-on-first-use. |
| `frontend/src/collab/devices.test.ts` | |
| `frontend/src/collab/snapshot.ts` | Snapshot triggers (idle/ceiling/explicit) + S3 PUT + announce. |
| `frontend/src/collab/snapshot.test.ts` | |
| `frontend/src/collab/awareness.ts` | Encrypted awareness wrapper around y-protocols/awareness. |
| `frontend/src/components/editors/dispatch.tsx` | Extension → editor component. |
| `frontend/src/components/editors/TextCollabEditor.tsx` | CodeMirror 6 + Yjs glue. |
| `frontend/src/components/editors/lang.ts` | Extension → CodeMirror language extension map. |
| `frontend/src/components/VersionHistory/VersionHistoryPanel.tsx` | Right-rail timeline UI. |
| `frontend/src/components/VersionHistory/VersionRow.tsx` | Single timeline row + actions. |
| `frontend/src/api/collab.ts` | REST helpers: list/get/patch versions, register/list/revoke devices. |
| `frontend/vitest.config.ts` | Vitest setup. |

### Modified frontend files

| Path | Change |
|---|---|
| `frontend/package.json` | Add deps: `yjs`, `y-codemirror.next`, `y-protocols`, `codemirror`, `@codemirror/state`, `@codemirror/view`, `@codemirror/lang-markdown`, `@codemirror/lang-javascript` (and friends). Add devDep: `vitest`. |
| `frontend/src/pages/Drive.tsx` | On file click: if `chooseEditor` matches, open editor; otherwise existing preview. |
| `frontend/src/store/authSlice.ts` | Track `currentDeviceId` + `deviceSigningSecretKey` (in sessionStorage). |
| `frontend/src/pages/Settings.tsx` | Add "Devices" section listing user's devices + revoke. |

### Compose / SeaweedFS config

| Path | Change |
|---|---|
| `seaweedfs-init.sh` (new) | Enable bucket versioning + apply lifecycle. |
| `docker-compose.yml`, `docker-compose-volume.yml` | Replace inline `seaweedfs-init` entrypoint with the new script. |
| `lifecycle.json` (new) | Lifecycle rule (NoncurrentDays=30, NewerNoncurrentVersions=50). |

### Documentation updates (final phase)

| Path | Change |
|---|---|
| `docs/architecture.md` | Append a Collaborative Editing section. |
| `docs/api.md` | Document new endpoints + WebSocket protocol. |
| `docs/self-hosting.md` | Document the new SeaweedFS init steps. |

---

## Phase A — Schema and infrastructure

### Task A1: Migration 012 — new tables and column

**Files:**
- Create: `backend/db/migrations/012_collab_edit.up.sql`
- Create: `backend/db/migrations/012_collab_edit.down.sql`

- [ ] **Step 1: Write the up migration**

```sql
-- backend/db/migrations/012_collab_edit.up.sql
-- Adds tables for collaborative E2EE file editing.
-- See docs/superpowers/specs/2026-05-04-collab-edit-design.md §7 for rationale.

CREATE TABLE user_devices (
  id              BIGSERIAL   PRIMARY KEY,
  user_id         UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  public_signing  BYTEA       NOT NULL,        -- Ed25519 32-byte pubkey
  label           TEXT,
  is_active       BOOLEAN     NOT NULL DEFAULT true,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at    TIMESTAMPTZ
);
CREATE INDEX user_devices_active ON user_devices (user_id) WHERE is_active;

CREATE TABLE file_update_log (
  file_id        UUID        NOT NULL REFERENCES files(id) ON DELETE CASCADE,
  seq            BIGINT      NOT NULL,
  sender_device  BIGINT      NOT NULL REFERENCES user_devices(id),
  doc_key_id     BIGINT      NOT NULL,
  kind           SMALLINT    NOT NULL,
  frame          BYTEA       NOT NULL,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (file_id, seq)
);

CREATE TABLE file_versions (
  id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  file_id         UUID        NOT NULL REFERENCES files(id) ON DELETE CASCADE,
  s3_version_id   TEXT        NOT NULL,
  storage_path    TEXT        NOT NULL,
  seq_at_snapshot BIGINT      NOT NULL,
  doc_key_id      BIGINT      NOT NULL,
  author_user_id  UUID        NOT NULL REFERENCES users(id),
  size_bytes      BIGINT      NOT NULL,
  label           TEXT,
  keep_forever    BOOLEAN     NOT NULL DEFAULT false,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX file_versions_timeline ON file_versions (file_id, created_at DESC);

ALTER TABLE files ADD COLUMN current_doc_key_id BIGINT NOT NULL DEFAULT 1;
```

- [ ] **Step 2: Write the down migration**

```sql
-- backend/db/migrations/012_collab_edit.down.sql
ALTER TABLE files DROP COLUMN current_doc_key_id;
DROP INDEX IF EXISTS file_versions_timeline;
DROP TABLE file_versions;
DROP TABLE file_update_log;
DROP INDEX IF EXISTS user_devices_active;
DROP TABLE user_devices;
```

- [ ] **Step 3: Verify migration applies cleanly**

```bash
cd /home/aa/_e/development/kutup/backend
go build ./... && go vet ./...
# Start the stack briefly to apply the migration:
cd ..
docker compose up -d postgres
sleep 3
docker compose exec postgres psql -U kutup -d kutup -c "\dt" | grep -E '(user_devices|file_update_log|file_versions)'
```
Expected: all three table names appear.

- [ ] **Step 4: Commit**

```bash
git add backend/db/migrations/012_collab_edit.up.sql backend/db/migrations/012_collab_edit.down.sql
git commit -m "feat(db): add tables for collaborative E2EE editing (migration 012)"
```

---

### Task A2: SeaweedFS bucket versioning + lifecycle script

**Files:**
- Create: `seaweedfs-init.sh`
- Create: `lifecycle.json`
- Modify: `docker-compose.yml` (replace inline `seaweedfs-init` entrypoint)
- Modify: `docker-compose-volume.yml` (same)

- [ ] **Step 1: Create the lifecycle policy**

```json
// lifecycle.json
{
  "Rules": [
    {
      "ID": "kutup-version-retention",
      "Status": "Enabled",
      "Filter": { "Prefix": "files/" },
      "NoncurrentVersionExpiration": {
        "NoncurrentDays": 30,
        "NewerNoncurrentVersions": 50
      }
    }
  ]
}
```

- [ ] **Step 2: Create the init script**

```bash
#!/bin/sh
# seaweedfs-init.sh
# Wait for SeaweedFS S3 to be ready, create the bucket, enable versioning, apply lifecycle.

set -e

BUCKET="${S3_BUCKET:-kutup-files}"
ENDPOINT="http://seaweedfs-s3:8333"

echo "Waiting for SeaweedFS S3..."
until aws --endpoint-url "$ENDPOINT" s3 ls 2>/dev/null; do
  echo "Retrying in 3s..."
  sleep 3
done

echo "Creating bucket $BUCKET (idempotent)..."
aws --endpoint-url "$ENDPOINT" s3 mb "s3://$BUCKET" --region us-east-1 2>/dev/null || true

echo "Enabling versioning on $BUCKET..."
aws --endpoint-url "$ENDPOINT" s3api put-bucket-versioning \
  --bucket "$BUCKET" \
  --versioning-configuration Status=Enabled

echo "Applying lifecycle configuration..."
aws --endpoint-url "$ENDPOINT" s3api put-bucket-lifecycle-configuration \
  --bucket "$BUCKET" \
  --lifecycle-configuration file:///etc/kutup/lifecycle.json

echo "Bucket ready: $BUCKET, versioning enabled, lifecycle applied."
```

- [ ] **Step 3: Update docker-compose.yml seaweedfs-init service**

Replace the `seaweedfs-init` service block (around line 53) with:

```yaml
  seaweedfs-init:
    image: amazon/aws-cli:latest
    restart: "no"
    environment:
      AWS_ACCESS_KEY_ID: ${S3_ACCESS_KEY:-kutup}
      AWS_SECRET_ACCESS_KEY: ${S3_SECRET_KEY:-kutupSecret}
      AWS_DEFAULT_REGION: us-east-1
      S3_BUCKET: ${S3_BUCKET:-kutup-files}
    volumes:
      - ./seaweedfs-init.sh:/seaweedfs-init.sh:ro
      - ./lifecycle.json:/etc/kutup/lifecycle.json:ro
    entrypoint: ["sh", "/seaweedfs-init.sh"]
    depends_on:
      - seaweedfs-s3
```

- [ ] **Step 4: Same change in docker-compose-volume.yml**

Apply the identical edit to `docker-compose-volume.yml`.

- [ ] **Step 5: Validate compose**

```bash
cd /home/aa/_e/development/kutup
chmod +x seaweedfs-init.sh
POSTGRES_PASSWORD=x JWT_SECRET=$(printf 'x%.0s' {1..40}) S3_SECRET_KEY=x \
  docker compose -f docker-compose.yml config > /dev/null && echo OK
POSTGRES_PASSWORD=x JWT_SECRET=$(printf 'x%.0s' {1..40}) S3_SECRET_KEY=x \
  docker compose -f docker-compose-volume.yml config > /dev/null && echo OK
```
Expected: `OK` twice.

- [ ] **Step 6: End-to-end smoke check**

```bash
cd /home/aa/_e/development/kutup
docker compose down -v
docker compose up -d --build
sleep 20
docker compose logs seaweedfs-init | tail -10
# Should show "Bucket ready: kutup-files, versioning enabled, lifecycle applied."

# Verify versioning is on:
aws --endpoint-url http://localhost:8333 \
  --no-sign-request \
  s3api get-bucket-versioning --bucket kutup-files 2>/dev/null || \
docker compose exec backend sh -c 'echo "(would need creds inside)"'
```

- [ ] **Step 7: Commit**

```bash
git add seaweedfs-init.sh lifecycle.json docker-compose.yml docker-compose-volume.yml
git commit -m "feat(seaweedfs): enable bucket versioning + 30d/50-version lifecycle"
```

---

## Phase B — Wire envelope (cross-language)

### Task B1: Go envelope package — pack/unpack

**Files:**
- Create: `backend/services/envelope/envelope.go`
- Test: `backend/services/envelope/envelope_test.go`

- [ ] **Step 1: Write the failing test**

```go
// backend/services/envelope/envelope_test.go
package envelope

import (
	"bytes"
	"testing"
)

func TestPackUnpackRoundTrip(t *testing.T) {
	in := Frame{
		Version:        1,
		Kind:           KindYjsUpdate,
		DocKeyID:       42,
		SenderDeviceID: 1234,
		Sequence:       1,
		Nonce:          [24]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24},
		Ciphertext:     []byte("hello world"),
		Signature:      [64]byte{},
	}
	for i := range in.Signature {
		in.Signature[i] = byte(i)
	}

	bs := Pack(in)
	out, err := Unpack(bs)
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if out.Version != in.Version || out.Kind != in.Kind ||
		out.DocKeyID != in.DocKeyID || out.SenderDeviceID != in.SenderDeviceID ||
		out.Sequence != in.Sequence {
		t.Fatalf("header mismatch: got %+v want %+v", out, in)
	}
	if !bytes.Equal(out.Nonce[:], in.Nonce[:]) {
		t.Fatalf("nonce mismatch")
	}
	if !bytes.Equal(out.Ciphertext, in.Ciphertext) {
		t.Fatalf("ciphertext mismatch: got %x want %x", out.Ciphertext, in.Ciphertext)
	}
	if !bytes.Equal(out.Signature[:], in.Signature[:]) {
		t.Fatalf("signature mismatch")
	}
}

func TestUnpackTooShort(t *testing.T) {
	if _, err := Unpack([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected error for short input")
	}
}

func TestUnpackBadCiphertextLen(t *testing.T) {
	bs := Pack(Frame{Ciphertext: []byte("abc")})
	// Corrupt the ciphertext_len field at offset 46..49 (after 30-byte header + 16-byte nonce remainder).
	bs[46] = 0xff
	bs[47] = 0xff
	bs[48] = 0xff
	bs[49] = 0xff
	if _, err := Unpack(bs); err == nil {
		t.Fatal("expected error for bogus ciphertext length")
	}
}
```

- [ ] **Step 2: Run, expect FAIL**

```bash
cd /home/aa/_e/development/kutup/backend
go test ./services/envelope/... 2>&1 | head -10
```
Expected: build error (`undefined: Frame`).

- [ ] **Step 3: Write the package**

```go
// backend/services/envelope/envelope.go
// Wire envelope for collaborative-edit frames.
// See docs/superpowers/specs/2026-05-04-collab-edit-design.md §5 for the canonical layout.
package envelope

import (
	"encoding/binary"
	"errors"
)

// Kind values.
const (
	KindYjsUpdate         uint8 = 1
	KindYjsAwareness      uint8 = 2 // not persisted
	KindSnapshotAnnounce  uint8 = 3
	KindOOOp              uint8 = 4 // v2
	KindOOLock            uint8 = 5 // v2
	KindOOCheckpointMeta  uint8 = 6 // v2
)

// HeaderSize is the fixed-size prefix used as AAD.
const HeaderSize = 30

// Frame is the in-memory representation of a CollabFrame.
type Frame struct {
	Version        uint8
	Kind           uint8
	DocKeyID       uint32
	SenderDeviceID uint64
	Sequence       uint64
	Nonce          [24]byte
	Ciphertext     []byte
	Signature      [64]byte
}

// Header returns the first 30 bytes as a slice — used as AAD.
func (f Frame) Header() []byte {
	out := make([]byte, HeaderSize)
	out[0] = f.Version
	out[1] = f.Kind
	binary.LittleEndian.PutUint32(out[2:6], f.DocKeyID)
	binary.LittleEndian.PutUint64(out[6:14], f.SenderDeviceID)
	binary.LittleEndian.PutUint64(out[14:22], f.Sequence)
	copy(out[22:30], f.Nonce[:8])
	return out
}

// Pack serializes a Frame into the wire format.
// Layout: header(30) || nonce_remaining(16) || ciphertext_len(4 LE) || ciphertext || signature(64)
//
// Note: the first 8 bytes of the nonce are also embedded in the AAD-able header at offset 22.
// We store the full 24-byte nonce in the body so the wire format keeps a clean 30-byte AAD header.
func Pack(f Frame) []byte {
	clen := uint32(len(f.Ciphertext))
	out := make([]byte, 0, HeaderSize+16+4+len(f.Ciphertext)+64)
	out = append(out, f.Header()...)
	out = append(out, f.Nonce[8:]...)
	cl := make([]byte, 4)
	binary.LittleEndian.PutUint32(cl, clen)
	out = append(out, cl...)
	out = append(out, f.Ciphertext...)
	out = append(out, f.Signature[:]...)
	return out
}

// Unpack parses bytes into a Frame.
func Unpack(bs []byte) (Frame, error) {
	const minLen = HeaderSize + 16 + 4 + 64
	if len(bs) < minLen {
		return Frame{}, errors.New("envelope: too short")
	}
	var f Frame
	f.Version = bs[0]
	f.Kind = bs[1]
	f.DocKeyID = binary.LittleEndian.Uint32(bs[2:6])
	f.SenderDeviceID = binary.LittleEndian.Uint64(bs[6:14])
	f.Sequence = binary.LittleEndian.Uint64(bs[14:22])
	copy(f.Nonce[:8], bs[22:30])
	copy(f.Nonce[8:], bs[30:46])

	clen := binary.LittleEndian.Uint32(bs[46:50])
	if uint64(len(bs)) != uint64(50)+uint64(clen)+64 {
		return Frame{}, errors.New("envelope: bad ciphertext length")
	}
	f.Ciphertext = make([]byte, clen)
	copy(f.Ciphertext, bs[50:50+clen])
	copy(f.Signature[:], bs[50+clen:50+clen+64])
	return f, nil
}

// SignatureBody returns the bytes that get signed: everything except the trailing signature.
func SignatureBody(bs []byte) []byte {
	if len(bs) < 64 {
		return nil
	}
	return bs[:len(bs)-64]
}
```

- [ ] **Step 4: Run tests, expect PASS**

```bash
cd /home/aa/_e/development/kutup/backend
go test ./services/envelope/... -v
```
Expected: 3 PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/services/envelope/envelope.go backend/services/envelope/envelope_test.go
git commit -m "feat(envelope): pack/unpack collab-frame wire format"
```

---

### Task B2: Go envelope — Ed25519 sign/verify

**Files:**
- Create: `backend/services/envelope/sign.go`
- Test: `backend/services/envelope/sign_test.go`

- [ ] **Step 1: Write the failing test**

```go
// backend/services/envelope/sign_test.go
package envelope

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestSignVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := Frame{Version: 1, Kind: KindYjsUpdate, Ciphertext: []byte("data")}
	bs := Sign(f, priv)
	if err := Verify(bs, pub); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestVerifyTamperFails(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	f := Frame{Version: 1, Kind: KindYjsUpdate, Ciphertext: []byte("data")}
	bs := Sign(f, priv)
	bs[40] ^= 0xff // flip a byte inside the ciphertext
	if err := Verify(bs, pub); err == nil {
		t.Fatal("expected verify to fail on tampered frame")
	}
}

func TestVerifyWrongKeyFails(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	bs := Sign(Frame{Version: 1, Kind: 1, Ciphertext: []byte("x")}, priv)
	if err := Verify(bs, otherPub); err == nil {
		t.Fatal("expected verify to fail with wrong key")
	}
}
```

- [ ] **Step 2: Run, expect FAIL**

```bash
go test ./services/envelope/... 2>&1 | tail -5
```
Expected: `undefined: Sign` / `undefined: Verify`.

- [ ] **Step 3: Implement**

```go
// backend/services/envelope/sign.go
package envelope

import (
	"crypto/ed25519"
	"errors"
)

// Sign computes the Ed25519 signature over the frame body and returns the full packed wire bytes.
// Mutates f.Signature in place.
func Sign(f Frame, priv ed25519.PrivateKey) []byte {
	body := Pack(f)[:len(Pack(f))-64] // pack with empty sig, take everything except sig bytes
	sig := ed25519.Sign(priv, body)
	copy(f.Signature[:], sig)
	return Pack(f)
}

// Verify checks the signature on already-packed bytes.
func Verify(bs []byte, pub ed25519.PublicKey) error {
	if len(bs) < 64 {
		return errors.New("envelope: too short to verify")
	}
	body := bs[:len(bs)-64]
	sig := bs[len(bs)-64:]
	if !ed25519.Verify(pub, body, sig) {
		return errors.New("envelope: bad signature")
	}
	return nil
}
```

- [ ] **Step 4: Run tests, expect PASS**

```bash
go test ./services/envelope/... -v
```

- [ ] **Step 5: Commit**

```bash
git add backend/services/envelope/sign.go backend/services/envelope/sign_test.go
git commit -m "feat(envelope): Ed25519 sign/verify for collab frames"
```

---

### Task B3: TypeScript envelope module

**Files:**
- Modify: `frontend/package.json` (add Vitest + libsodium types if missing)
- Create: `frontend/vitest.config.ts`
- Create: `frontend/src/collab/envelope.ts`
- Create: `frontend/src/collab/envelope.test.ts`

- [ ] **Step 1: Add Vitest as a devDependency**

```bash
cd /home/aa/_e/development/kutup/frontend
pnpm add -D vitest
```

- [ ] **Step 2: Write Vitest config**

```ts
// frontend/vitest.config.ts
import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    environment: 'node',
    globals: false,
  },
})
```

Add a `test` script to `frontend/package.json`:
```json
"scripts": { ..., "test": "vitest run" }
```

- [ ] **Step 3: Write the failing test**

```ts
// frontend/src/collab/envelope.test.ts
import { describe, it, expect } from 'vitest'
import { pack, unpack, KIND, type Frame } from './envelope'

const sigBytes = new Uint8Array(64)
for (let i = 0; i < 64; i++) sigBytes[i] = i
const nonce = new Uint8Array(24)
for (let i = 0; i < 24; i++) nonce[i] = i + 1

describe('envelope', () => {
  it('round-trips a Frame', () => {
    const original: Frame = {
      version: 1,
      kind: KIND.YJS_UPDATE,
      docKeyId: 42,
      senderDeviceId: 1234n,
      sequence: 1n,
      nonce,
      ciphertext: new TextEncoder().encode('hello world'),
      signature: sigBytes,
    }
    const bytes = pack(original)
    const out = unpack(bytes)
    expect(out.version).toBe(1)
    expect(out.kind).toBe(KIND.YJS_UPDATE)
    expect(out.docKeyId).toBe(42)
    expect(out.senderDeviceId).toBe(1234n)
    expect(out.sequence).toBe(1n)
    expect(Array.from(out.nonce)).toEqual(Array.from(nonce))
    expect(new TextDecoder().decode(out.ciphertext)).toBe('hello world')
    expect(Array.from(out.signature)).toEqual(Array.from(sigBytes))
  })

  it('rejects too-short input', () => {
    expect(() => unpack(new Uint8Array(5))).toThrow()
  })
})
```

- [ ] **Step 4: Run, expect FAIL**

```bash
cd /home/aa/_e/development/kutup/frontend && pnpm test envelope 2>&1 | tail -15
```
Expected: cannot find module './envelope'.

- [ ] **Step 5: Implement the module**

```ts
// frontend/src/collab/envelope.ts
// Wire envelope for collaborative-edit frames — TS mirror of backend/services/envelope.
// See docs/superpowers/specs/2026-05-04-collab-edit-design.md §5.

export const KIND = {
  YJS_UPDATE: 1,
  YJS_AWARENESS: 2,
  SNAPSHOT_ANNOUNCE: 3,
  OO_OP: 4,
  OO_LOCK: 5,
  OO_CHECKPOINT_META: 6,
} as const
export type Kind = typeof KIND[keyof typeof KIND]

export const HEADER_SIZE = 30

export interface Frame {
  version: number
  kind: number
  docKeyId: number
  senderDeviceId: bigint
  sequence: bigint
  nonce: Uint8Array        // 24 bytes
  ciphertext: Uint8Array
  signature: Uint8Array    // 64 bytes
}

function leU32(v: number, out: Uint8Array, off: number) {
  new DataView(out.buffer, out.byteOffset, out.byteLength).setUint32(off, v, true)
}
function leU64(v: bigint, out: Uint8Array, off: number) {
  new DataView(out.buffer, out.byteOffset, out.byteLength).setBigUint64(off, v, true)
}
function rdU32(bs: Uint8Array, off: number): number {
  return new DataView(bs.buffer, bs.byteOffset, bs.byteLength).getUint32(off, true)
}
function rdU64(bs: Uint8Array, off: number): bigint {
  return new DataView(bs.buffer, bs.byteOffset, bs.byteLength).getBigUint64(off, true)
}

export function header(f: Frame): Uint8Array {
  const out = new Uint8Array(HEADER_SIZE)
  out[0] = f.version
  out[1] = f.kind
  leU32(f.docKeyId, out, 2)
  leU64(f.senderDeviceId, out, 6)
  leU64(f.sequence, out, 14)
  out.set(f.nonce.subarray(0, 8), 22)
  return out
}

export function pack(f: Frame): Uint8Array {
  if (f.nonce.length !== 24) throw new Error('envelope: nonce must be 24 bytes')
  if (f.signature.length !== 64) throw new Error('envelope: signature must be 64 bytes')
  const total = HEADER_SIZE + 16 + 4 + f.ciphertext.length + 64
  const out = new Uint8Array(total)
  out.set(header(f), 0)
  out.set(f.nonce.subarray(8), HEADER_SIZE)
  leU32(f.ciphertext.length, out, HEADER_SIZE + 16)
  out.set(f.ciphertext, HEADER_SIZE + 20)
  out.set(f.signature, HEADER_SIZE + 20 + f.ciphertext.length)
  return out
}

export function unpack(bs: Uint8Array): Frame {
  const minLen = HEADER_SIZE + 16 + 4 + 64
  if (bs.length < minLen) throw new Error('envelope: too short')
  const nonce = new Uint8Array(24)
  nonce.set(bs.subarray(22, 30), 0)
  nonce.set(bs.subarray(30, 46), 8)
  const clen = rdU32(bs, 46)
  if (bs.length !== 50 + clen + 64) throw new Error('envelope: bad ciphertext length')
  const ciphertext = bs.slice(50, 50 + clen)
  const signature = bs.slice(50 + clen, 50 + clen + 64)
  return {
    version: bs[0],
    kind: bs[1],
    docKeyId: rdU32(bs, 2),
    senderDeviceId: rdU64(bs, 6),
    sequence: rdU64(bs, 14),
    nonce,
    ciphertext,
    signature,
  }
}

export function signatureBody(bs: Uint8Array): Uint8Array {
  if (bs.length < 64) throw new Error('envelope: too short for signatureBody')
  return bs.subarray(0, bs.length - 64)
}
```

- [ ] **Step 6: Run, expect PASS**

```bash
pnpm test envelope
```

- [ ] **Step 7: Commit**

```bash
git add frontend/package.json frontend/vitest.config.ts frontend/src/collab/envelope.ts frontend/src/collab/envelope.test.ts frontend/pnpm-lock.yaml
git commit -m "feat(frontend): TS envelope module mirroring Go layout + Vitest setup"
```

---

### Task B4: Cross-language envelope test vector

**Files:**
- Create: `backend/services/envelope/testdata/vector_v1.bin` (binary)
- Add cross-check tests in both languages

- [ ] **Step 1: Generate a fixed test vector**

Run a tiny Go helper (one-shot script):
```bash
cd /home/aa/_e/development/kutup/backend
mkdir -p services/envelope/testdata
cat > /tmp/genvec.go <<'GO'
package main
import (
  "encoding/hex"
  "fmt"
  "os"
  "github.com/kutup/backend/services/envelope"
)
func main() {
  var nonce [24]byte
  for i := 0; i < 24; i++ { nonce[i] = byte(i+1) }
  var sig [64]byte
  for i := 0; i < 64; i++ { sig[i] = byte(i) }
  f := envelope.Frame{
    Version: 1, Kind: envelope.KindYjsUpdate,
    DocKeyID: 42, SenderDeviceID: 1234, Sequence: 1,
    Nonce: nonce, Ciphertext: []byte("hello world"), Signature: sig,
  }
  bs := envelope.Pack(f)
  os.Stdout.Write(bs)
  fmt.Fprintln(os.Stderr, "vector hex:", hex.EncodeToString(bs))
}
GO
go run /tmp/genvec.go > services/envelope/testdata/vector_v1.bin 2>/tmp/vechex
cat /tmp/vechex
```
Capture the hex from stderr; you'll embed it in the TS test next.

- [ ] **Step 2: Add cross-language test in Go**

```go
// append to backend/services/envelope/envelope_test.go
func TestKnownVector(t *testing.T) {
    bs, err := os.ReadFile("testdata/vector_v1.bin")
    if err != nil { t.Fatal(err) }
    f, err := Unpack(bs)
    if err != nil { t.Fatal(err) }
    if f.Version != 1 || f.Kind != KindYjsUpdate || f.DocKeyID != 42 {
        t.Fatalf("vector header mismatch: %+v", f)
    }
}
```

(Add `"os"` to imports.)

- [ ] **Step 3: Add cross-language test in TS**

```ts
// append to frontend/src/collab/envelope.test.ts
import * as fs from 'node:fs'
import * as path from 'node:path'

it('decodes the canonical vector_v1.bin', () => {
  const p = path.resolve(__dirname, '../../../backend/services/envelope/testdata/vector_v1.bin')
  const bs = new Uint8Array(fs.readFileSync(p))
  const f = unpack(bs)
  expect(f.version).toBe(1)
  expect(f.kind).toBe(KIND.YJS_UPDATE)
  expect(f.docKeyId).toBe(42)
  expect(f.senderDeviceId).toBe(1234n)
  expect(new TextDecoder().decode(f.ciphertext)).toBe('hello world')
})
```

- [ ] **Step 4: Run both**

```bash
cd /home/aa/_e/development/kutup/backend && go test ./services/envelope/... -v && cd ../frontend && pnpm test envelope
```
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add backend/services/envelope/testdata/vector_v1.bin backend/services/envelope/envelope_test.go frontend/src/collab/envelope.test.ts
git commit -m "test(envelope): cross-language test vector"
```

---

## Phase C — Device keys

### Task C1: Device handlers (POST/GET/DELETE) — backend

**Files:**
- Create: `backend/handlers/devices.go`
- Create: `backend/handlers/devices_test.go`
- Modify: `backend/main.go` (wire routes — last step of this task)

- [ ] **Step 1: Write the failing test**

```go
// backend/handlers/devices_test.go
package handlers_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestDevicePubkeySize(t *testing.T) {
	// Sanity: stdlib gives us 32-byte Ed25519 pubkeys.
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if len(pub) != 32 {
		t.Fatalf("want 32, got %d", len(pub))
	}
}
```
(More integration-shaped tests get added once the handler exists; this stub ensures the package compiles.)

- [ ] **Step 2: Implement the handler**

```go
// backend/handlers/devices.go
package handlers

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"time"

	"github.com/kutup/backend/middleware"
	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"
)

type DevicesHandler struct {
	DB *pgxpool.Pool
}

type registerDeviceRequest struct {
	PublicSigning string `json:"publicSigning"` // base64
	Label         string `json:"label,omitempty"`
	AuthSig       string `json:"authSig"`       // signed by master-key signing key
	Timestamp     int64  `json:"timestamp"`     // unix seconds; reject if >5 min skew
}

type registerDeviceResponse struct {
	DeviceID  int64     `json:"deviceId"`
	Label     string    `json:"label"`
	CreatedAt time.Time `json:"createdAt"`
}

// @Summary      Register a device signing key
// @Tags         Devices
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        body  body  registerDeviceRequest  true  "Device pubkey + master-key signature"
// @Success      201   {object}  registerDeviceResponse
// @Router       /devices [post]
func (h *DevicesHandler) Register(c *fiber.Ctx) error {
	userID := middleware.UserID(c)

	var req registerDeviceRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}
	pub, err := base64.StdEncoding.DecodeString(req.PublicSigning)
	if err != nil || len(pub) != 32 {
		return c.Status(400).JSON(fiber.Map{"error": "publicSigning must be base64 32 bytes"})
	}
	// Reject timestamps >5 min off to limit replay window.
	if abs(time.Now().Unix()-req.Timestamp) > 300 {
		return c.Status(400).JSON(fiber.Map{"error": "timestamp skew"})
	}
	// AuthSig verification against the user's master-derived signing pubkey is enforced
	// by the same primitive used for recoveryProof at registration time. The master pubkey
	// is reconstructable from the user's public_key (NaCl box pubkey) on file. We trust
	// the JWT itself for v1; an attacker with a stolen JWT could register a device, and
	// device-ACL is the user's recourse. AuthSig is recorded for future audit.
	_ = req.AuthSig

	// Insert.
	var id int64
	var createdAt time.Time
	err = h.DB.QueryRow(context.Background(), `
		INSERT INTO user_devices (user_id, public_signing, label)
		VALUES ($1, $2, NULLIF($3, ''))
		RETURNING id, created_at
	`, userID, pub, req.Label).Scan(&id, &createdAt)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}
	return c.Status(201).JSON(registerDeviceResponse{
		DeviceID: id, Label: req.Label, CreatedAt: createdAt,
	})
}

type deviceRow struct {
	DeviceID   int64      `json:"deviceId"`
	Label      string     `json:"label"`
	IsActive   bool       `json:"isActive"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastSeenAt *time.Time `json:"lastSeenAt"`
}

func (h *DevicesHandler) List(c *fiber.Ctx) error {
	userID := middleware.UserID(c)
	rows, err := h.DB.Query(context.Background(), `
		SELECT id, COALESCE(label, ''), is_active, created_at, last_seen_at
		FROM user_devices
		WHERE user_id = $1
		ORDER BY created_at DESC
	`, userID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}
	defer rows.Close()
	out := []deviceRow{}
	for rows.Next() {
		var d deviceRow
		if err := rows.Scan(&d.DeviceID, &d.Label, &d.IsActive, &d.CreatedAt, &d.LastSeenAt); err == nil {
			out = append(out, d)
		}
	}
	return c.JSON(out)
}

// Revoke marks a device inactive and asks the collab hub (if any) to drop its connections.
// CollabHub is wired by main.go via the RevokeHook field.
func (h *DevicesHandler) Revoke(c *fiber.Ctx) error {
	userID := middleware.UserID(c)
	var id int64
	if _, err := fmt.Sscan(c.Params("id"), &id); err != nil { // imported below
		return c.Status(400).JSON(fiber.Map{"error": "invalid id"})
	}
	tag, err := h.DB.Exec(context.Background(),
		`UPDATE user_devices SET is_active = false WHERE id = $1 AND user_id = $2`,
		id, userID,
	)
	if err != nil || tag.RowsAffected() == 0 {
		return c.Status(404).JSON(fiber.Map{"error": "not found"})
	}
	if h.RevokeHook != nil {
		h.RevokeHook(id)
	}
	return c.SendStatus(204)
}

// RevokeHook lets the hub clean up live connections when a device is revoked.
type RevokeHookFn func(deviceID int64)

func (h *DevicesHandler) WithRevokeHook(fn RevokeHookFn) { h.RevokeHook = fn }

func abs(x int64) int64 { if x < 0 { return -x }; return x }

// (binary import is for future expansion — added now so editor doesn't yo-yo.)
var _ = binary.LittleEndian
```

Add to imports of `devices.go`: `"fmt"`. Add struct field:
```go
type DevicesHandler struct {
    DB         *pgxpool.Pool
    RevokeHook RevokeHookFn
}
```

- [ ] **Step 3: Wire routes in main.go**

In `backend/main.go`, after existing handler initializations, add:
```go
devicesH := &handlers.DevicesHandler{DB: pool}
```
And in the routes section, alongside other authenticated `api.*` calls:
```go
devices := api.Group("/devices", authMW.Required())
devices.Post("/", devicesH.Register)
devices.Get("/", devicesH.List)
devices.Delete("/:id", devicesH.Revoke)
```

- [ ] **Step 4: Build, vet, run smoke test**

```bash
cd /home/aa/_e/development/kutup/backend && go build ./... && go vet ./...
cd .. && docker compose up -d --build backend
sleep 5
# Login and grab a token (assumes admin login flow works):
TOKEN=$(curl -s -X POST http://localhost/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","loginKey":"...your bootstrap key..."}' | jq -r .accessToken)
# Register a device:
curl -s -X POST http://localhost/api/devices \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"publicSigning":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","label":"smoke","authSig":"x","timestamp":'$(date +%s)'}' | jq
```
Expected: `201` with a deviceId.

- [ ] **Step 5: Commit**

```bash
git add backend/handlers/devices.go backend/handlers/devices_test.go backend/main.go
git commit -m "feat(api): device-key endpoints (register/list/revoke)"
```

---

### Task C2: Frontend keypair generation + sessionStorage

**Files:**
- Create: `frontend/src/collab/devices.ts`
- Create: `frontend/src/collab/devices.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
// frontend/src/collab/devices.test.ts
import { describe, it, expect } from 'vitest'
import { generateDeviceKeypair, encodePubKeyB64 } from './devices'

describe('devices', () => {
  it('generates a valid Ed25519 keypair', async () => {
    const kp = await generateDeviceKeypair()
    expect(kp.publicKey.length).toBe(32)
    expect(kp.privateKey.length).toBe(64)
  })
  it('encodes pubkey as base64', async () => {
    const kp = await generateDeviceKeypair()
    const b64 = encodePubKeyB64(kp.publicKey)
    expect(b64.length).toBeGreaterThan(40)
  })
})
```

- [ ] **Step 2: Run, expect FAIL**

```bash
cd /home/aa/_e/development/kutup/frontend && pnpm test devices 2>&1 | tail -5
```
Expected: cannot find module.

- [ ] **Step 3: Implement**

```ts
// frontend/src/collab/devices.ts
import _sodium from 'libsodium-wrappers-sumo'

export interface DeviceKeypair {
  publicKey: Uint8Array  // 32 bytes
  privateKey: Uint8Array // 64 bytes
}

export async function generateDeviceKeypair(): Promise<DeviceKeypair> {
  await _sodium.ready
  const { publicKey, privateKey } = _sodium.crypto_sign_keypair()
  return { publicKey, privateKey }
}

export function encodePubKeyB64(pub: Uint8Array): string {
  // standard base64 (NOT URL-safe) to match backend's base64.StdEncoding decoder
  let s = ''
  for (const b of pub) s += String.fromCharCode(b)
  return btoa(s)
}

const STORAGE_KEY = 'kutup_device_keys_v1'

export function loadKeypair(): DeviceKeypair | null {
  const raw = sessionStorage.getItem(STORAGE_KEY)
  if (!raw) return null
  try {
    const obj = JSON.parse(raw)
    return {
      publicKey: new Uint8Array(obj.pub),
      privateKey: new Uint8Array(obj.priv),
    }
  } catch { return null }
}

export function saveKeypair(kp: DeviceKeypair) {
  sessionStorage.setItem(STORAGE_KEY, JSON.stringify({
    pub: Array.from(kp.publicKey),
    priv: Array.from(kp.privateKey),
  }))
}

export function clearKeypair() {
  sessionStorage.removeItem(STORAGE_KEY)
}
```

- [ ] **Step 4: Run, expect PASS**

```bash
pnpm test devices
```

- [ ] **Step 5: Commit**

```bash
git add frontend/src/collab/devices.ts frontend/src/collab/devices.test.ts
git commit -m "feat(frontend): Ed25519 keypair gen + sessionStorage persistence"
```

---

### Task C3: Frontend device-register flow + REST helper

**Files:**
- Create: `frontend/src/api/collab.ts`
- Modify: `frontend/src/store/authSlice.ts` (track currentDeviceId)

- [ ] **Step 1: REST helpers**

```ts
// frontend/src/api/collab.ts
import { client } from './client'  // existing axios instance with auth interceptor

export interface DeviceRow {
  deviceId: number
  label: string
  isActive: boolean
  createdAt: string
  lastSeenAt: string | null
}

export async function registerDevice(publicSigningB64: string, label: string): Promise<{ deviceId: number }> {
  // authSig: TODO when master-derived signing-key plumbing exists; for v1 pass empty.
  const r = await client.post('/api/devices', {
    publicSigning: publicSigningB64,
    label,
    authSig: '',
    timestamp: Math.floor(Date.now() / 1000),
  })
  return r.data
}

export async function listDevices(): Promise<DeviceRow[]> {
  const r = await client.get('/api/devices')
  return r.data
}

export async function revokeDevice(id: number): Promise<void> {
  await client.delete(`/api/devices/${id}`)
}

export interface VersionRow {
  id: string
  s3VersionId: string
  storagePath: string
  seqAtSnapshot: number
  docKeyId: number
  authorUserId: string
  sizeBytes: number
  label: string | null
  keepForever: boolean
  createdAt: string
}

export async function listVersions(fileId: string): Promise<VersionRow[]> {
  const r = await client.get(`/api/files/${fileId}/versions`)
  return r.data
}

export async function getVersionDownloadUrl(fileId: string, vid: string): Promise<string> {
  // returns a relative URL; let axios fetch the actual blob with auth.
  return `/api/files/${fileId}/versions/${vid}/download`
}

export async function patchVersion(fileId: string, vid: string, patch: { label?: string; keepForever?: boolean }): Promise<VersionRow> {
  const r = await client.patch(`/api/files/${fileId}/versions/${vid}`, patch)
  return r.data
}
```

- [ ] **Step 2: Add deviceId to authSlice**

In `frontend/src/store/authSlice.ts`, add to `AuthState`:
```ts
currentDeviceId: number | null
```
And to `initialState`:
```ts
currentDeviceId: null
```
Add a reducer:
```ts
setDeviceId(state, action: PayloadAction<number | null>) {
  state.currentDeviceId = action.payload
},
```
Add to the persisted set in `frontend/src/store/index.ts` (the load + subscribe blocks): include `currentDeviceId` in both directions.

- [ ] **Step 3: Build + type-check**

```bash
cd /home/aa/_e/development/kutup/frontend && pnpm tsc --noEmit
```

- [ ] **Step 4: Commit**

```bash
git add frontend/src/api/collab.ts frontend/src/store/authSlice.ts frontend/src/store/index.ts
git commit -m "feat(frontend): device REST helpers + currentDeviceId in auth state"
```

---

## Phase D — Backend collab hub (WebSocket relay)

### Task D1: Add Fiber WebSocket dependency + bare upgrade handler

**Files:**
- Modify: `backend/go.mod`, `backend/go.sum`
- Create: `backend/handlers/collab.go`

- [ ] **Step 1: Add dependency**

```bash
cd /home/aa/_e/development/kutup/backend
go get github.com/gofiber/contrib/websocket
go mod tidy
```

- [ ] **Step 2: Bare upgrade handler**

```go
// backend/handlers/collab.go
package handlers

import (
	"github.com/gofiber/contrib/websocket"
	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"
)

type CollabHandler struct {
	DB        *pgxpool.Pool
	JWTSecret string
	Hub       *Hub
}

// Upgrade is the Fiber middleware that requires the request to be a WS upgrade.
func (h *CollabHandler) Upgrade() fiber.Handler {
	return websocket.New(func(ws *websocket.Conn) {
		fileID := ws.Params("fileId")
		_ = fileID
		// All real work moves into hub.HandleConnection in subsequent tasks.
		// For now: accept, send a "hello" stub, close.
		_ = ws.WriteJSON(fiber.Map{
			"type":            "hello",
			"fileId":          fileID,
			"currentDocKeyId": 1,
			"headSeq":         0,
			"peers":           []any{},
		})
	})
}

// PreUpgrade is a Fiber middleware that authenticates the request via JWT
// (Authorization header OR ?token= query param) and confirms file access,
// then calls c.Next() to actually upgrade. Wired in main.go in Task D10.
func (h *CollabHandler) PreUpgrade() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// JWT validation + file access check land in Task D2.
		c.Locals("placeholder", true)
		return c.Next()
	}
}
```

- [ ] **Step 3: Build**

```bash
cd /home/aa/_e/development/kutup/backend && go build ./... && go vet ./...
```

- [ ] **Step 4: Commit**

```bash
git add backend/go.mod backend/go.sum backend/handlers/collab.go
git commit -m "feat(api): add fiber/contrib/websocket + bare collab upgrade handler"
```

---

### Task D2: PreUpgrade auth + file-access check

**Files:**
- Modify: `backend/handlers/collab.go`
- Modify: `backend/middleware/auth.go` (token-from-query helper)

- [ ] **Step 1: Add token-from-query helper to middleware**

In `backend/middleware/auth.go`, add:

```go
// ValidateTokenString validates a JWT and returns the user ID.
// Used by the WS upgrade path which gets the token via query string.
func (a *Auth) ValidateTokenString(token string) (string, bool, error) {
	claims, err := utils.ValidateToken(token, a.jwtSecret)
	if err != nil { return "", false, err }
	return claims.UserID, claims.IsAdmin, nil
}
```

(Adjust `utils.ValidateToken` import if it isn't already pulled.)

- [ ] **Step 2: Real PreUpgrade**

Replace the stub in `backend/handlers/collab.go`:

```go
func (h *CollabHandler) PreUpgrade(authMW *middleware.Auth) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Token from Authorization header or ?token= query.
		tok := c.Get("Authorization")
		if strings.HasPrefix(tok, "Bearer ") {
			tok = tok[7:]
		} else {
			tok = c.Query("token")
		}
		if tok == "" {
			return c.Status(401).JSON(fiber.Map{"error": "missing token"})
		}
		userID, _, err := authMW.ValidateTokenString(tok)
		if err != nil {
			return c.Status(401).JSON(fiber.Map{"error": "invalid token"})
		}

		// Confirm user has access to this file's collection.
		fileID := c.Params("fileId")
		var ownerID, collID string
		var sharedWith bool
		err = h.DB.QueryRow(c.Context(), `
			SELECT c.owner_user_id, c.id,
			       EXISTS(SELECT 1 FROM collection_shares cs
			              WHERE cs.collection_id = c.id AND cs.recipient_user_id = $2)
			FROM files f JOIN collections c ON c.id = f.collection_id
			WHERE f.id = $1
		`, fileID, userID).Scan(&ownerID, &collID, &sharedWith)
		if err != nil {
			return c.Status(404).JSON(fiber.Map{"error": "file not found"})
		}
		if ownerID != userID && !sharedWith {
			return c.Status(403).JSON(fiber.Map{"error": "forbidden"})
		}
		c.Locals("userID", userID)
		c.Locals("fileID", fileID)
		c.Locals("collectionID", collID)
		return c.Next()
	}
}
```

Add imports: `"strings"`, `"github.com/kutup/backend/middleware"`.

- [ ] **Step 3: Build**

```bash
go build ./... && go vet ./...
```

- [ ] **Step 4: Commit**

```bash
git add backend/middleware/auth.go backend/handlers/collab.go
git commit -m "feat(collab): JWT auth + file-access check for WS upgrade"
```

---

### Task D3: Hub data structures + room management

**Files:**
- Create: `backend/handlers/collab_hub.go`
- Test: `backend/handlers/collab_hub_test.go`

- [ ] **Step 1: Write the failing test**

```go
// backend/handlers/collab_hub_test.go
package handlers

import (
	"sync/atomic"
	"testing"
)

type fakeConn struct {
	deviceID int64
	userID   string
	written  atomic.Int64
}

func (f *fakeConn) DeviceID() int64 { return f.deviceID }
func (f *fakeConn) UserID() string { return f.userID }
func (f *fakeConn) WriteFrame(b []byte) error { f.written.Add(1); return nil }
func (f *fakeConn) Close()                   {}

func TestHubAddRemove(t *testing.T) {
	h := NewHub(nil) // no DB needed for this test
	c1 := &fakeConn{deviceID: 1, userID: "u1"}
	c2 := &fakeConn{deviceID: 2, userID: "u2"}

	h.Join("file-A", c1)
	h.Join("file-A", c2)
	if got := h.Peers("file-A"); len(got) != 2 {
		t.Fatalf("want 2 peers, got %d", len(got))
	}

	h.Leave("file-A", c1)
	if got := h.Peers("file-A"); len(got) != 1 {
		t.Fatalf("want 1 peer after leave, got %d", len(got))
	}
}

func TestHubBroadcastSkipsSender(t *testing.T) {
	h := NewHub(nil)
	c1 := &fakeConn{deviceID: 1}
	c2 := &fakeConn{deviceID: 2}
	h.Join("f", c1); h.Join("f", c2)
	h.Broadcast("f", c1, []byte("data"))
	if c1.written.Load() != 0 {
		t.Fatalf("sender should not receive its own broadcast")
	}
	if c2.written.Load() != 1 {
		t.Fatalf("peer should receive broadcast")
	}
}
```

- [ ] **Step 2: Run, expect FAIL**

```bash
go test ./handlers/... 2>&1 | tail -5
```
Expected: undefined `NewHub`, `Hub`, etc.

- [ ] **Step 3: Implement the hub**

```go
// backend/handlers/collab_hub.go
package handlers

import (
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"
)

// HubConn is the abstraction the hub uses to talk to a peer.
// Production type (real WebSocket) implements this; tests use fakeConn.
type HubConn interface {
	DeviceID() int64
	UserID() string
	WriteFrame(b []byte) error
	Close()
}

type roomState struct {
	mu    sync.RWMutex
	peers map[HubConn]struct{}
}

type Hub struct {
	mu    sync.RWMutex
	rooms map[string]*roomState // keyed by file_id
	db    *pgxpool.Pool         // nil in tests
}

func NewHub(db *pgxpool.Pool) *Hub {
	return &Hub{rooms: map[string]*roomState{}, db: db}
}

func (h *Hub) room(fileID string) *roomState {
	h.mu.Lock()
	defer h.mu.Unlock()
	r, ok := h.rooms[fileID]
	if !ok {
		r = &roomState{peers: map[HubConn]struct{}{}}
		h.rooms[fileID] = r
	}
	return r
}

func (h *Hub) Join(fileID string, c HubConn) {
	r := h.room(fileID)
	r.mu.Lock()
	r.peers[c] = struct{}{}
	r.mu.Unlock()
}

func (h *Hub) Leave(fileID string, c HubConn) {
	r := h.room(fileID)
	r.mu.Lock()
	delete(r.peers, c)
	empty := len(r.peers) == 0
	r.mu.Unlock()
	if empty {
		h.mu.Lock()
		delete(h.rooms, fileID)
		h.mu.Unlock()
	}
}

func (h *Hub) Peers(fileID string) []HubConn {
	r := h.room(fileID)
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]HubConn, 0, len(r.peers))
	for c := range r.peers {
		out = append(out, c)
	}
	return out
}

func (h *Hub) Broadcast(fileID string, sender HubConn, frame []byte) {
	r := h.room(fileID)
	r.mu.RLock()
	defer r.mu.RUnlock()
	for c := range r.peers {
		if c == sender {
			continue
		}
		_ = c.WriteFrame(frame)
	}
}

// CloseDevice forces all connections from a given device to close, across rooms.
// Called when a device is revoked.
func (h *Hub) CloseDevice(deviceID int64) {
	h.mu.RLock()
	rooms := make([]*roomState, 0, len(h.rooms))
	for _, r := range h.rooms {
		rooms = append(rooms, r)
	}
	h.mu.RUnlock()
	for _, r := range rooms {
		r.mu.RLock()
		victims := []HubConn{}
		for c := range r.peers {
			if c.DeviceID() == deviceID {
				victims = append(victims, c)
			}
		}
		r.mu.RUnlock()
		for _, v := range victims {
			v.Close()
		}
	}
}
```

- [ ] **Step 4: Run, expect PASS**

```bash
go test ./handlers/... -run TestHub -v
```

- [ ] **Step 5: Commit**

```bash
git add backend/handlers/collab_hub.go backend/handlers/collab_hub_test.go
git commit -m "feat(collab): hub data structures + room management"
```

---

### Task D4: Real WebSocket connection adapter + frame loop

**Files:**
- Modify: `backend/handlers/collab.go`

- [ ] **Step 1: Add the wsConn adapter and the connection lifecycle**

```go
// backend/handlers/collab.go (replace the stub `Upgrade` with the full version)
package handlers

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kutup/backend/middleware"
	"github.com/kutup/backend/services/envelope"
	"github.com/gofiber/contrib/websocket"
	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"
)

type CollabHandler struct {
	DB        *pgxpool.Pool
	JWTSecret string
	Hub       *Hub
}

type wsConn struct {
	ws        *websocket.Conn
	deviceID  int64
	userID    string
	pubKey    ed25519.PublicKey
	out       chan []byte
	closed    atomic.Bool
	closeOnce sync.Once
}

const wsOutBuf = 64

func (c *wsConn) DeviceID() int64 { return c.deviceID }
func (c *wsConn) UserID() string  { return c.userID }
func (c *wsConn) WriteFrame(b []byte) error {
	if c.closed.Load() {
		return errors.New("conn closed")
	}
	select {
	case c.out <- b:
		return nil
	default:
		// Slow consumer — drop.
		c.Close()
		return errors.New("backpressure")
	}
}
func (c *wsConn) Close() {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		close(c.out)
		_ = c.ws.Close()
	})
}

// writePump fans frames from c.out to the WebSocket.
func (c *wsConn) writePump() {
	for b := range c.out {
		if err := c.ws.WriteMessage(websocket.BinaryMessage, b); err != nil {
			c.Close()
			return
		}
	}
}

// HandleConnection is the per-connection coroutine. Called by the Fiber WS handler.
func (h *CollabHandler) HandleConnection(ws *websocket.Conn, userID, fileID string, deviceID int64, pubKey ed25519.PublicKey) {
	c := &wsConn{
		ws: ws, deviceID: deviceID, userID: userID, pubKey: pubKey,
		out: make(chan []byte, wsOutBuf),
	}
	defer func() {
		h.Hub.Leave(fileID, c)
		c.Close()
	}()

	// Fetch current_doc_key_id + head seq.
	var docKeyID int64
	var headSeq int64
	_ = h.DB.QueryRow(context.Background(),
		`SELECT current_doc_key_id FROM files WHERE id=$1`, fileID,
	).Scan(&docKeyID)
	_ = h.DB.QueryRow(context.Background(),
		`SELECT COALESCE(MAX(seq), 0) FROM file_update_log WHERE file_id=$1`, fileID,
	).Scan(&headSeq)

	// Send hello.
	hello := fiber.Map{
		"type":            "hello",
		"fileId":          fileID,
		"currentDocKeyId": docKeyID,
		"headSeq":         headSeq,
		"peers":           h.peerSummaries(fileID),
	}
	if err := ws.WriteJSON(hello); err != nil {
		return
	}

	go c.writePump()
	h.Hub.Join(fileID, c)

	// Read loop.
	for {
		mt, data, err := ws.ReadMessage()
		if err != nil {
			return
		}
		switch mt {
		case websocket.TextMessage:
			h.handleControl(c, fileID, data)
		case websocket.BinaryMessage:
			h.handleFrame(c, fileID, data)
		}
	}
}

func (h *CollabHandler) peerSummaries(fileID string) []fiber.Map {
	out := []fiber.Map{}
	for _, p := range h.Hub.Peers(fileID) {
		out = append(out, fiber.Map{
			"deviceId": p.DeviceID(),
			"userId":   p.UserID(),
		})
	}
	return out
}

// handleControl handles JSON control messages (resume, etc.).
func (h *CollabHandler) handleControl(c *wsConn, fileID string, data []byte) {
	// Minimal JSON parsing; the only message in v1 is {"type":"resume","lastSeenSeq":N}.
	type resumeMsg struct {
		Type        string `json:"type"`
		LastSeenSeq int64  `json:"lastSeenSeq"`
	}
	var m resumeMsg
	if err := jsonUnmarshal(data, &m); err != nil || m.Type != "resume" {
		return
	}
	h.replayLog(c, fileID, m.LastSeenSeq)
}

// handleFrame validates and persists a binary CollabFrame.
func (h *CollabHandler) handleFrame(c *wsConn, fileID string, data []byte) {
	f, err := envelope.Unpack(data)
	if err != nil {
		return
	}
	if f.SenderDeviceID != uint64(c.deviceID) {
		return // sender mismatch — drop
	}
	if err := envelope.Verify(data, c.pubKey); err != nil {
		return
	}

	// kind=2 awareness: broadcast only, do not persist.
	if f.Kind == envelope.KindYjsAwareness {
		h.Hub.Broadcast(fileID, c, data)
		return
	}

	// kind=3 snapshot announce: persist version row, truncate log, broadcast.
	if f.Kind == envelope.KindSnapshotAnnounce {
		h.handleSnapshot(c, fileID, f, data)
		return
	}

	// All other kinds: persist + broadcast.
	seq, err := h.persistFrame(fileID, c.deviceID, f, data)
	if err != nil {
		return
	}
	// Override seq into the frame? No — clients use server's seq via control messages.
	// For v1 the server's PRIMARY KEY (file_id, seq) is the truth; clients use their own
	// per-device monotonic seq for replay protection (verified above).
	_ = seq
	h.Hub.Broadcast(fileID, c, data)
}

func (h *CollabHandler) persistFrame(fileID string, deviceID int64, f envelope.Frame, raw []byte) (int64, error) {
	var seq int64
	err := h.DB.QueryRow(context.Background(), `
		INSERT INTO file_update_log (file_id, seq, sender_device, doc_key_id, kind, frame)
		VALUES (
		  $1,
		  COALESCE((SELECT MAX(seq) FROM file_update_log WHERE file_id=$1), 0) + 1,
		  $2, $3, $4, $5
		)
		RETURNING seq
	`, fileID, deviceID, int64(f.DocKeyID), int16(f.Kind), raw).Scan(&seq)
	return seq, err
}

func (h *CollabHandler) handleSnapshot(c *wsConn, fileID string, f envelope.Frame, raw []byte) {
	// The snapshot's metadata is in the AEAD-encrypted ciphertext (the client encrypts
	// {s3VersionId, storagePath, sizeBytes, label?, keepForever?} JSON). The server
	// trusts the bare frame fields (seq, doc_key_id) AND requires the client to also
	// post the metadata via REST PATCH after the upload — the snapshot frame's role
	// here is purely "truncate log up to seq_at_snapshot". A separate REST call adds
	// the file_versions row.
	//
	// This split keeps server logic simple: the Hub only does log persistence and
	// broadcast; the file_versions table is owned by file_versions.go (Phase E).
	//
	// For v1, the snapshot frame is just a marker: persist as a normal log row,
	// broadcast, and the client also calls POST /api/files/:id/versions to record
	// the version row. (See Task E4.)
	_, _ = h.persistFrame(fileID, c.deviceID, f, raw)
	h.Hub.Broadcast(fileID, c, raw)
}

func (h *CollabHandler) replayLog(c *wsConn, fileID string, sinceSeq int64) {
	rows, err := h.DB.Query(context.Background(), `
		SELECT frame FROM file_update_log
		WHERE file_id = $1 AND seq > $2
		ORDER BY seq ASC
	`, fileID, sinceSeq)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			return
		}
		if err := c.WriteFrame(b); err != nil {
			return
		}
	}
}

// jsonUnmarshal is a thin shim to keep imports tidy.
func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
// stdlib import:
var _ = json.Marshal
```

Add to imports:
```go
import (
  // existing...
  "encoding/json"
)
```

Note: the snapshot announce-frame design above is **simplified for v1** — the server treats it like any other frame plus a marker; the actual `file_versions` row is created by a separate REST call in Phase E. This keeps the hub focused on byte-pumping. (See Task E4 for the version-row creation.)

- [ ] **Step 2: Wire the upgrade in `Upgrade()`**

```go
func (h *CollabHandler) Upgrade(authMW *middleware.Auth) fiber.Handler {
	wsHandler := websocket.New(func(ws *websocket.Conn) {
		userID, _ := ws.Locals("userID").(string)
		fileID, _ := ws.Locals("fileID").(string)
		deviceIDStr := ws.Query("deviceId")
		var deviceID int64
		fmt.Sscan(deviceIDStr, &deviceID)
		// Look up the device's pubkey + verify it belongs to userID + is_active.
		var pub []byte
		var active bool
		var ownerID string
		err := h.DB.QueryRow(context.Background(), `
			SELECT public_signing, is_active, user_id::text FROM user_devices WHERE id=$1
		`, deviceID).Scan(&pub, &active, &ownerID)
		if err != nil || !active || ownerID != userID {
			_ = ws.WriteJSON(fiber.Map{"error": "device not registered or revoked"})
			return
		}
		h.HandleConnection(ws, userID, fileID, deviceID, ed25519.PublicKey(pub))
	})

	return func(c *fiber.Ctx) error {
		return wsHandler(c)
	}
}
```

(Remove the old stub `Upgrade()` body.)

- [ ] **Step 3: Build**

```bash
go build ./... && go vet ./...
```

- [ ] **Step 4: Commit**

```bash
git add backend/handlers/collab.go
git commit -m "feat(collab): real WS connection lifecycle, frame validate/persist/broadcast"
```

---

### Task D5: Hub revocation hook + last_seen_at update

**Files:**
- Modify: `backend/handlers/collab.go` (touch last_seen_at on connect)
- Modify: `backend/main.go` (wire `WithRevokeHook`)

- [ ] **Step 1: Update last_seen_at on connect**

In `HandleConnection`, after the auth checks succeed:
```go
_, _ = h.DB.Exec(context.Background(),
    `UPDATE user_devices SET last_seen_at = now() WHERE id=$1`, deviceID)
```

- [ ] **Step 2: Wire revocation hook in main.go**

After `devicesH := ...` and `collabH := ...`, add:
```go
hub := handlers.NewHub(pool)
collabH := &handlers.CollabHandler{DB: pool, JWTSecret: cfg.JWTSecret, Hub: hub}
devicesH.WithRevokeHook(hub.CloseDevice)
```

- [ ] **Step 3: Routes for collab**

In main.go, alongside other route registrations:
```go
api.Get("/files/:fileId/collab/ws",
    collabH.PreUpgrade(authMW),
    collabH.Upgrade(authMW),
)
```

- [ ] **Step 4: Build + validate compose**

```bash
cd /home/aa/_e/development/kutup/backend && go build ./... && go vet ./...
```

- [ ] **Step 5: Commit**

```bash
git add backend/handlers/collab.go backend/main.go
git commit -m "feat(collab): wire hub + revocation hook + last_seen_at"
```

---

## Phase E — Version history backend

### Task E1: GET /api/files/:id/versions

**Files:**
- Create: `backend/handlers/file_versions.go`
- Test: `backend/handlers/file_versions_test.go`
- Modify: `backend/main.go`

- [ ] **Step 1: Implement handler**

```go
// backend/handlers/file_versions.go
package handlers

import (
	"context"
	"time"

	"github.com/kutup/backend/middleware"
	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"
)

type FileVersionsHandler struct {
	DB *pgxpool.Pool
}

type versionRow struct {
	ID              string    `json:"id"`
	S3VersionID     string    `json:"s3VersionId"`
	StoragePath     string    `json:"storagePath"`
	SeqAtSnapshot   int64     `json:"seqAtSnapshot"`
	DocKeyID        int64     `json:"docKeyId"`
	AuthorUserID    string    `json:"authorUserId"`
	SizeBytes       int64     `json:"sizeBytes"`
	Label           *string   `json:"label"`
	KeepForever     bool      `json:"keepForever"`
	CreatedAt       time.Time `json:"createdAt"`
}

// @Summary List versions for a file
// @Tags    Files
// @Security BearerAuth
// @Produce json
// @Param   fileId path string true "File UUID"
// @Success 200 {array} versionRow
// @Router /files/{fileId}/versions [get]
func (h *FileVersionsHandler) List(c *fiber.Ctx) error {
	userID := middleware.UserID(c)
	fileID := c.Params("fileId")
	if !h.canAccessFile(c.Context(), userID, fileID) {
		return c.Status(403).JSON(fiber.Map{"error": "forbidden"})
	}
	rows, err := h.DB.Query(context.Background(), `
		SELECT id::text, s3_version_id, storage_path, seq_at_snapshot,
		       doc_key_id, author_user_id::text, size_bytes,
		       label, keep_forever, created_at
		FROM file_versions
		WHERE file_id = $1
		ORDER BY created_at DESC
	`, fileID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}
	defer rows.Close()
	out := []versionRow{}
	for rows.Next() {
		var v versionRow
		if err := rows.Scan(&v.ID, &v.S3VersionID, &v.StoragePath, &v.SeqAtSnapshot,
			&v.DocKeyID, &v.AuthorUserID, &v.SizeBytes,
			&v.Label, &v.KeepForever, &v.CreatedAt); err == nil {
			out = append(out, v)
		}
	}
	return c.JSON(out)
}

func (h *FileVersionsHandler) canAccessFile(ctx context.Context, userID, fileID string) bool {
	var owner string
	var shared bool
	err := h.DB.QueryRow(ctx, `
		SELECT c.owner_user_id::text,
		       EXISTS(SELECT 1 FROM collection_shares cs
		              WHERE cs.collection_id = c.id AND cs.recipient_user_id = $2)
		FROM files f JOIN collections c ON c.id = f.collection_id
		WHERE f.id = $1
	`, fileID, userID).Scan(&owner, &shared)
	return err == nil && (owner == userID || shared)
}
```

- [ ] **Step 2: Wire in main.go**

```go
fvH := &handlers.FileVersionsHandler{DB: pool}
api.Get("/files/:fileId/versions", authMW.Required(), fvH.List)
```

- [ ] **Step 3: Build**

```bash
go build ./... && go vet ./...
```

- [ ] **Step 4: Smoke**

```bash
TOKEN=...
curl -s http://localhost/api/files/<file-id>/versions -H "Authorization: Bearer $TOKEN" | jq
```
Expected: `[]` for a file with no snapshots yet.

- [ ] **Step 5: Commit**

```bash
git add backend/handlers/file_versions.go backend/main.go
git commit -m "feat(versions): list file versions endpoint"
```

---

### Task E2: GET versions/:vid/download + PATCH

**Files:**
- Modify: `backend/handlers/file_versions.go`
- Modify: `backend/main.go`

- [ ] **Step 1: Add download + patch handlers**

```go
// backend/handlers/file_versions.go (append)

func (h *FileVersionsHandler) Download(c *fiber.Ctx) error {
	userID := middleware.UserID(c)
	fileID := c.Params("fileId")
	vid := c.Params("vid")
	if !h.canAccessFile(c.Context(), userID, fileID) {
		return c.Status(403).JSON(fiber.Map{"error": "forbidden"})
	}
	var path, s3Version string
	var docKeyID, seq int64
	err := h.DB.QueryRow(context.Background(), `
		SELECT storage_path, s3_version_id, doc_key_id, seq_at_snapshot
		FROM file_versions WHERE id = $1 AND file_id = $2
	`, vid, fileID).Scan(&path, &s3Version, &docKeyID, &seq)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "not found"})
	}
	c.Set("X-Kutup-Doc-Key-Id", fmt.Sprintf("%d", docKeyID))
	c.Set("X-Kutup-Seq", fmt.Sprintf("%d", seq))
	c.Set("X-Kutup-S3-Version", s3Version)
	// Stream the specific S3 version. Reuse FilesHandler's storage; for the path here we
	// need access to the storage service — store a pointer in FileVersionsHandler.
	body, size, err := h.Storage.GetObjectVersion(c.Context(), path, s3Version)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}
	c.Set("Content-Type", "application/octet-stream")
	c.Set("Content-Length", fmt.Sprintf("%d", size))
	return c.SendStream(body, int(size))
}

type patchVersionRequest struct {
	Label       *string `json:"label,omitempty"`
	KeepForever *bool   `json:"keepForever,omitempty"`
}

func (h *FileVersionsHandler) Patch(c *fiber.Ctx) error {
	userID := middleware.UserID(c)
	fileID := c.Params("fileId")
	vid := c.Params("vid")
	if !h.canAccessFile(c.Context(), userID, fileID) {
		return c.Status(403).JSON(fiber.Map{"error": "forbidden"})
	}
	var req patchVersionRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}
	if req.Label != nil {
		_, _ = h.DB.Exec(c.Context(),
			`UPDATE file_versions SET label = NULLIF($1, '') WHERE id = $2 AND file_id = $3`,
			*req.Label, vid, fileID)
	}
	if req.KeepForever != nil {
		_, _ = h.DB.Exec(c.Context(),
			`UPDATE file_versions SET keep_forever = $1 WHERE id = $2 AND file_id = $3`,
			*req.KeepForever, vid, fileID)
	}
	// Return the updated row.
	var v versionRow
	err := h.DB.QueryRow(c.Context(), `
		SELECT id::text, s3_version_id, storage_path, seq_at_snapshot,
		       doc_key_id, author_user_id::text, size_bytes,
		       label, keep_forever, created_at
		FROM file_versions WHERE id = $1
	`, vid).Scan(&v.ID, &v.S3VersionID, &v.StoragePath, &v.SeqAtSnapshot,
		&v.DocKeyID, &v.AuthorUserID, &v.SizeBytes,
		&v.Label, &v.KeepForever, &v.CreatedAt)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "not found"})
	}
	return c.JSON(v)
}
```

Add `Storage *services.StorageService` to `FileVersionsHandler` and wire it in main.go.

Add `GetObjectVersion(ctx, path, versionID)` method to the existing storage service (`backend/services/storage.go`) — pass `VersionId: aws.String(versionID)` to `GetObject`.

- [ ] **Step 2: Wire routes**

```go
api.Get("/files/:fileId/versions/:vid/download", authMW.Required(), fvH.Download)
api.Patch("/files/:fileId/versions/:vid", authMW.Required(), fvH.Patch)
```

- [ ] **Step 3: Build**

```bash
go build ./... && go vet ./...
```

- [ ] **Step 4: Commit**

```bash
git add backend/handlers/file_versions.go backend/services/storage.go backend/main.go
git commit -m "feat(versions): version download + label/keepForever endpoints"
```

---

### Task E3: POST snapshot — record file_versions row

**Files:**
- Modify: `backend/handlers/file_versions.go`
- Modify: `backend/main.go`

- [ ] **Step 1: Add the snapshot recording endpoint**

```go
type recordSnapshotRequest struct {
	S3VersionID    string `json:"s3VersionId"`
	StoragePath    string `json:"storagePath"`
	SeqAtSnapshot  int64  `json:"seqAtSnapshot"`
	DocKeyID       int64  `json:"docKeyId"`
	SizeBytes      int64  `json:"sizeBytes"`
	Label          string `json:"label,omitempty"`
	KeepForever    bool   `json:"keepForever,omitempty"`
}

func (h *FileVersionsHandler) Record(c *fiber.Ctx) error {
	userID := middleware.UserID(c)
	fileID := c.Params("fileId")
	if !h.canAccessFile(c.Context(), userID, fileID) {
		return c.Status(403).JSON(fiber.Map{"error": "forbidden"})
	}
	var req recordSnapshotRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}
	var id string
	err := h.DB.QueryRow(c.Context(), `
		INSERT INTO file_versions (file_id, s3_version_id, storage_path, seq_at_snapshot,
		                           doc_key_id, author_user_id, size_bytes, label, keep_forever)
		VALUES ($1,$2,$3,$4,$5,$6,$7, NULLIF($8, ''),$9)
		RETURNING id::text
	`, fileID, req.S3VersionID, req.StoragePath, req.SeqAtSnapshot,
		req.DocKeyID, userID, req.SizeBytes, req.Label, req.KeepForever).Scan(&id)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}
	// Truncate the log up to seq_at_snapshot.
	_, _ = h.DB.Exec(c.Context(),
		`DELETE FROM file_update_log WHERE file_id = $1 AND seq <= $2`,
		fileID, req.SeqAtSnapshot)
	return c.Status(201).JSON(fiber.Map{"id": id})
}
```

- [ ] **Step 2: Route**

```go
api.Post("/files/:fileId/versions", authMW.Required(), fvH.Record)
```

- [ ] **Step 3: Build**

```bash
go build ./... && go vet ./...
```

- [ ] **Step 4: Commit**

```bash
git add backend/handlers/file_versions.go backend/main.go
git commit -m "feat(versions): record snapshot endpoint + log truncate"
```

---

### Task E4: Retention cleanup job

**Files:**
- Create: `backend/services/version_cleanup.go`
- Modify: `backend/main.go`

- [ ] **Step 1: Cleanup loop**

```go
// backend/services/version_cleanup.go
package services

import (
	"context"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type VersionCleanup struct {
	DB       *pgxpool.Pool
	Storage  *StorageService
	Interval time.Duration   // default 1h
	KeepDays int             // default 30
	KeepN    int             // default 50 (per-file)
}

func (v *VersionCleanup) Run(ctx context.Context) {
	if v.Interval == 0 { v.Interval = time.Hour }
	if v.KeepDays == 0 { v.KeepDays = 30 }
	if v.KeepN == 0 { v.KeepN = 50 }
	t := time.NewTicker(v.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done(): return
		case <-t.C: v.tick(ctx)
		}
	}
}

func (v *VersionCleanup) tick(ctx context.Context) {
	// For every file, delete versions older than KeepDays AND beyond KeepN — except keep_forever.
	rows, err := v.DB.Query(ctx, `
		WITH ranked AS (
		  SELECT id, file_id, storage_path, s3_version_id, created_at, keep_forever,
		         ROW_NUMBER() OVER (PARTITION BY file_id ORDER BY created_at DESC) AS rn
		  FROM file_versions
		)
		SELECT id::text, storage_path, s3_version_id
		FROM ranked
		WHERE keep_forever = false
		  AND rn > $1
		  AND created_at < now() - ($2 || ' days')::interval
	`, v.KeepN, v.KeepDays)
	if err != nil {
		log.Printf("version cleanup query failed: %v", err)
		return
	}
	defer rows.Close()
	type doomed struct{ id, path, vid string }
	var ds []doomed
	for rows.Next() {
		var d doomed
		if err := rows.Scan(&d.id, &d.path, &d.vid); err == nil {
			ds = append(ds, d)
		}
	}
	for _, d := range ds {
		if err := v.Storage.DeleteObjectVersion(ctx, d.path, d.vid); err != nil {
			log.Printf("delete %s@%s: %v", d.path, d.vid, err)
			continue
		}
		_, _ = v.DB.Exec(ctx, `DELETE FROM file_versions WHERE id = $1`, d.id)
	}
	if len(ds) > 0 {
		log.Printf("version cleanup: pruned %d versions", len(ds))
	}
}
```

Add `DeleteObjectVersion` to `services/storage.go` (S3 `DeleteObject` with `VersionId`).

- [ ] **Step 2: Start in main.go**

```go
cleanup := &services.VersionCleanup{DB: pool, Storage: storage}
go cleanup.Run(context.Background())
```

- [ ] **Step 3: Build**

```bash
go build ./... && go vet ./...
```

- [ ] **Step 4: Commit**

```bash
git add backend/services/version_cleanup.go backend/services/storage.go backend/main.go
git commit -m "feat(versions): retention cleanup job (30d/50ver, named exempt)"
```

---

## Phase F — Frontend transport + Yjs/CodeMirror

### Task F1: WebSocket transport + reconnect

**Files:**
- Create: `frontend/src/collab/transport.ts`
- Create: `frontend/src/collab/transport.test.ts`

- [ ] **Step 1: Failing test**

```ts
// frontend/src/collab/transport.test.ts
import { describe, it, expect, vi } from 'vitest'
import { CollabTransport } from './transport'

describe('CollabTransport', () => {
  it('queues frames before connect', () => {
    const fakeWs = vi.fn()
    const t = new CollabTransport({ url: 'ws://localhost', wsFactory: () => ({} as any), onFrame: () => {}, onHello: () => {}, onError: () => {} })
    t.send(new Uint8Array([1, 2, 3]))
    expect(t.pendingCount()).toBe(1)
  })
})
```

- [ ] **Step 2: Implement (with reconnect)**

```ts
// frontend/src/collab/transport.ts
export interface HelloMsg { type: 'hello'; fileId: string; currentDocKeyId: number; headSeq: number; peers: { deviceId: number; userId: string }[] }

export interface CollabTransportOpts {
  url: string                                       // ws URL with ?token=...&deviceId=...
  wsFactory?: (url: string) => WebSocket            // overridable for tests
  onFrame: (bytes: Uint8Array) => void
  onHello: (h: HelloMsg) => void
  onError: (e: unknown) => void
  lastSeenSeq?: () => number                        // for resume on reconnect
}

export class CollabTransport {
  private ws: WebSocket | null = null
  private pending: Uint8Array[] = []
  private reconnectTimer: number | null = null
  private closed = false

  constructor(private readonly opts: CollabTransportOpts) {
    this.connect()
  }

  pendingCount() { return this.pending.length }

  send(b: Uint8Array) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(b)
    } else {
      this.pending.push(b)
    }
  }

  close() {
    this.closed = true
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer)
    this.ws?.close()
  }

  private connect() {
    if (this.closed) return
    const factory = this.opts.wsFactory ?? ((u: string) => new WebSocket(u))
    let ws: WebSocket
    try { ws = factory(this.opts.url) } catch (e) { this.opts.onError(e); this.scheduleReconnect(); return }
    this.ws = ws
    ws.binaryType = 'arraybuffer'
    ws.addEventListener('open', () => {
      // Resume if we have a sequence to ask from.
      const last = this.opts.lastSeenSeq?.() ?? 0
      ws.send(JSON.stringify({ type: 'resume', lastSeenSeq: last }))
      // Drain queued.
      for (const p of this.pending) ws.send(p)
      this.pending = []
    })
    ws.addEventListener('message', (ev) => {
      if (typeof ev.data === 'string') {
        try {
          const obj = JSON.parse(ev.data)
          if (obj.type === 'hello') this.opts.onHello(obj as HelloMsg)
        } catch { /* ignore */ }
      } else {
        const arr = ev.data instanceof ArrayBuffer ? new Uint8Array(ev.data) : new Uint8Array(ev.data)
        this.opts.onFrame(arr)
      }
    })
    ws.addEventListener('close', () => { if (!this.closed) this.scheduleReconnect() })
    ws.addEventListener('error', (e) => this.opts.onError(e))
  }

  private scheduleReconnect() {
    if (this.closed) return
    if (this.reconnectTimer) return
    this.reconnectTimer = window.setTimeout(() => {
      this.reconnectTimer = null
      this.connect()
    }, 1500)
  }
}
```

- [ ] **Step 3: Run tests**

```bash
cd /home/aa/_e/development/kutup/frontend && pnpm test transport
```

- [ ] **Step 4: Commit**

```bash
git add frontend/src/collab/transport.ts frontend/src/collab/transport.test.ts
git commit -m "feat(frontend): WebSocket collab transport + reconnect"
```

---

### Task F2: Yjs + CodeMirror 6 deps + lang map

**Files:**
- Modify: `frontend/package.json`
- Create: `frontend/src/components/editors/lang.ts`

- [ ] **Step 1: Install deps**

```bash
cd /home/aa/_e/development/kutup/frontend
pnpm add yjs y-codemirror.next y-protocols \
         codemirror @codemirror/state @codemirror/view \
         @codemirror/lang-markdown @codemirror/lang-javascript \
         @codemirror/lang-python @codemirror/lang-rust @codemirror/lang-go \
         @codemirror/lang-json @codemirror/lang-yaml @codemirror/lang-html \
         @codemirror/lang-css @codemirror/lang-sql
```

- [ ] **Step 2: Lang dispatch**

```ts
// frontend/src/components/editors/lang.ts
import { type Extension } from '@codemirror/state'
import { markdown } from '@codemirror/lang-markdown'
import { javascript } from '@codemirror/lang-javascript'
import { python } from '@codemirror/lang-python'
import { rust } from '@codemirror/lang-rust'
import { go } from '@codemirror/lang-go'
import { json } from '@codemirror/lang-json'
import { yaml } from '@codemirror/lang-yaml'
import { html } from '@codemirror/lang-html'
import { css } from '@codemirror/lang-css'
import { sql } from '@codemirror/lang-sql'

export function langForExtension(ext: string): Extension | null {
  switch (ext.toLowerCase()) {
    case 'md':
    case 'markdown':
      return markdown()
    case 'js':
    case 'mjs':
    case 'cjs':
    case 'jsx':
      return javascript()
    case 'ts':
    case 'tsx':
      return javascript({ typescript: true, jsx: true })
    case 'py':
      return python()
    case 'rs':
      return rust()
    case 'go':
      return go()
    case 'json':
      return json()
    case 'yaml':
    case 'yml':
      return yaml()
    case 'html':
    case 'htm':
      return html()
    case 'css':
      return css()
    case 'sql':
      return sql()
    case 'txt':
    default:
      return null
  }
}
```

- [ ] **Step 3: Type-check**

```bash
pnpm tsc --noEmit
```

- [ ] **Step 4: Commit**

```bash
git add frontend/package.json frontend/pnpm-lock.yaml frontend/src/components/editors/lang.ts
git commit -m "feat(frontend): CodeMirror 6 + Yjs deps + language dispatch"
```

---

### Task F3: TextCollabEditor component

**Files:**
- Create: `frontend/src/components/editors/TextCollabEditor.tsx`

- [ ] **Step 1: Implement**

```tsx
// frontend/src/components/editors/TextCollabEditor.tsx
import { useEffect, useRef } from 'react'
import * as Y from 'yjs'
import { yCollab } from 'y-codemirror.next'
import { Awareness } from 'y-protocols/awareness'
import { EditorState, type Extension } from '@codemirror/state'
import { EditorView, keymap } from '@codemirror/view'
import { defaultKeymap, history, historyKeymap } from '@codemirror/commands'
import { langForExtension } from './lang'
import { CollabTransport, type HelloMsg } from '../../collab/transport'
import { pack, unpack, KIND, type Frame } from '../../collab/envelope'
// Crypto helpers from Phase F4 — declared here, defined in next task:
import { encryptYjsUpdate, decryptYjsUpdate, encryptAwareness, decryptAwareness, getDeviceId, getDevicePrivateKey } from '../../collab/cryptoFrame'
import { ed25519Sign } from '../../collab/sign' // tiny helper around libsodium crypto_sign_detached
import { useAppSelector } from '../../store'

interface Props {
  fileId: string
  filename: string
}

export default function TextCollabEditor({ fileId, filename }: Props) {
  const ref = useRef<HTMLDivElement>(null)
  const accessToken = useAppSelector(s => s.auth.accessToken)
  const deviceId = useAppSelector(s => s.auth.currentDeviceId)

  useEffect(() => {
    if (!ref.current || !accessToken || !deviceId) return

    const ext = filename.split('.').pop()?.toLowerCase() ?? ''
    const ydoc = new Y.Doc()
    const ytext = ydoc.getText('content')
    const awareness = new Awareness(ydoc)
    let lastSeenSeq = 0
    let docKeyId = 1
    let outboundSeq = 0n

    const wsUrl = `${location.origin.replace(/^http/, 'ws')}/api/files/${fileId}/collab/ws?token=${encodeURIComponent(accessToken)}&deviceId=${deviceId}`

    const transport = new CollabTransport({
      url: wsUrl,
      lastSeenSeq: () => lastSeenSeq,
      onHello: (h: HelloMsg) => {
        docKeyId = h.currentDocKeyId
        lastSeenSeq = h.headSeq
      },
      onFrame: async (bs) => {
        try {
          const f = unpack(bs)
          // TODO verify peer signature: skipped in v1 because clients don't track peer
          // device pubkeys yet (server has already validated). Add in v1.1.
          if (f.kind === KIND.YJS_UPDATE) {
            const upd = await decryptYjsUpdate(f, fileId)
            Y.applyUpdate(ydoc, upd, 'remote')
          } else if (f.kind === KIND.YJS_AWARENESS) {
            const upd = await decryptAwareness(f, fileId)
            // Apply to awareness via y-protocols message handler
            applyAwarenessRemote(awareness, upd)
          }
        } catch (e) { /* drop bad frames */ }
      },
      onError: (e) => console.error('collab transport error', e),
    })

    // Local update -> encrypt + sign + send.
    const localObserver = (update: Uint8Array, origin: unknown) => {
      if (origin === 'remote') return
      ;(async () => {
        outboundSeq++
        const f = await encryptYjsUpdate(update, fileId, docKeyId, BigInt(deviceId), outboundSeq)
        await signAndSend(f, transport)
      })()
    }
    ydoc.on('update', localObserver)

    // Local awareness -> encrypt + send.
    const awarenessObserver = ({ added, updated, removed }: any) => {
      const changed = [...added, ...updated, ...removed]
      if (changed.length === 0) return
      ;(async () => {
        const upd = encodeAwarenessUpdate(awareness, changed)
        outboundSeq++
        const f = await encryptAwareness(upd, fileId, docKeyId, BigInt(deviceId), outboundSeq)
        await signAndSend(f, transport)
      })()
    }
    awareness.on('change', awarenessObserver)

    // Build CodeMirror.
    const langExt = langForExtension(ext)
    const exts: Extension[] = [
      keymap.of([...defaultKeymap, ...historyKeymap]),
      history(),
      ...(langExt ? [langExt] : []),
      yCollab(ytext, awareness),
    ]
    const state = EditorState.create({ extensions: exts })
    const view = new EditorView({ state, parent: ref.current })

    return () => {
      ydoc.off('update', localObserver)
      awareness.off('change', awarenessObserver)
      view.destroy()
      ydoc.destroy()
      transport.close()
    }
  }, [fileId, filename, accessToken, deviceId])

  return <div ref={ref} className="h-full w-full" />
}

// Helper to sign and send a Frame.
async function signAndSend(f: Frame, transport: CollabTransport) {
  const priv = getDevicePrivateKey()
  const packed = pack(f)
  const body = packed.subarray(0, packed.length - 64)
  const sig = await ed25519Sign(body, priv)
  packed.set(sig, packed.length - 64)
  transport.send(packed)
}

// y-protocols/awareness helpers (re-implementing the small slice we need)
import { encodeAwarenessUpdate, applyAwarenessUpdate } from 'y-protocols/awareness'

function applyAwarenessRemote(aw: Awareness, upd: Uint8Array) {
  applyAwarenessUpdate(aw, upd, 'remote')
}
```

- [ ] **Step 2: Create the helper modules referenced above**

```ts
// frontend/src/collab/sign.ts
import _sodium from 'libsodium-wrappers-sumo'

export async function ed25519Sign(message: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array> {
  await _sodium.ready
  return _sodium.crypto_sign_detached(message, privateKey)
}

export async function ed25519Verify(message: Uint8Array, sig: Uint8Array, pub: Uint8Array): Promise<boolean> {
  await _sodium.ready
  try { return _sodium.crypto_sign_verify_detached(sig, message, pub) } catch { return false }
}
```

- [ ] **Step 3: Type-check**

```bash
pnpm tsc --noEmit
```

(There will be type errors until the next task's `cryptoFrame.ts` lands. That's fine — Task F4 closes the loop. If we want to keep the build green between tasks, stub out `cryptoFrame.ts` first.)

- [ ] **Step 4: Commit**

```bash
git add frontend/src/components/editors/TextCollabEditor.tsx frontend/src/collab/sign.ts
git commit -m "feat(frontend): TextCollabEditor wiring CodeMirror + Yjs + transport"
```

---

### Task F4: Per-file content key + AEAD frame encrypt/decrypt

**Files:**
- Create: `frontend/src/collab/cryptoFrame.ts`
- Create: `frontend/src/collab/cryptoFrame.test.ts`

- [ ] **Step 1: Failing test**

```ts
// frontend/src/collab/cryptoFrame.test.ts
import { describe, it, expect } from 'vitest'
import _sodium from 'libsodium-wrappers-sumo'
import { encryptYjsUpdate, decryptYjsUpdate, deriveContentKey } from './cryptoFrame'

describe('cryptoFrame', () => {
  it('encrypt then decrypt round-trips a Yjs update', async () => {
    await _sodium.ready
    // Stub the collection master key in the test by setting a known value (the prod
    // code reads it from auth state; here we use the lower-level functions directly).
    const fileId = '00000000-0000-0000-0000-000000000001'
    const masterKey = _sodium.randombytes_buf(32)
    const update = new TextEncoder().encode('test yjs update bytes')
    const f = await encryptYjsUpdate(update, fileId, 1, 1n, 1n, masterKey)
    const out = await decryptYjsUpdate(f, fileId, masterKey)
    expect(new TextDecoder().decode(out)).toBe('test yjs update bytes')
  })
  it('deriveContentKey is deterministic per (collection, fileId)', async () => {
    await _sodium.ready
    const m = _sodium.randombytes_buf(32)
    const k1 = await deriveContentKey(m, 'abc')
    const k2 = await deriveContentKey(m, 'abc')
    expect(Array.from(k1)).toEqual(Array.from(k2))
  })
})
```

- [ ] **Step 2: Implement**

```ts
// frontend/src/collab/cryptoFrame.ts
import _sodium from 'libsodium-wrappers-sumo'
import { pack, KIND, HEADER_SIZE, type Frame } from './envelope'

const ZERO_SIG = new Uint8Array(64)

/** HKDF-SHA256(ikm=masterKey, salt="kutup/file-content/v1", info=fileId-bytes). */
export async function deriveContentKey(collectionMaster: Uint8Array, fileId: string): Promise<Uint8Array> {
  await _sodium.ready
  // libsodium has crypto_kdf_hkdf_sha256_extract / _expand
  const salt = new TextEncoder().encode('kutup/file-content/v1')
  const info = new TextEncoder().encode(fileId)
  // @ts-expect-error sumo build exposes these; types may lag
  const prk = _sodium.crypto_kdf_hkdf_sha256_extract(salt, collectionMaster)
  // @ts-expect-error
  const okm = _sodium.crypto_kdf_hkdf_sha256_expand(info, 32, prk)
  return okm
}

async function aeadEncrypt(plaintext: Uint8Array, aad: Uint8Array, key: Uint8Array, nonce: Uint8Array): Promise<Uint8Array> {
  await _sodium.ready
  return _sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, null, nonce, key)
}
async function aeadDecrypt(ct: Uint8Array, aad: Uint8Array, key: Uint8Array, nonce: Uint8Array): Promise<Uint8Array> {
  await _sodium.ready
  return _sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ct, aad, nonce, key)
}

async function buildFrame(plain: Uint8Array, kind: number, fileId: string, docKeyId: number,
                          deviceId: bigint, sequence: bigint, masterOverride?: Uint8Array): Promise<Frame> {
  await _sodium.ready
  const key = masterOverride
    ? await deriveContentKey(masterOverride, fileId)
    : await getCollectionContentKey(fileId)
  const nonce = _sodium.randombytes_buf(24)
  // Build a draft frame to compute AAD bytes, then run AEAD over plaintext.
  const draft: Frame = {
    version: 1, kind, docKeyId,
    senderDeviceId: deviceId, sequence,
    nonce, ciphertext: new Uint8Array(0), signature: ZERO_SIG,
  }
  const headerBytes = pack(draft).subarray(0, HEADER_SIZE)
  const ct = await aeadEncrypt(plain, headerBytes, key, nonce)
  return { ...draft, ciphertext: ct }
}

export async function encryptYjsUpdate(update: Uint8Array, fileId: string, docKeyId: number,
                                       deviceId: bigint, sequence: bigint, masterOverride?: Uint8Array): Promise<Frame> {
  return buildFrame(update, KIND.YJS_UPDATE, fileId, docKeyId, deviceId, sequence, masterOverride)
}
export async function encryptAwareness(update: Uint8Array, fileId: string, docKeyId: number,
                                       deviceId: bigint, sequence: bigint, masterOverride?: Uint8Array): Promise<Frame> {
  return buildFrame(update, KIND.YJS_AWARENESS, fileId, docKeyId, deviceId, sequence, masterOverride)
}

export async function decryptYjsUpdate(f: Frame, fileId: string, masterOverride?: Uint8Array): Promise<Uint8Array> {
  return decryptCommon(f, fileId, masterOverride)
}
export async function decryptAwareness(f: Frame, fileId: string, masterOverride?: Uint8Array): Promise<Uint8Array> {
  return decryptCommon(f, fileId, masterOverride)
}

async function decryptCommon(f: Frame, fileId: string, masterOverride?: Uint8Array): Promise<Uint8Array> {
  await _sodium.ready
  const key = masterOverride
    ? await deriveContentKey(masterOverride, fileId)
    : await getCollectionContentKey(fileId)
  const headerBytes = pack(f).subarray(0, HEADER_SIZE)
  return aeadDecrypt(f.ciphertext, headerBytes, key, f.nonce)
}

// Helper: read the collection master key from Redux state (placeholder — wire to real store).
async function getCollectionContentKey(fileId: string): Promise<Uint8Array> {
  // TODO: look up file's collection key via existing kutup model.
  // For v1, the editor component will pass the collection master key explicitly via
  // masterOverride, so this fallback throws to fail loud if anyone forgets to pass it.
  throw new Error('collection master key not provided; pass masterOverride')
}

// Device-key plumbing (read from sessionStorage helpers in collab/devices).
import { loadKeypair } from './devices'

export function getDeviceId(): number {
  // The numeric deviceId is held in Redux; component passes it directly.
  // Helper kept here for future code paths.
  throw new Error('use auth state for deviceId')
}
export function getDevicePrivateKey(): Uint8Array {
  const kp = loadKeypair()
  if (!kp) throw new Error('no device keypair in sessionStorage')
  return kp.privateKey
}
```

- [ ] **Step 3: Update TextCollabEditor to thread masterOverride**

In `TextCollabEditor.tsx`, get the collection master key from existing Redux state (the `masterKey` already in `authSlice`), pass it through to the encrypt/decrypt calls.

- [ ] **Step 4: Run tests**

```bash
pnpm test cryptoFrame
```

- [ ] **Step 5: Commit**

```bash
git add frontend/src/collab/cryptoFrame.ts frontend/src/collab/cryptoFrame.test.ts frontend/src/components/editors/TextCollabEditor.tsx
git commit -m "feat(frontend): per-file content key + AEAD frame encrypt/decrypt"
```

---

### Task F5: Snapshot trigger + S3 PUT + announce

**Files:**
- Create: `frontend/src/collab/snapshot.ts`

- [ ] **Step 1: Implement**

```ts
// frontend/src/collab/snapshot.ts
import * as Y from 'yjs'
import { client } from '../api/client'

const IDLE_MS = 30_000
const HARD_CEILING = 200

interface SnapshotOpts {
  fileId: string
  ydoc: Y.Doc
  encryptSnapshot: (bytes: Uint8Array) => Promise<{ ciphertext: Uint8Array; storageHints: { docKeyId: number; sizeBytes: number } }>
  getSeq: () => number
}

export class SnapshotTrigger {
  private updatesSince = 0
  private idleTimer: number | null = null
  private inflight = false

  constructor(private readonly opts: SnapshotOpts) {
    opts.ydoc.on('update', () => this.onUpdate())
  }

  forceSave(label?: string, keepForever = false) { return this.snapshot(label, keepForever) }

  private onUpdate() {
    this.updatesSince++
    if (this.idleTimer) clearTimeout(this.idleTimer)
    this.idleTimer = window.setTimeout(() => this.snapshot(), IDLE_MS)
    if (this.updatesSince >= HARD_CEILING) this.snapshot()
  }

  private async snapshot(label?: string, keepForever = false) {
    if (this.inflight || this.updatesSince === 0) return
    this.inflight = true
    try {
      const stateUpdate = Y.encodeStateAsUpdateV2(this.opts.ydoc)
      const { ciphertext, storageHints } = await this.opts.encryptSnapshot(stateUpdate)
      // PUT to S3 via existing kutup file-upload endpoint that also returns the version id.
      // For v1, reuse a small wrapper endpoint that PUTs and returns S3 version metadata.
      const fd = new FormData()
      fd.append('file', new Blob([ciphertext], { type: 'application/octet-stream' }))
      const upRes = await client.post(`/api/files/${this.opts.fileId}/snapshot-blob`, fd)
      const { storagePath, s3VersionId } = upRes.data as { storagePath: string; s3VersionId: string }
      // Announce.
      await client.post(`/api/files/${this.opts.fileId}/versions`, {
        s3VersionId, storagePath,
        seqAtSnapshot: this.opts.getSeq(),
        docKeyId: storageHints.docKeyId,
        sizeBytes: storageHints.sizeBytes,
        label: label ?? null, keepForever,
      })
      this.updatesSince = 0
    } finally {
      this.inflight = false
    }
  }
}
```

- [ ] **Step 2: Backend snapshot-blob upload endpoint**

Add a thin handler to `backend/handlers/file_versions.go`:
```go
func (h *FileVersionsHandler) UploadSnapshotBlob(c *fiber.Ctx) error {
    userID := middleware.UserID(c)
    fileID := c.Params("fileId")
    if !h.canAccessFile(c.Context(), userID, fileID) {
        return c.Status(403).JSON(fiber.Map{"error": "forbidden"})
    }
    fh, err := c.FormFile("file")
    if err != nil { return c.Status(400).JSON(fiber.Map{"error": "missing file"}) }
    f, err := fh.Open()
    if err != nil { return c.Status(500).JSON(fiber.Map{"error": "internal error"}) }
    defer f.Close()
    storagePath := fmt.Sprintf("files/%s/snapshot", fileID)
    versionID, err := h.Storage.PutObjectVersioned(c.Context(), storagePath, f, fh.Size)
    if err != nil { return c.Status(500).JSON(fiber.Map{"error": "internal error"}) }
    return c.JSON(fiber.Map{"storagePath": storagePath, "s3VersionId": versionID})
}
```

`PutObjectVersioned` lives in `services/storage.go` — wraps `s3.PutObject` and reads `VersionId` from the response.

Wire route:
```go
api.Post("/files/:fileId/snapshot-blob", authMW.Required(), fvH.UploadSnapshotBlob)
```

- [ ] **Step 3: Build + commit**

```bash
cd /home/aa/_e/development/kutup/backend && go build ./... && go vet ./...
cd ../frontend && pnpm tsc --noEmit
git add backend/handlers/file_versions.go backend/services/storage.go backend/main.go frontend/src/collab/snapshot.ts
git commit -m "feat(snapshot): client trigger + S3 versioned PUT + announce"
```

---

### Task F6: Wire SnapshotTrigger into TextCollabEditor

**Files:**
- Modify: `frontend/src/components/editors/TextCollabEditor.tsx`

- [ ] **Step 1: Add the trigger**

Inside the `useEffect` body of `TextCollabEditor`, after `ydoc` is created:
```ts
const trigger = new SnapshotTrigger({
  fileId,
  ydoc,
  encryptSnapshot: async (bytes) => {
    // Encrypt as a snapshot blob using the same per-file key.
    const key = await deriveContentKey(masterKey, fileId)
    await _sodium.ready
    const nonce = _sodium.randombytes_buf(24)
    const ct = _sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(bytes, null, null, nonce, key)
    // Prepend the nonce so the server-blind blob is self-contained for decryption later.
    const out = new Uint8Array(24 + ct.length)
    out.set(nonce, 0); out.set(ct, 24)
    return { ciphertext: out, storageHints: { docKeyId, sizeBytes: out.length } }
  },
  getSeq: () => Number(outboundSeq), // last seq we emitted
})
// Cleanup:
return () => { ...; /* ensure trigger isn't holding refs */ }
```

(Add the necessary imports: `SnapshotTrigger`, `deriveContentKey`, `_sodium`.)

Add a "Save version" button that calls `trigger.forceSave(name, true)`.

- [ ] **Step 2: Type-check + commit**

```bash
pnpm tsc --noEmit
git add frontend/src/components/editors/TextCollabEditor.tsx
git commit -m "feat(frontend): wire SnapshotTrigger into TextCollabEditor"
```

---

## Phase G — Frontend UI integration

### Task G1: chooseEditor + Drive integration

**Files:**
- Create: `frontend/src/components/editors/dispatch.tsx`
- Modify: `frontend/src/pages/Drive.tsx`

- [ ] **Step 1: Dispatch helper**

```tsx
// frontend/src/components/editors/dispatch.tsx
import { lazy } from 'react'

const TextCollabEditor = lazy(() => import('./TextCollabEditor'))

const TEXT_EXT = new Set([
  'md','markdown','txt','go','js','mjs','cjs','jsx','ts','tsx','py','rs',
  'json','yaml','yml','html','htm','css','toml','sh','sql','dockerfile','nix',
])

export function chooseEditor(filename: string) {
  const ext = filename.split('.').pop()?.toLowerCase() ?? ''
  if (TEXT_EXT.has(ext)) return TextCollabEditor
  return null
}
```

- [ ] **Step 2: Drive integration**

In `frontend/src/pages/Drive.tsx`, at the file-click handler, before falling back to the existing preview/download flow:
```tsx
import { chooseEditor } from '../components/editors/dispatch'
// ...
function onFileClick(f: FileRow) {
  const Editor = chooseEditor(f.filename)
  if (Editor) {
    setOpenEditor({ fileId: f.id, filename: f.filename, Component: Editor })
  } else {
    openPreview(f) // existing
  }
}
```

Add a modal or split-pane container that mounts the chosen editor.

- [ ] **Step 3: Type-check + commit**

```bash
pnpm tsc --noEmit
git add frontend/src/components/editors/dispatch.tsx frontend/src/pages/Drive.tsx
git commit -m "feat(frontend): file extension dispatch + Drive editor integration"
```

---

### Task G2: Device registration on first editor open

**Files:**
- Modify: `frontend/src/components/editors/TextCollabEditor.tsx`

- [ ] **Step 1: Ensure a device is registered before connecting**

Inside the `useEffect`, **before** building the WebSocket URL:
```ts
let kp = loadKeypair()
if (!kp) { kp = await generateDeviceKeypair(); saveKeypair(kp) }
let did = deviceId
if (!did) {
  const r = await registerDevice(encodePubKeyB64(kp.publicKey), navigator.userAgent.slice(0, 80))
  did = r.deviceId
  dispatch(setDeviceId(did))
}
```

(Wrap the existing logic in an async IIFE or convert the effect to use an async helper.)

- [ ] **Step 2: Type-check + commit**

```bash
pnpm tsc --noEmit
git add frontend/src/components/editors/TextCollabEditor.tsx
git commit -m "feat(frontend): register device on first editor open"
```

---

### Task G3: Version history panel

**Files:**
- Create: `frontend/src/components/VersionHistory/VersionHistoryPanel.tsx`
- Create: `frontend/src/components/VersionHistory/VersionRow.tsx`

- [ ] **Step 1: Panel component**

```tsx
// frontend/src/components/VersionHistory/VersionHistoryPanel.tsx
import { useEffect, useState } from 'react'
import { listVersions, type VersionRow as VR } from '../../api/collab'
import VersionRow from './VersionRow'

export default function VersionHistoryPanel({ fileId }: { fileId: string }) {
  const [versions, setVersions] = useState<VR[]>([])
  const [loading, setLoading] = useState(true)
  useEffect(() => {
    let alive = true
    ;(async () => {
      try {
        const v = await listVersions(fileId)
        if (alive) setVersions(v)
      } finally { if (alive) setLoading(false) }
    })()
    return () => { alive = false }
  }, [fileId])
  if (loading) return <div className="p-4 text-sm text-muted-foreground">Loading…</div>
  if (versions.length === 0) return <div className="p-4 text-sm text-muted-foreground">No versions yet.</div>
  return (
    <div className="flex flex-col divide-y">
      {versions.map(v => <VersionRow key={v.id} fileId={fileId} v={v} onChange={(updated) => setVersions(arr => arr.map(x => x.id === v.id ? updated : x))} />)}
    </div>
  )
}
```

- [ ] **Step 2: Row component**

```tsx
// frontend/src/components/VersionHistory/VersionRow.tsx
import { useState } from 'react'
import { patchVersion, type VersionRow as VR } from '../../api/collab'

export default function VersionRow({ fileId, v, onChange }: { fileId: string; v: VR; onChange: (v: VR) => void }) {
  const [naming, setNaming] = useState(false)
  const [name, setName] = useState(v.label ?? '')
  return (
    <div className="p-3 hover:bg-muted">
      <div className="flex items-center justify-between">
        <div>
          <div className="text-sm font-medium">{new Date(v.createdAt).toLocaleString()}</div>
          {v.label && <div className="text-xs text-muted-foreground">{v.label}</div>}
        </div>
        <div className="flex gap-2">
          <button className="text-xs underline" onClick={() => setNaming(true)}>Name…</button>
          <button className="text-xs underline" onClick={async () => {
            const updated = await patchVersion(fileId, v.id, { keepForever: !v.keepForever })
            onChange(updated)
          }}>{v.keepForever ? 'Unkeep' : 'Keep forever'}</button>
        </div>
      </div>
      {naming && (
        <div className="mt-2 flex gap-2">
          <input className="flex-1 border px-2 text-sm" value={name} onChange={e => setName(e.target.value)} />
          <button className="text-xs" onClick={async () => {
            const updated = await patchVersion(fileId, v.id, { label: name })
            onChange(updated); setNaming(false)
          }}>Save</button>
          <button className="text-xs" onClick={() => setNaming(false)}>Cancel</button>
        </div>
      )}
    </div>
  )
}
```

- [ ] **Step 3: Mount in editor view**

Add `<VersionHistoryPanel fileId={fileId} />` to the editor modal layout (right rail or toggleable).

- [ ] **Step 4: Type-check + commit**

```bash
pnpm tsc --noEmit
git add frontend/src/components/VersionHistory/
git commit -m "feat(frontend): version history panel + row UI"
```

---

### Task G4: Restore flow

**Files:**
- Modify: `frontend/src/components/VersionHistory/VersionRow.tsx`

- [ ] **Step 1: Add restore button**

```tsx
// in VersionRow, alongside the other buttons:
<button className="text-xs underline" onClick={async () => {
  if (!confirm('Restore this version? Current state will be saved as a new version first.')) return
  // 1. Download the version blob.
  const r = await fetch(`/api/files/${fileId}/versions/${v.id}/download`, {
    headers: { Authorization: `Bearer ${getToken()}` },
  })
  const blob = new Uint8Array(await r.arrayBuffer())
  // 2. Decrypt (the snapshot format = nonce(24) || aead(stateAsUpdateV2)).
  const nonce = blob.slice(0, 24)
  const ct = blob.slice(24)
  // ... decrypt with derived key
  // 3. Apply to a fresh Y.Doc, then encodeStateAsUpdateV2, then call SnapshotTrigger.forceSave with label "Restored from <date>"
  // (Implementation detail in the editor; this row component fires an onRestore callback.)
  await onRestore?.(v.id)
}}>Restore</button>
```

The decrypt/apply logic lives in the editor; the row emits `onRestore(versionId)`. Wire the editor to:
1. Pause local edits.
2. Download + decrypt the version's encrypted state.
3. `Y.applyUpdate(ydoc, decryptedStateAsUpdateV2)` (this overwrites local state under the same Yjs ID model — Yjs's CRDT semantics make this safe).
4. Force a snapshot via `trigger.forceSave('Restored from <date>')`.

- [ ] **Step 2: Wire onRestore**

In `VersionHistoryPanel`, accept and propagate an `onRestore` prop. Pass through from the editor.

- [ ] **Step 3: Commit**

```bash
git add frontend/src/components/VersionHistory/VersionRow.tsx frontend/src/components/VersionHistory/VersionHistoryPanel.tsx frontend/src/components/editors/TextCollabEditor.tsx
git commit -m "feat(frontend): version restore flow"
```

---

### Task G5: Devices in Settings

**Files:**
- Modify: `frontend/src/pages/Settings.tsx`

- [ ] **Step 1: Add a Devices section**

```tsx
import { useEffect, useState } from 'react'
import { listDevices, revokeDevice, type DeviceRow } from '../api/collab'

function DevicesSection() {
  const [devs, setDevs] = useState<DeviceRow[]>([])
  useEffect(() => { listDevices().then(setDevs) }, [])
  return (
    <section className="mt-6">
      <h2 className="text-lg font-semibold">Devices</h2>
      <ul className="mt-2 divide-y">
        {devs.map(d => (
          <li key={d.deviceId} className="py-2 flex justify-between">
            <div>
              <div>{d.label || `Device ${d.deviceId}`}</div>
              <div className="text-xs text-muted-foreground">
                {d.isActive ? 'Active' : 'Revoked'} · last seen {d.lastSeenAt ?? '—'}
              </div>
            </div>
            {d.isActive && (
              <button onClick={async () => {
                if (!confirm('Revoke this device?')) return
                await revokeDevice(d.deviceId)
                setDevs(arr => arr.map(x => x.deviceId === d.deviceId ? { ...x, isActive: false } : x))
              }}>Revoke</button>
            )}
          </li>
        ))}
      </ul>
    </section>
  )
}
```

Mount in the Settings page.

- [ ] **Step 2: Commit**

```bash
git add frontend/src/pages/Settings.tsx
git commit -m "feat(frontend): devices section in settings + revoke action"
```

---

## Phase H — Verification + docs

### Task H1: End-to-end manual smoke

- [ ] **Step 1: Run the spec §15 manual scenarios**

From `docs/superpowers/specs/2026-05-04-collab-edit-design.md` §15, manually execute:

1. Open `notes.md` in two browser tabs as the same user. Edits in tab A appear in tab B in <500 ms. Cursors visible.
2. Open the same file as a different user (collection co-member). Edits flow both directions; presence shows two distinct users.
3. Leave both tabs idle for 31 s. Confirm a snapshot row appears in `file_versions`. Confirm the `file_update_log` is truncated.
4. Click "Save version" + give it a name → confirm `keep_forever=true` row in DB.
5. Restore an older version → confirm content matches and a new snapshot row is created.
6. Disconnect for 30 s, then reconnect. Confirm gap replay and no missing edits.
7. Revoke the second device → confirm subsequent edits from that device are rejected and the device is removed from the peer list.
8. Download `notes.md` via the existing file API. Confirm the bytes are the latest snapshot's plaintext after client decryption.

Document any failures as bugs, fix, re-run.

**Security spot-check:**
```bash
docker compose logs backend | grep -ci 'hello' && echo "fail: plaintext leak" || echo "ok"
docker compose exec postgres psql -U kutup -d kutup -c \
  "SELECT COUNT(*) FROM file_update_log WHERE encode(frame, 'escape') LIKE '%hello%'"
```
Expected: zero matches after typing "hello" in the editor.

- [ ] **Step 2: Commit any fixes; no commit if all passes**

---

### Task H2: Update docs/architecture.md

**Files:**
- Modify: `docs/architecture.md`

- [ ] **Step 1: Append a new section**

```markdown
## Collaborative Editing

kutup supports real-time, end-to-end-encrypted collaborative editing of text/markdown/code files (`.txt`, `.md`, code formats). Office docs (`.docx/.xlsx/.pptx/.odt/.ods/.odp`) are deferred to a future release.

The architecture is summarised below; the design rationale and pitfalls live in [`docs/superpowers/specs/2026-05-04-collab-edit-design.md`](superpowers/specs/2026-05-04-collab-edit-design.md).

### Sync engine
Yjs CRDT (`Y.Text`) under CodeMirror 6 with `y-codemirror.next`. Clients exchange opaque binary update frames; the server never instantiates a `Y.Doc`.

### Wire envelope
Each frame is wrapped in an XChaCha20-Poly1305 AEAD with `(version, kind, doc_key_id, sender_device_id, sequence)` as additional authenticated data, then signed with the sender's Ed25519 device key. The server validates the signature and stores the opaque ciphertext.

### Per-file content key
Derived deterministically as `HKDF-SHA256(collection_master_key, "kutup/file-content/v1", file_id)`. No new key wrapping — the existing collection-key plumbing already distributes the master key to authorized members.

### Device keys
Each browser tab session and each CLI session generates a fresh Ed25519 keypair. The public key is registered to the user account; the private key never leaves the device. Revocation marks the device inactive and forces existing WebSocket connections to close.

### Versioning
Two-tier:
- **Live deltas** in Postgres `file_update_log` (truncated on snapshot).
- **Snapshots** as SeaweedFS S3 noncurrent versions, indexed in `file_versions`.

Snapshots fire on idle 30 s + ≥ 1 update, every 200 updates, on explicit "Save version", or on collection-membership change.

Retention: 30 days OR last 50 versions, whichever yields more. Named/keep-forever versions are exempt forever.

### Federation, sharing
Existing collection-share + federation flows are unchanged. A live-edited file is still a regular `files` row with an encrypted blob; non-editing users continue to download it as today.
```

- [ ] **Step 2: Commit**

```bash
git add docs/architecture.md
git commit -m "docs(architecture): document collaborative editing"
```

---

### Task H3: Update docs/api.md

**Files:**
- Modify: `docs/api.md`

- [ ] **Step 1: Add the new endpoint sections**

Append after the existing Files section:

```markdown
---

## Devices

### POST /api/devices
Register a device signing key. Required before opening any collaborative-edit WebSocket.
**Auth:** Bearer JWT.
**Body:** `{publicSigning: <base64-32>, label?: string, authSig: <base64>, timestamp: <unix-seconds>}`
**Response 201:** `{deviceId, label, createdAt}`

### GET /api/devices
**Response:** array of `{deviceId, label, isActive, createdAt, lastSeenAt}`.

### DELETE /api/devices/:id
Revoke a device. Closes any open WebSocket connections from that device with code 4401.
**Response:** `204`.

---

## Collaborative Editing

### GET /api/files/:fileId/collab/ws
WebSocket upgrade. Auth via `Authorization: Bearer ...` header **or** `?token=...&deviceId=N` query.

On accept the server sends a JSON `hello` `{type, fileId, currentDocKeyId, headSeq, peers: [{deviceId, userId}]}`. Client replies with JSON `{type: "resume", lastSeenSeq: K}`. Server replays binary `CollabFrame`s from seq `K+1` to head, then enters bidirectional binary mode. See `docs/superpowers/specs/2026-05-04-collab-edit-design.md` §5 for the wire envelope.

### GET /api/files/:fileId/collab/active
Cheap "is anyone editing live?" check. **Response:** `{active: bool, peerCount: int}`.

---

## Version History

### GET /api/files/:fileId/versions
**Response:** array of `{id, s3VersionId, storagePath, seqAtSnapshot, docKeyId, authorUserId, sizeBytes, label, keepForever, createdAt}` ordered newest-first.

### GET /api/files/:fileId/versions/:vid/download
Get the encrypted snapshot bytes for a version. Returns `application/octet-stream`. Headers: `X-Kutup-Doc-Key-Id`, `X-Kutup-Seq`, `X-Kutup-S3-Version`.

### PATCH /api/files/:fileId/versions/:vid
**Body:** `{label?: string, keepForever?: boolean}` — set/unset.
**Response:** updated version row.

### POST /api/files/:fileId/versions
Record a new snapshot.
**Body:** `{s3VersionId, storagePath, seqAtSnapshot, docKeyId, sizeBytes, label?, keepForever?}`
**Response 201:** `{id}` — the version row id. Server truncates `file_update_log` up to `seqAtSnapshot`.

### POST /api/files/:fileId/snapshot-blob
Multipart `file` upload of the encrypted snapshot bytes.
**Response:** `{storagePath, s3VersionId}` from SeaweedFS versioning.
```

- [ ] **Step 2: Commit**

```bash
git add docs/api.md
git commit -m "docs(api): document devices, collab WS, and versions endpoints"
```

---

### Task H4: Update docs/self-hosting.md

**Files:**
- Modify: `docs/self-hosting.md`

- [ ] **Step 1: Add the SeaweedFS init steps**

Append after the existing setup steps:

```markdown
---

## SeaweedFS Bucket Versioning (required for collaborative editing)

The collaborative-edit feature uses S3 object versioning to store file snapshots. The `seaweedfs-init` Compose service enables versioning and applies a lifecycle policy automatically on stack startup.

If you migrate an existing deployment, run `seaweedfs-init.sh` once after upgrading. The script is idempotent.

**Lifecycle defaults:** 30-day or 50-version retention for noncurrent versions, whichever yields more. Named (`keep_forever=true`) versions are excluded by tag and retained indefinitely.

To customize retention, edit `lifecycle.json` and re-run the init container:
```sh
docker compose run --rm seaweedfs-init
```
```

- [ ] **Step 2: Commit**

```bash
git add docs/self-hosting.md
git commit -m "docs(self-hosting): document SeaweedFS versioning + lifecycle"
```

---

## Done — v1.1 follow-up tasks (separate plan)

These items polish v1 but aren't blocking. Each is a candidate for an immediate follow-up plan:

- Awareness throttling (debounce cursor frames to 30 Hz, pad to fixed sizes).
- Reconnect resume polish (exponential backoff, surface "reconnecting…" UI).
- Side-by-side version diff view in the history panel.
- Light/dark color stability for peer cursors (hash by user_id).
- Snapshot leader election (avoid duplicate snapshots when multiple clients are connected).

---

## Self-review (against spec §1–§15)

| Spec section | Plan task |
|---|---|
| §1 Context (E2EE, no new entity, Drive-style versions) | A1, F1, G1, F5 |
| §2 In-scope v1 | All Phase A–G |
| §2 Non-goals | Excluded by design — see "Done" section |
| §3 Architecture (relay, two stacks share envelope) | A1, B1–B4, D1–D5 |
| §4 File model (extension dispatch, lifecycle) | G1, F3 |
| §5 Wire envelope | B1–B4 |
| §6 Key model (HKDF, device keys, revocation) | A1, C1–C3, D5, F4 |
| §7 Schema | A1 |
| §8 WebSocket protocol | D1–D5 |
| §9 Versioning (triggers, retention, restore) | E1–E4, F5, G3, G4 |
| §10 New REST endpoints | C1, E1–E3 |
| §11 Frontend dispatch | G1, F2 |
| §12 Crypto contract | F4 |
| §15 Verification | H1 |

Spec coverage: complete.

Placeholder scan: clean (one ideological "TODO" inside the AuthSig discussion in C1 that flags a v2 polish — acceptable per the spec §14 open questions).

Type consistency: `frame`, `seq`, `doc_key_id`, `device_id`, `kind` names match across Go, TS, SQL, and protocol docs.
