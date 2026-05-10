// Client-side snapshot trigger.
//
// Snapshots are produced when ANY of:
//   1. 30s of editor idleness has passed AND >= 1 update has accumulated.
//   2. >= 200 updates have accumulated since the last snapshot (hard ceiling).
//   3. forceSave() is called (explicit "Save version" button).
//
// On snapshot:
//   1. Encode current Yjs state via Y.encodeStateAsUpdateV2.
//   2. Call encryptSnapshot() (provided by caller — wraps the bytes in AEAD with
//      the per-file content key and prepends the nonce).
//   3. PUT the encrypted bytes to /api/files/:fileId/snapshot-blob, get a
//      {storagePath, s3VersionId} back.
//   4. POST /api/files/:fileId/versions with the snapshot metadata + caller's
//      current seqAtSnapshot. Server records the row and truncates the log.
//
// See docs/superpowers/specs/2026-05-04-collab-edit-design.md §9.

import * as Y from 'yjs'
import api from '../api/client'
import { recordSnapshot } from '../api/collab'
import { QuotaExceededError } from '../api/errors'

const IDLE_MS = 30_000
const HARD_CEILING = 200

export interface SnapshotEncryptResult {
  /** Bytes to PUT to S3. Caller is responsible for prepending the nonce / framing. */
  ciphertext: Uint8Array
  /** Carried into the version-record API call. */
  storageHints: { docKeyId: number; sizeBytes: number }
}

export interface SnapshotOpts {
  fileId: string
  ydoc: Y.Doc
  /** Encrypt the encoded state. The caller decides framing (nonce prefix, etc.). */
  encryptSnapshot: (bytes: Uint8Array) => Promise<SnapshotEncryptResult>
  /** Latest known per-device sequence number at snapshot time — drives log truncation server-side. */
  getSeq: () => number
  /** Optional: invoked when a snapshot fails. The caller decides whether
   *  to surface a toast. QuotaExceededError additionally disarms the
   *  trigger (see disarmed flag). */
  onError?: (err: unknown) => void
}

export class SnapshotTrigger {
  private updatesSince = 0
  private idleTimer: ReturnType<typeof setTimeout> | null = null
  private inflight = false
  // Set once a 413 fires. Subsequent updates won't schedule autosave;
  // only destroy() (page reload / navigation) clears it. Prevents the
  // "toast every IDLE_MS" UX a quota-exceeded user would otherwise hit.
  private disarmed = false

  constructor(private readonly opts: SnapshotOpts) {
    opts.ydoc.on('update', this.onUpdate)
  }

  /** Tear down listeners. Call from the editor's cleanup. */
  destroy(): void {
    this.opts.ydoc.off('update', this.onUpdate)
    if (this.idleTimer != null) {
      clearTimeout(this.idleTimer)
      this.idleTimer = null
    }
  }

  /** User-initiated "Save version" button. Always snapshots. */
  forceSave(label?: string, keepForever = false): Promise<void> {
    return this.snapshot(label, keepForever)
  }

  private onUpdate = () => {
    if (this.disarmed) return
    this.updatesSince++
    if (this.idleTimer != null) clearTimeout(this.idleTimer)
    this.idleTimer = setTimeout(() => this.snapshot(), IDLE_MS)
    if (this.updatesSince >= HARD_CEILING) {
      this.snapshot()
    }
  }

  private async snapshot(label?: string, keepForever = false): Promise<void> {
    if (this.inflight) return
    if (this.disarmed && !label) return // explicit forceSave can still try; autosave can't.
    if (this.updatesSince === 0 && !label) return  // nothing to do (unless explicit label)
    this.inflight = true
    try {
      const stateUpdate = Y.encodeStateAsUpdateV2(this.opts.ydoc)
      const { ciphertext, storageHints } = await this.opts.encryptSnapshot(stateUpdate)

      // 1. Upload encrypted snapshot blob to S3.
      const fd = new FormData()
      fd.append('file', new Blob([ciphertext.buffer as ArrayBuffer], { type: 'application/octet-stream' }))
      const upRes = await api.post(`/files/${this.opts.fileId}/snapshot-blob`, fd)
      const { storagePath, s3VersionId } = upRes.data as { storagePath: string; s3VersionId: string }

      // 2. Announce snapshot — server records file_versions row + truncates log.
      // recordSnapshot converts axios 413 → QuotaExceededError so the catch
      // below can disarm autosave + surface a localized toast.
      await recordSnapshot(this.opts.fileId, {
        s3VersionId,
        storagePath,
        seqAtSnapshot: this.opts.getSeq(),
        docKeyId: storageHints.docKeyId,
        sizeBytes: storageHints.sizeBytes,
        label: label ?? null,
        keepForever,
      })

      this.updatesSince = 0
    } catch (err) {
      if (err instanceof QuotaExceededError) {
        this.disarmed = true
      }
      this.opts.onError?.(err)
      // Don't re-throw on QuotaExceededError — the caller has been notified
      // via onError and we don't want to fire an unhandled rejection from
      // the unawaited setTimeout in onUpdate. Other errors propagate so
      // explicit forceSave callers can react.
      if (!(err instanceof QuotaExceededError)) {
        throw err
      }
    } finally {
      this.inflight = false
    }
  }
}
