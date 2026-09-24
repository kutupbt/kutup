// Client-side snapshot trigger.
//
// Snapshots are produced when ANY of:
//   1. 30s of editor idleness has passed AND >= 1 update has accumulated.
//   2. >= 200 updates have accumulated since the last snapshot (hard ceiling).
//   3. forceSave() is called (explicit "Save version" button).
//
// On snapshot:
//   1. Encode current Yjs state via Y.encodeStateAsUpdateV2.
//   2. Call encryptSnapshot() (provided by caller — the V1 browser uses the
//      same typed, context-bound Drive file-blob format as other snapshots).
//   3. POST it to /api/files/:fileId/versions (one request: stored, charged
//      by its measured size, recorded, update log truncated to the seq).
//   A named version of unchanged content labels the latest version instead.
//
// See docs/superpowers/specs/2026-05-04-collab-edit-design.md §9.

import * as Y from 'yjs'
import { createVersion, listVersions, patchVersion } from './api'
import { QuotaExceededError } from '@kutup/session/errors'

const IDLE_MS = 30_000
const HARD_CEILING = 200

export interface SnapshotEncryptResult {
  /** Complete typed encrypted blob to persist. */
  ciphertext: Uint8Array
  /** Carried into the version-record API call. */
  storageHints: { docKeyId: number; sizeBytes: number }
}

export interface SnapshotOpts {
  fileId: string
  ydoc: Y.Doc
  /** Encrypt and frame the encoded state as a complete persistent blob. */
  encryptSnapshot: (bytes: Uint8Array) => Promise<SnapshotEncryptResult>
  /** Latest known per-device sequence number at snapshot time — drives log truncation server-side. */
  getSeq: () => number
  /** Optional: invoked when a snapshot fails. The caller decides whether
   *  to surface a toast. QuotaExceededError additionally disarms the
   *  trigger (see disarmed flag). */
  onError?: (err: unknown) => void
  /** After a version is recorded: its id, and whether someone asked for it
   *  (Save / Save version) rather than autosave. Drive redraws the
   *  thumbnail from here. */
  onSnapshot?: (versionId: string, explicit: boolean) => void
}

export class SnapshotTrigger {
  private updatesSince = 0
  private idleTimer: ReturnType<typeof setTimeout> | null = null
  private inflight = false
  // Set once a 413 fires. Subsequent updates won't schedule autosave;
  // only destroy() (page reload / navigation) clears it. Prevents the
  // "toast every IDLE_MS" UX a quota-exceeded user would otherwise hit.
  private disarmed = false
  /** The newest version this tab knows of (named in place when unchanged). */
  private latestVersionId: string | null = null

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
    return this.snapshot(label, keepForever, true)
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

  private async snapshot(label?: string, keepForever = false, explicit = false): Promise<void> {
    if (this.inflight) return
    if (this.disarmed && !label) return // explicit forceSave can still try; autosave can't.
    if (this.updatesSince === 0 && !label) return  // nothing to do (unless explicit label)
    this.inflight = true
    try {
      // Naming unchanged content names the version that already holds it
      // (a pointer, as CryptPad's snapshots are) rather than storing a copy.
      if (this.updatesSince === 0 && label) {
        const latest = this.latestVersionId ?? (await listVersions(this.opts.fileId))[0]?.id
        if (latest) {
          await patchVersion(this.opts.fileId, latest, { label, keepForever })
          this.opts.onSnapshot?.(latest, explicit)
          return
        }
      }
      const stateUpdate = Y.encodeStateAsUpdateV2(this.opts.ydoc)
      const { ciphertext, storageHints } = await this.opts.encryptSnapshot(stateUpdate)

      // One request: the server stores it, charges its measured size,
      // records the row and truncates the update log. createVersion turns a
      // 413 into QuotaExceededError so the catch below can disarm autosave.
      const recorded = await createVersion(this.opts.fileId, ciphertext, {
        kind: 'yjs',
        seqAtSnapshot: this.opts.getSeq(),
        docKeyId: storageHints.docKeyId,
        label: label ?? null,
        keepForever,
      })
      this.latestVersionId = recorded.id

      this.updatesSince = 0
      this.opts.onSnapshot?.(recorded.id, explicit)
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
