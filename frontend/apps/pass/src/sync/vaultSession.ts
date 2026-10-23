// One open vault and how its edits reach Drive (docs/plans/pass.md, K2c).
//
// Every edit is applied in the worker at once and kept in the outbox; then
// the vault is saved as a new version made from the version it started from
// (`basedOn`). If another device saved first, the two are merged here
// (base, ours, theirs; the same Rust merge `kutup sync` uses) and saved on
// top of theirs. Without a connection the edits wait in the outbox and go
// when it comes back, also after the tab was closed.

import { isAxiosError } from 'axios'
import { VersionConflictError, listVersions } from '@kutup/collab/api'
import type { DriveFile, Folder } from '@kutup/drive-core/model'
import { QuotaExceededError } from '@kutup/session/errors'
import { ORIGINAL, readCurrentVault, readVaultVersion, refreshVaultFile, saveVaultVersion, vaultTitle } from '../drive/vaults'
import { VaultError, VaultHandle, type KeyChange, type KeyChanged } from '../vault/client'
import type { Applied, MergeReport, Op, VaultKeyInput, VaultView } from '../vault/types'
import { outbox } from './outbox'

export type SyncStatus =
  /** Everything is in Drive. */
  | 'saved'
  | 'saving'
  /** Kutup cannot be reached: edits are kept on this device. */
  | 'offline'
  /** The vault was saved elsewhere under another key: it is needed to merge. */
  | 'needsKey'
  /** Not saved: storage is full. */
  | 'quota'
  | 'error'

export interface SessionState {
  view: VaultView
  status: SyncStatus
  /** The last merge with another device's save that needs a look, if any. */
  merge: MergeReport | null
  /** When this vault came from the outbox because Drive could not be reached. */
  fromOutbox: boolean
}

const RETRY_MS = 30_000
/** Edits close together are saved once (each save derives the vault key). */
const SAVE_DELAY_MS = 600

function isOffline(error: unknown): boolean {
  return (isAxiosError(error) && !error.response) || (typeof navigator !== 'undefined' && navigator.onLine === false)
}

/** Why a key change was not made (nothing changed). */
export type KeyChangeFailure =
  /** Edits or another device's save are still on their way: save first. */
  | 'notReady'
  /** Another device saved meanwhile: its save is merged in, try again. */
  | 'conflict'
  /** Kutup didn't answer: the vault keeps the new key and saves under it when it does. */
  | 'pending'
  | 'failed'

export class KeyChangeError extends Error {
  constructor(readonly failure: KeyChangeFailure) {
    super(`the vault key was not changed: ${failure}`)
  }
}

function needsReview(report: MergeReport): boolean {
  return report.conflicts.length > 0 || report.groupConflicts.length > 0 || report.metadataConflicts.length > 0 || report.restored.length > 0
}

export class VaultSession {
  private listeners = new Set<() => void>()
  private state: SessionState
  private saveTimer: ReturnType<typeof setTimeout> | null = null
  private retryTimer: ReturnType<typeof setTimeout> | null = null
  private saving: Promise<void> | null = null
  private dirty = false
  private closed = false
  /**
   * What follows a key change whose save got no answer (keeping the new key
   * in the account, or forgetting the old one): run once the save loop has
   * the vault in Drive under the new key.
   */
  private afterKeyChange: (() => Promise<void>) | null = null
  /**
   * A key change whose save got no answer: done once Drive is known to hold
   * the vault under the new key (a save of ours lands, or the newest version
   * opens with it). No other key change starts meanwhile.
   */
  private keyChangePending = false
  /** The other device's version while its key is needed. */
  private waitingTheirs: { contents: Uint8Array; version: string } | null = null
  private readonly onOnline = () => this.scheduleSave(0)

  private constructor(
    private readonly handle: VaultHandle,
    readonly folder: Folder,
    private file: DriveFile,
    private readonly userId: string,
    readonly canEdit: boolean,
    private baseVersion: string,
    private base: Uint8Array,
    view: VaultView,
    fromOutbox: boolean,
  ) {
    this.state = { view, status: 'saved', merge: null, fromOutbox }
    window.addEventListener('online', this.onOnline)
  }

  /**
   * Opens a vault with `key`: what Drive holds, merged with edits this
   * device kept and had not saved; only the kept copy when Drive cannot be
   * reached. A wrong key throws {@link VaultError}.
   */
  static async open(folder: Folder, file: DriveFile, key: VaultKeyInput, userId: string, canEdit: boolean): Promise<VaultSession> {
    const kept = await outbox.get(userId, file.id)
    let current: { contents: Uint8Array; version: string } | null = null
    try {
      current = await readCurrentVault(file)
    } catch (error) {
      if (!kept || !isOffline(error)) throw error
    }
    if (!current) {
      // Offline: the kept copy, edits and all.
      const record = kept!
      const handle = await VaultHandle.open(record.pending ?? record.base, key)
      const session = new VaultSession(handle, folder, file, userId, canEdit, record.baseVersion, record.base, await handle.view(), true)
      session.dirty = Boolean(record.pending)
      session.set({ status: record.pending ? 'offline' : 'saved' })
      if (record.pending) session.scheduleRetry()
      return session
    }
    if (kept?.pending) {
      const handle = await VaultHandle.open(kept.pending, key)
      const session = new VaultSession(handle, folder, file, userId, canEdit, kept.baseVersion, kept.base, await handle.view(), false)
      session.dirty = true
      if (current.version !== kept.baseVersion) await session.mergeTheirs(current.contents, current.version)
      session.scheduleSave(0)
      return session
    }
    const handle = await VaultHandle.open(current.contents, key)
    await outbox.put(userId, { fileId: file.id, baseVersion: current.version, base: current.contents, pending: null, savedAt: Date.now() })
    return new VaultSession(handle, folder, file, userId, canEdit, current.version, current.contents, await handle.view(), false)
  }

  get fileId(): string {
    return this.file.id
  }

  getState(): SessionState {
    return this.state
  }

  subscribe(listener: () => void): () => void {
    this.listeners.add(listener)
    return () => this.listeners.delete(listener)
  }

  private set(patch: Partial<SessionState>) {
    this.state = { ...this.state, ...patch }
    for (const listener of this.listeners) listener()
  }

  /** The vault's handle in the worker, for reads (history, attachments, codes). */
  vault(): VaultHandle {
    return this.handle
  }

  /** Applies one edit and saves it soon. */
  async apply(op: Op): Promise<Applied> {
    if (!this.canEdit) throw new VaultError('this vault is read-only for you')
    const applied = await this.handle.apply(op)
    if (applied.changed) {
      // The edit is saved whatever follows.
      this.dirty = true
      this.scheduleSave(SAVE_DELAY_MS)
      // A rename made while locked, or in Drive, reaches the name inside the
      // KeePass file with the next edit (KeePassXC shows that one); best
      // effort, never in the way of the edit itself.
      const title = vaultTitle(this.file.name)
      if (op.op !== 'updateVault' && title) {
        try {
          const view = await this.handle.view()
          if (view.name !== title) {
            await this.handle.apply({ op: 'updateVault', name: title, description: view.description, defaultUserName: view.defaultUserName })
          }
        } catch {
          // Tried again with the next edit.
        }
      }
      this.set({ view: await this.handle.view(), status: this.state.status === 'saved' ? 'saving' : this.state.status })
    }
    return applied
  }

  /**
   * Changes the vault's key and saves the vault with it, straight to Drive
   * (never the outbox: a change not in Drive is undone, so the vault never
   * ends up under a key nobody confirmed). Only from a saved vault, holding
   * the save slot meanwhile; edits made during it are saved after, under
   * the new key. On any failure the old key is back and nothing changed.
   */
  async changeKey(change: KeyChange, whenSaved?: (changed: KeyChanged) => Promise<void>): Promise<KeyChanged> {
    if (!this.canEdit) throw new VaultError('this vault is read-only for you')
    if (this.saving || this.dirty || this.waitingTheirs || this.keyChangePending || this.state.status !== 'saved') {
      throw new KeyChangeError('notReady')
    }
    let release!: () => void
    this.saving = new Promise<void>((resolve) => (release = resolve))
    let conflict = false
    try {
      const changed = await this.handle.changeKey(change)
      let contents: Uint8Array
      try {
        contents = await this.handle.save()
      } catch {
        await this.handle.abandonKeyChange()
        throw new KeyChangeError('failed')
      }
      let saved: { version: string; file: DriveFile }
      try {
        saved = await this.push(contents)
      } catch (error) {
        if (error instanceof VersionConflictError) {
          await this.handle.abandonKeyChange()
          conflict = true
          throw new KeyChangeError('conflict')
        }
        if (isAxiosError(error) && error.response) {
          // Answered and refused: nothing was stored.
          await this.handle.abandonKeyChange()
          throw new KeyChangeError('failed')
        }
        // No answer: Drive may hold the new version already. The new key
        // stays, and the vault is saved under it once Kutup answers: a save
        // that did land is then the newest version, which opens with this
        // key and is merged; one that didn't is made now. Either way the
        // vault ends up under the new key, never under one nobody holds.
        this.dirty = true
        this.keyChangePending = true
        this.afterKeyChange = whenSaved ? () => whenSaved(changed) : null
        this.set({ status: 'offline' })
        this.scheduleRetry()
        throw new KeyChangeError('pending')
      }
      this.file = saved.file
      this.baseVersion = saved.version
      this.base = contents
      await this.handle.keyChangeSaved()
      // Drive holds it: the outbox's base follows, so a later offline edit
      // merges against the vault under its new key.
      await outbox
        .put(this.userId, { fileId: this.file.id, baseVersion: this.baseVersion, base: this.base, pending: null, savedAt: Date.now() })
        .catch(() => undefined)
      this.set({ view: await this.handle.view() })
      return changed
    } finally {
      release()
      this.saving = null
      if (this.dirty) this.scheduleSave(0)
      // Another device's save: taken in now, under the key it has.
      if (conflict) void this.refresh()
    }
  }

  /**
   * Drive holds the vault under the key this session has: a pending key
   * change is done, and what was to follow it (the account's kept key, the
   * earlier versions) follows now. Nothing when none is pending.
   */
  private async keyChangeLanded(): Promise<void> {
    await this.handle.keyChangeSaved()
    if (!this.keyChangePending) return
    this.keyChangePending = false
    const after = this.afterKeyChange
    this.afterKeyChange = null
    if (after) void after().catch(() => undefined)
  }

  /** The merge notice was read. */
  dismissMerge() {
    this.set({ merge: null })
  }

  private scheduleSave(delay: number) {
    if (this.closed || !this.dirty) return
    if (this.saveTimer) clearTimeout(this.saveTimer)
    this.saveTimer = setTimeout(() => {
      this.saveTimer = null
      void this.save()
    }, delay)
  }

  private scheduleRetry() {
    if (this.retryTimer || this.closed) return
    this.retryTimer = setTimeout(() => {
      this.retryTimer = null
      this.scheduleSave(0)
    }, RETRY_MS)
  }

  /** Saves until Drive holds every edit, merging with other devices' saves. */
  save(): Promise<void> {
    if (!this.saving) {
      this.saving = this.saveLoop().finally(() => {
        this.saving = null
        if (this.dirty && this.state.status === 'saving') this.scheduleSave(0)
      })
    }
    return this.saving
  }

  private async saveLoop(): Promise<void> {
    while (this.dirty && !this.closed) {
      this.dirty = false
      this.set({ status: 'saving' })
      const contents = await this.handle.save()
      await outbox.put(this.userId, { fileId: this.file.id, baseVersion: this.baseVersion, base: this.base, pending: contents, savedAt: Date.now() })
      try {
        const saved = await this.push(contents)
        this.file = saved.file
        this.baseVersion = saved.version
        this.base = contents
        // A key change whose first save got no answer is done now.
        await this.keyChangeLanded()
        // Edits made while saving stay pending in the outbox.
        if (!this.dirty) {
          await outbox.put(this.userId, { fileId: this.file.id, baseVersion: this.baseVersion, base: this.base, pending: null, savedAt: Date.now() })
        }
      } catch (error) {
        this.dirty = true
        if (error instanceof VersionConflictError) {
          const theirs = await readVaultVersion(this.file, error.current)
          if (!(await this.mergeTheirs(theirs, error.current))) return
          continue
        }
        if (error instanceof QuotaExceededError) {
          this.set({ status: 'quota' })
          return
        }
        if (isOffline(error)) {
          this.set({ status: 'offline' })
          this.scheduleRetry()
          return
        }
        this.set({ status: 'error' })
        throw error
      }
    }
    if (!this.closed && !this.dirty) this.set({ status: 'saved', fromOutbox: false })
  }

  private async push(contents: Uint8Array): Promise<{ version: string; file: DriveFile }> {
    try {
      return await saveVaultVersion(this.folder, this.file, contents, this.baseVersion)
    } catch (error) {
      // Re-keyed by someone else since it was listed: list it again, once.
      if (isAxiosError(error) && error.response?.status === 409 && !(error instanceof VersionConflictError)) {
        this.file = await refreshVaultFile(this.folder, this.file)
        return saveVaultVersion(this.folder, this.file, contents, this.baseVersion)
      }
      throw error
    }
  }

  /**
   * Merges another device's version into this one. False when its key is
   * needed first (the status says so).
   */
  private async mergeTheirs(contents: Uint8Array, version: string, theirsKey?: VaultKeyInput): Promise<boolean> {
    let outcome
    try {
      outcome = await this.handle.merge(this.base, contents, theirsKey)
    } catch (error) {
      if (error instanceof VaultError && !theirsKey) {
        this.waitingTheirs = { contents, version }
        this.set({ status: 'needsKey' })
        return false
      }
      throw error
    }
    this.base = contents
    this.baseVersion = version
    this.dirty = outcome.differsFromTheirs
    // The newest version opens with our key: a key change whose save got no
    // answer did land (there is nothing left to push for it).
    if (outcome.theirsUnderCurrentKey) await this.keyChangeLanded()
    await outbox.put(this.userId, {
      fileId: this.file.id,
      baseVersion: version,
      base: contents,
      pending: this.dirty ? await this.handle.save() : null,
      savedAt: Date.now(),
    })
    this.set({ view: await this.handle.view(), merge: needsReview(outcome.report) ? outcome.report : this.state.merge })
    return true
  }

  /** The key another device saved the vault under; then the merge goes on. */
  async provideTheirsKey(key: VaultKeyInput): Promise<void> {
    const waiting = this.waitingTheirs
    if (!waiting) return
    await this.mergeTheirs(waiting.contents, waiting.version, key)
    this.waitingTheirs = null
    this.dirty = true
    this.scheduleSave(0)
  }

  /** Looks for a version another device saved, and takes it in. */
  async refresh(): Promise<void> {
    if (this.closed || this.saving || this.dirty || this.waitingTheirs) return
    try {
      const newest = (await listVersions(this.file.id)).find((v) => v.kind === 'file')
      const version = newest?.id ?? ORIGINAL
      if (version === this.baseVersion) return
      const contents = await readVaultVersion(this.file, version)
      if (await this.mergeTheirs(contents, version)) this.scheduleSave(0)
    } catch (error) {
      if (isOffline(error)) this.set({ status: 'offline' })
    }
  }

  async close(): Promise<void> {
    this.closed = true
    if (this.saveTimer) clearTimeout(this.saveTimer)
    if (this.retryTimer) clearTimeout(this.retryTimer)
    window.removeEventListener('online', this.onOnline)
    await this.handle.close()
  }
}
