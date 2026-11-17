/**
 * The account-records store (docs/plans/account-records.md, W3): a device's
 * copy of one scope and the batches made on it. The same rules as
 * `kutup_crypto::account_records`, whose registry this mirrors. Reading and
 * writing go through `AccountHead.records` and `AccountHead.recordsWrite`,
 * which verify every page's head and check the index once caught up.
 */

import { toBase64Url } from '@kutup/crypto/base64'
import { randomBytes } from '@kutup/crypto/random'
import { storageReady } from '@kutup/crypto/storageGate'

/** The scopes of the store (`RecordScope` in kutup-crypto). */
export type RecordScopeName =
  | 'passSecrets'
  | 'pins'
  | 'chatGroups'
  | 'chatContacts'
  | 'photosLibrary'
  | 'chatAttachments'
  | 'contactGroups'
  | 'calendarSettings'
  | 'joinedMeetings'

/**
 * A new record id for a scope whose ids are random (`IdForm::Random`: the
 * Photos library, the attachment ledger, a joined meeting): 32 random bytes,
 * unpadded base64url.
 */
export function randomRecordId(): string {
  return toBase64Url(randomBytes(32))
}

/** One record as a device keeps it. */
export interface StoredRecord {
  revision: number
  /** The sealed record, canonical base64. */
  envelope: string
}

/** One page, as `GET /api/account/records/{scope}` answers. */
export interface RecordsPage {
  records: { id: string; revision: number; envelope: string; seq: number }[]
  deleted: { id: string; seq: number }[]
  next: number
  more: boolean
  resync: boolean
  head: string | null
  basis: string | null
}

/** What a records batch changes, and what the write returns once stored. */
export interface RecordsEdit<T> {
  /** New or changed records, each at the revision its envelope was sealed at. */
  puts: readonly { id: string; revision: number; envelope: string }[]
  deletes: readonly string[]
  done: T
}

/** A batch's items, each on the copy's revision. */
export interface RecordsBatch {
  scope: RecordScopeName
  puts: { id: string; baseRevision: number; revision: number; envelope: string }[]
  deletes: { id: string; baseRevision: number }[]
}

/** A device's copy of one scope: its records and how far it has read. */
export class ScopeRecords {
  /** The `next` of the last page merged; 0 before the first. */
  cursor = 0
  readonly records = new Map<string, StoredRecord>()

  constructor(readonly scope: RecordScopeName) {}

  /**
   * Merges a page read from `cursor`: 'more' (read on), 'done' (check the
   * index against the page's head before using the copy) or 'resync' (the
   * copy was emptied; read from 0). Refuses changes out of counter order.
   */
  merge(page: RecordsPage): 'more' | 'done' | 'resync' {
    if (page.resync) {
      this.records.clear()
      this.cursor = 0
      return 'resync'
    }
    const changes = [
      ...page.records.map((record) => ({ seq: record.seq, id: record.id, record })),
      ...page.deleted.map((gone) => ({ seq: gone.seq, id: gone.id, record: null })),
    ].sort((a, b) => a.seq - b.seq)
    let last = this.cursor
    for (const change of changes) {
      if (!Number.isSafeInteger(change.seq) || change.seq <= last) throw new Error(`${this.scope}: records page out of order`)
      last = change.seq
      if (change.record) {
        if (!(change.record.revision >= 1)) throw new Error(`${this.scope}: a record at revision 0`)
        this.records.set(change.id, { revision: change.record.revision, envelope: change.record.envelope })
      } else {
        this.records.delete(change.id)
      }
    }
    if (!Number.isSafeInteger(page.next) || page.next < last) throw new Error(`${this.scope}: the records cursor goes back`)
    this.cursor = page.next
    return page.more ? 'more' : 'done'
  }

  /** `(id, revision)` sorted by id: what the head's index names. */
  index(): [string, number][] {
    return [...this.records].map(([id, record]): [string, number] => [id, record.revision]).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
  }

  /** A batch on this copy; each base revision is the copy's (0: new). */
  plan(edit: Pick<RecordsEdit<unknown>, 'puts' | 'deletes'>): RecordsBatch {
    const named = new Set<string>()
    const once = (id: string) => {
      if (named.has(id)) throw new Error(`${this.scope}: a record is named twice`)
      named.add(id)
    }
    const puts = edit.puts.map(({ id, revision, envelope }) => {
      once(id)
      const baseRevision = this.records.get(id)?.revision ?? 0
      if (revision <= baseRevision) throw new Error(`${this.scope}: a put's revision must be above the record's`)
      return { id, baseRevision, revision, envelope }
    })
    const deletes = edit.deletes.map((id) => {
      once(id)
      const stored = this.records.get(id)
      if (!stored) throw new Error(`${this.scope}: a delete names no record`)
      return { id, baseRevision: stored.revision }
    })
    return { scope: this.scope, puts, deletes }
  }

  /** The index once `batch` lands: what the next head names. */
  indexAfter(batch: RecordsBatch): [string, number][] {
    const next = new ScopeRecords(this.scope)
    for (const [id, record] of this.records) next.records.set(id, record)
    for (const put of batch.puts) next.records.set(put.id, { revision: put.revision, envelope: put.envelope })
    for (const gone of batch.deletes) next.records.delete(gone.id)
    return next.index()
  }
}

/** The `POST /api/account/records` body. */
export function batchBody(batch: RecordsBatch, head: string): unknown {
  return {
    head,
    puts: batch.puts.map(({ id, baseRevision, envelope }) => ({ scope: batch.scope, id, baseRevision, envelope })),
    deletes: batch.deletes.map(({ id, baseRevision }) => ({ scope: batch.scope, id, baseRevision })),
  }
}

/**
 * Where a device keeps its copies between page loads: one row per record,
 * keyed by the copy's name and the record id, and each copy's cursor. The
 * envelopes are already sealed account records (each bound to its account,
 * its id and its revision), so the rows are kept as they came; nothing here
 * is trusted until the whole scope matches the verified head again.
 */
export interface RecordsStore {
  load(copy: string): Promise<{ cursor: number; records: [string, StoredRecord][] } | null>
  /** Writes what changed since the copy was loaded (`reset`: drop every row first). */
  save(copy: string, cursor: number, changes: { puts: [string, StoredRecord][]; deletes: string[]; reset: boolean }): Promise<void>
  clear(): Promise<void>
}

export function memoryRecordsStore(): RecordsStore {
  const copies = new Map<string, { cursor: number; records: Map<string, StoredRecord> }>()
  return {
    load: (copy) => {
      const kept = copies.get(copy)
      return Promise.resolve(kept ? { cursor: kept.cursor, records: [...kept.records] } : null)
    },
    save: (copy, cursor, { puts, deletes, reset }) => {
      const kept = (!reset && copies.get(copy)?.records) || new Map<string, StoredRecord>()
      for (const [id, record] of puts) kept.set(id, record)
      for (const id of deletes) kept.delete(id)
      copies.set(copy, { cursor, records: kept })
      return Promise.resolve()
    },
    clear: () => {
      copies.clear()
      return Promise.resolve()
    },
  }
}

const DB_NAME = 'kutup.account.records'
const RECORDS = 'records'
const CURSORS = 'cursors'

/**
 * The copies in this origin's IndexedDB, or in memory where it can't be
 * opened (a private window that refuses it): a copy that isn't kept is only
 * read again from the start.
 */
export function indexedDbRecordsStore(): RecordsStore {
  let opened: Promise<IDBDatabase | null> | null = null
  const db = () =>
    (opened ??= storageReady().then(() => new Promise<IDBDatabase | null>((resolve) => {
      try {
        const open = indexedDB.open(DB_NAME, 1)
        open.onupgradeneeded = () => {
          open.result.createObjectStore(RECORDS)
          open.result.createObjectStore(CURSORS)
        }
        open.onsuccess = () => resolve(open.result)
        open.onerror = () => resolve(null)
        open.onblocked = () => resolve(null)
      } catch {
        resolve(null)
      }
    })))
  const fallback = memoryRecordsStore()
  // Every record id of a copy: string ids sort below arrays.
  const rangeOf = (copy: string) => IDBKeyRange.bound([copy, ''], [copy, []])
  const done = (tx: IDBTransaction) =>
    new Promise<void>((resolve, reject) => {
      tx.oncomplete = () => resolve()
      tx.onerror = () => reject(tx.error ?? new Error('IndexedDB write failed'))
      tx.onabort = () => reject(tx.error ?? new Error('IndexedDB write aborted'))
    })
  const asked = <T>(request: IDBRequest<T>) =>
    new Promise<T>((resolve, reject) => {
      request.onsuccess = () => resolve(request.result)
      request.onerror = () => reject(request.error ?? new Error('IndexedDB read failed'))
    })
  return {
    async load(copy) {
      const handle = await db()
      if (!handle) return fallback.load(copy)
      try {
        const tx = handle.transaction([RECORDS, CURSORS], 'readonly')
        const cursor = await asked(tx.objectStore(CURSORS).get(copy) as IDBRequest<number | undefined>)
        if (typeof cursor !== 'number') return null
        const range = rangeOf(copy)
        const [keys, values] = await Promise.all([asked(tx.objectStore(RECORDS).getAllKeys(range)), asked(tx.objectStore(RECORDS).getAll(range) as IDBRequest<StoredRecord[]>)])
        const records = keys.map((key, i): [string, StoredRecord] => [String((key as unknown[])[1]), values[i]!])
        return { cursor, records }
      } catch {
        return null
      }
    },
    async save(copy, cursor, { puts, deletes, reset }) {
      const handle = await db()
      if (!handle) return fallback.save(copy, cursor, { puts, deletes, reset })
      try {
        const tx = handle.transaction([RECORDS, CURSORS], 'readwrite')
        const records = tx.objectStore(RECORDS)
        if (reset) records.delete(rangeOf(copy))
        for (const [id, record] of puts) records.put({ revision: record.revision, envelope: record.envelope }, [copy, id])
        for (const id of deletes) records.delete([copy, id])
        tx.objectStore(CURSORS).put(cursor, copy)
        await done(tx)
      } catch {
        // Not kept: the next page load reads this scope from the start.
      }
    },
    async clear() {
      const handle = await db()
      await fallback.clear()
      if (!handle) return
      try {
        const tx = handle.transaction([RECORDS, CURSORS], 'readwrite')
        tx.objectStore(RECORDS).clear()
        tx.objectStore(CURSORS).clear()
        await done(tx)
      } catch {
        // Nothing more to do: a copy left behind is checked before any use.
      }
    },
  }
}

/** What changed from `before` (null: nothing kept) to `after`. */
export function changesOf(before: ScopeRecords | null, after: ScopeRecords): { puts: [string, StoredRecord][]; deletes: string[]; reset: boolean } {
  if (!before) return { puts: [...after.records], deletes: [], reset: true }
  const puts: [string, StoredRecord][] = []
  for (const [id, record] of after.records) {
    const was = before.records.get(id)
    if (!was || was.revision !== record.revision || was.envelope !== record.envelope) puts.push([id, record])
  }
  const deletes = [...before.records.keys()].filter((id) => !after.records.has(id))
  return { puts, deletes, reset: false }
}

/** A copy that can change without changing `copy`. */
export function cloneRecords(copy: ScopeRecords): ScopeRecords {
  const clone = new ScopeRecords(copy.scope)
  clone.cursor = copy.cursor
  for (const [id, record] of copy.records) clone.records.set(id, record)
  return clone
}
