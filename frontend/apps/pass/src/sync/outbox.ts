import { storageReady } from '@kutup/crypto/storageGate'
// What keeps a vault's edits when Kutup cannot be reached
// (docs/plans/pass.md, "Offline"). Per vault, in this browser's IndexedDB:
// the version the edits are made on (its id and contents) and the edited
// vault waiting to be saved. Both are KeePass files, encrypted under the
// vault's own key, so the record holds no readable secret
// (docs/research/16-browser-storage-architecture.md). One database per
// account; nothing names a vault but its Drive file id.

export interface OutboxRecord {
  fileId: string
  /** The version the edits start from: an id, or `original`. */
  baseVersion: string
  /** That version's contents (KDBX). */
  base: Uint8Array
  /** The edited vault not yet saved to Drive (KDBX), if any. */
  pending: Uint8Array | null
  savedAt: number
}

const STORE = 'vaults'

const databaseName = (accountId: string) => `kutup.pass.outbox:${accountId}`

async function open(accountId: string): Promise<IDBDatabase> {
  await storageReady()
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(databaseName(accountId), 1)
    request.onupgradeneeded = () => {
      request.result.createObjectStore(STORE, { keyPath: 'fileId' })
    }
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error ?? new Error('IndexedDB is not available'))
  })
}

async function run<T>(accountId: string, mode: IDBTransactionMode, work: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  const db = await open(accountId)
  try {
    return await new Promise<T>((resolve, reject) => {
      const tx = db.transaction(STORE, mode)
      const request = work(tx.objectStore(STORE))
      tx.oncomplete = () => resolve(request.result)
      tx.onerror = () => reject(tx.error ?? new Error('IndexedDB transaction failed'))
      tx.onabort = () => reject(tx.error ?? new Error('IndexedDB transaction aborted'))
    })
  } finally {
    db.close()
  }
}

export const outbox = {
  async get(accountId: string, fileId: string): Promise<OutboxRecord | null> {
    try {
      return ((await run(accountId, 'readonly', (store) => store.get(fileId))) as OutboxRecord | undefined) ?? null
    } catch {
      // A private window without IndexedDB: nothing was kept.
      return null
    }
  },
  async put(accountId: string, record: OutboxRecord): Promise<void> {
    await run(accountId, 'readwrite', (store) => store.put(record))
  },
  async delete(accountId: string, fileId: string): Promise<void> {
    try {
      await run(accountId, 'readwrite', (store) => store.delete(fileId))
    } catch {
      // Nothing to forget.
    }
  },
  /** Forgets every vault kept for the account here (on sign-out). */
  async clear(accountId: string): Promise<void> {
    await new Promise<void>((resolve) => {
      const request = indexedDB.deleteDatabase(databaseName(accountId))
      request.onsuccess = () => resolve()
      request.onerror = () => resolve()
      request.onblocked = () => resolve()
    })
  },
  /** The vaults with edits waiting to be saved. */
  async pendingIds(accountId: string): Promise<string[]> {
    try {
      const all = (await run(accountId, 'readonly', (store) => store.getAll())) as OutboxRecord[]
      return all.filter((r) => r.pending).map((r) => r.fileId)
    } catch {
      return []
    }
  },
}
