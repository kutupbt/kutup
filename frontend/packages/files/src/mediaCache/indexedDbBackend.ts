import type {
  CiphertextCacheBackendV1,
  CiphertextCacheChunkV1,
  CiphertextCacheEntryV1,
} from './types'

const DATABASE_NAME = 'kutup-private-ciphertext-cache-v1'
const DATABASE_VERSION = 1
const ENTRY_STORE = 'entries'
const CHUNK_STORE = 'chunks'

interface StoredChunkV1 {
  key: string
  cacheId: string
  index: number
  bytes: ArrayBuffer
}

export class IndexedDbCiphertextCacheBackendV1 implements CiphertextCacheBackendV1 {
  private databasePromise: Promise<IDBDatabase> | null = null

  async getByBindingKey(bindingKey: string): Promise<CiphertextCacheEntryV1 | null> {
    const database = await this.database()
    const transaction = database.transaction(ENTRY_STORE, 'readonly')
    const request = transaction.objectStore(ENTRY_STORE).index('bindingKey').get(bindingKey)
    const value = await requestResult<CiphertextCacheEntryV1 | undefined>(request)
    await transactionDone(transaction)
    return value ?? null
  }

  async putEntry(entry: CiphertextCacheEntryV1): Promise<void> {
    const database = await this.database()
    const transaction = database.transaction(ENTRY_STORE, 'readwrite')
    transaction.objectStore(ENTRY_STORE).put(entry)
    await transactionDone(transaction)
  }

  async putChunk(chunk: CiphertextCacheChunkV1): Promise<void> {
    const database = await this.database()
    const transaction = database.transaction(CHUNK_STORE, 'readwrite')
    const bytes = chunk.bytes.slice().buffer
    transaction.objectStore(CHUNK_STORE).put({
      key: chunkKey(chunk.cacheId, chunk.index),
      cacheId: chunk.cacheId,
      index: chunk.index,
      bytes,
    } satisfies StoredChunkV1)
    await transactionDone(transaction)
  }

  async listChunks(cacheId: string): Promise<CiphertextCacheChunkV1[]> {
    const database = await this.database()
    const transaction = database.transaction(CHUNK_STORE, 'readonly')
    const request = transaction.objectStore(CHUNK_STORE).index('cacheId').getAll(cacheId)
    const stored = await requestResult<StoredChunkV1[]>(request)
    await transactionDone(transaction)
    return stored
      .sort((left, right) => left.index - right.index)
      .map(chunk => ({
        cacheId: chunk.cacheId,
        index: chunk.index,
        bytes: new Uint8Array(chunk.bytes),
      }))
  }

  async listEntries(accountScope: string): Promise<CiphertextCacheEntryV1[]> {
    const database = await this.database()
    const transaction = database.transaction(ENTRY_STORE, 'readonly')
    const request = transaction.objectStore(ENTRY_STORE).index('accountScope').getAll(accountScope)
    const entries = await requestResult<CiphertextCacheEntryV1[]>(request)
    await transactionDone(transaction)
    return entries
  }

  async deleteEntry(cacheId: string): Promise<void> {
    const database = await this.database()
    const transaction = database.transaction([ENTRY_STORE, CHUNK_STORE], 'readwrite')
    transaction.objectStore(ENTRY_STORE).delete(cacheId)
    const chunkStore = transaction.objectStore(CHUNK_STORE)
    const cursorRequest = chunkStore.index('cacheId').openKeyCursor(IDBKeyRange.only(cacheId))
    cursorRequest.onsuccess = () => {
      const cursor = cursorRequest.result
      if (!cursor) return
      chunkStore.delete(cursor.primaryKey)
      cursor.continue()
    }
    await transactionDone(transaction)
  }

  async clearAccount(accountScope: string): Promise<void> {
    const entries = await this.listEntries(accountScope)
    for (const entry of entries) await this.deleteEntry(entry.cacheId)
  }

  close(): void {
    void this.databasePromise?.then(database => database.close()).catch(() => undefined)
    this.databasePromise = null
  }

  private database(): Promise<IDBDatabase> {
    if (!globalThis.indexedDB) return Promise.reject(new Error('IndexedDB is unavailable'))
    this.databasePromise ??= new Promise((resolve, reject) => {
      const request = globalThis.indexedDB.open(DATABASE_NAME, DATABASE_VERSION)
      request.onupgradeneeded = () => {
        const database = request.result
        const entries = database.createObjectStore(ENTRY_STORE, { keyPath: 'cacheId' })
        entries.createIndex('bindingKey', 'bindingKey', { unique: true })
        entries.createIndex('accountScope', 'accountScope')
        const chunks = database.createObjectStore(CHUNK_STORE, { keyPath: 'key' })
        chunks.createIndex('cacheId', 'cacheId')
      }
      request.onsuccess = () => resolve(request.result)
      request.onerror = () => reject(request.error ?? new Error('failed to open ciphertext cache'))
      request.onblocked = () => reject(new Error('ciphertext cache upgrade is blocked'))
    })
    return this.databasePromise
  }
}

function chunkKey(cacheId: string, index: number): string {
  return `${cacheId}:${index.toString().padStart(8, '0')}`
}

function requestResult<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error ?? new Error('ciphertext cache request failed'))
  })
}

function transactionDone(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve()
    transaction.onerror = () => reject(transaction.error ?? new Error('ciphertext cache transaction failed'))
    transaction.onabort = () => reject(transaction.error ?? new Error('ciphertext cache transaction aborted'))
  })
}
