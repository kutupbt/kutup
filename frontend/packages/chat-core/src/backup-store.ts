const ZERO_DIGEST = '0'.repeat(64)

export interface StoredBackupRecord<T> {
  id: string
  fingerprint: string
  record: T
  local: boolean
}

export interface BackupOutboxEntry {
  deviceSequence: number
  operationId: string
  previousSegmentDigest: string
  ciphertext: string
  ciphertextBytes: number
  ciphertextSha256: string
  recordCount: number
}

export interface StoredBackupMedia {
  attachmentId: string
  referenceId: string
  mediaId: string
  ciphertextBytes: number
  protected: boolean
  needsAttention: boolean
  storageFull: boolean
}

export interface BackupLocalState {
  key: 'state'
  deviceSequence: number
  lastSegmentDigest: string
  restoredCursor: number
  latestProtectedAt?: number
  acknowledgedEvents: number
  acknowledgedBytes: number
  lastCompactedAt: number
  highestGeneration: number
  highestCursor: number
  highestManifestDigest: string
}

export function openBackupStore(name: string): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(`${name}:continuous-backup`, 2)
    request.onupgradeneeded = () => {
      const db = request.result
      if (!db.objectStoreNames.contains('meta')) db.createObjectStore('meta', { keyPath: 'key' })
      if (!db.objectStoreNames.contains('records')) db.createObjectStore('records', { keyPath: 'id' })
      if (!db.objectStoreNames.contains('outbox')) {
        db.createObjectStore('outbox', { keyPath: 'deviceSequence' })
      }
      if (!db.objectStoreNames.contains('media')) {
        db.createObjectStore('media', { keyPath: 'attachmentId' })
      }
    }
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error ?? new Error('open Chat backup database'))
  })
}

export async function replaceBackupMedia(
  db: IDBDatabase,
  media: StoredBackupMedia[],
): Promise<void> {
  const transaction = db.transaction('media', 'readwrite')
  const store = transaction.objectStore('media')
  store.clear()
  for (const value of media) store.put(value)
  await transactionDone(transaction)
}

export async function getAll<T>(db: IDBDatabase, store: string): Promise<T[]> {
  const transaction = db.transaction(store, 'readonly')
  const result = await requestResult(transaction.objectStore(store).getAll()) as T[]
  await transactionDone(transaction)
  return result
}

export async function countStore(db: IDBDatabase, store: string): Promise<number> {
  const transaction = db.transaction(store, 'readonly')
  const result = await requestResult(transaction.objectStore(store).count())
  await transactionDone(transaction)
  return result
}

export async function putValue(
  db: IDBDatabase,
  store: string,
  value: unknown,
): Promise<void> {
  const transaction = db.transaction(store, 'readwrite')
  transaction.objectStore(store).put(value)
  await transactionDone(transaction)
}

export async function loadBackupState(
  db: IDBDatabase,
  now = Date.now(),
): Promise<BackupLocalState> {
  const transaction = db.transaction('meta', 'readonly')
  const value = await requestResult(
    transaction.objectStore('meta').get('state'),
  ) as BackupLocalState | undefined
  await transactionDone(transaction)
  const defaults: BackupLocalState = {
    key: 'state',
    deviceSequence: 0,
    lastSegmentDigest: ZERO_DIGEST,
    restoredCursor: 0,
    acknowledgedEvents: 0,
    acknowledgedBytes: 0,
    lastCompactedAt: now,
    highestGeneration: 0,
    highestCursor: 0,
    highestManifestDigest: ZERO_DIGEST,
  }
  return value ? { ...defaults, ...value } : defaults
}

export async function commitBackupQueue<T>(
  db: IDBDatabase,
  records: StoredBackupRecord<T>[],
  outbox: BackupOutboxEntry[],
  state: BackupLocalState,
): Promise<void> {
  const transaction = db.transaction(['meta', 'records', 'outbox'], 'readwrite')
  const recordStore = transaction.objectStore('records')
  for (const record of records) recordStore.put(record)
  const outboxStore = transaction.objectStore('outbox')
  for (const entry of outbox) outboxStore.add(entry)
  transaction.objectStore('meta').put(state)
  await transactionDone(transaction)
}

export async function acknowledgeBackupEntry(
  db: IDBDatabase,
  entry: BackupOutboxEntry,
  cursor: number,
  acknowledgedAt: number,
  now = Date.now(),
): Promise<void> {
  const state = await loadBackupState(db, now)
  state.restoredCursor = Math.max(state.restoredCursor, cursor)
  state.highestCursor = Math.max(state.highestCursor, cursor)
  state.latestProtectedAt = acknowledgedAt
  state.acknowledgedEvents += entry.recordCount
  state.acknowledgedBytes += entry.ciphertextBytes
  const transaction = db.transaction(['meta', 'outbox'], 'readwrite')
  transaction.objectStore('outbox').delete(entry.deviceSequence)
  transaction.objectStore('meta').put(state)
  await transactionDone(transaction)
}

export async function replaceRestoredRecords<T>(
  db: IDBDatabase,
  records: StoredBackupRecord<T>[],
  cursor: number,
  now = Date.now(),
  media?: StoredBackupMedia[],
): Promise<void> {
  const state = await loadBackupState(db, now)
  state.restoredCursor = cursor
  const stores = media ? ['meta', 'records', 'media'] : ['meta', 'records']
  const transaction = db.transaction(stores, 'readwrite')
  const store = transaction.objectStore('records')
  store.clear()
  for (const record of records) store.put(record)
  if (media) {
    const mediaStore = transaction.objectStore('media')
    mediaStore.clear()
    for (const value of media) mediaStore.put(value)
  }
  transaction.objectStore('meta').put(state)
  await transactionDone(transaction)
}

function requestResult<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error ?? new Error('Chat backup database request'))
  })
}

function transactionDone(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve()
    transaction.onerror = () => reject(
      transaction.error ?? new Error('Chat backup database transaction'),
    )
    transaction.onabort = () => reject(
      transaction.error ?? new Error('Chat backup database transaction aborted'),
    )
  })
}
