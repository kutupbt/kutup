// Uploads started in this browser and not finished: enough to go on after a
// reload or a crash (docs/roadmap.md, "Drive · large uploads from the
// browser"). Kept in IndexedDB, one store per app origin, each record for
// one account.
//
// Nothing here is readable without the folder's key: the file's key and
// its name travel in the two envelopes the upload already made (sealed
// under the folder key and the file key, exactly as the server stores
// them), and the prefix (the Drive and secretstream headers) is not
// secret: it is the start of what was uploaded. The size and the time the
// file was last modified pick out the same file when it is chosen again.

export interface PendingUpload {
  fileId: string
  /** The account that started it. */
  owner: string
  /** The tus upload on the server. */
  uploadUrl: string
  size: number
  lastModified: number
  collectionId: string
  keyEpoch: number
  /** The file key sealed under the folder key at `keyEpoch`. */
  fileKeyEnvelope: string
  /** The name and details sealed under the file key. */
  metadataEnvelope: string
  /** Base64 of the ciphertext's first bytes (Drive header, secretstream header). */
  prefix: string
  startedAt: number
  updatedAt: number
}

/**
 * The server reaps an upload nobody has written to for 24 hours (the tus
 * reaper in crates/kutup-server/src/jobs.rs); one older than that cannot
 * go on.
 */
export const PENDING_UPLOAD_LIFETIME_MS = 24 * 60 * 60 * 1000

const DATABASE = 'kutup-pending-uploads'
const STORE = 'uploads'

function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE, 1)
    request.onupgradeneeded = () => {
      const store = request.result.createObjectStore(STORE, { keyPath: 'fileId' })
      store.createIndex('owner', 'owner')
    }
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error ?? new Error('pending uploads cannot be opened'))
  })
}

async function run<T>(mode: IDBTransactionMode, work: (store: IDBObjectStore) => IDBRequest<T> | void): Promise<T | undefined> {
  const db = await open()
  try {
    return await new Promise<T | undefined>((resolve, reject) => {
      const transaction = db.transaction(STORE, mode)
      const request = work(transaction.objectStore(STORE))
      transaction.oncomplete = () => resolve(request ? request.result : undefined)
      transaction.onerror = () => reject(transaction.error ?? new Error('pending uploads transaction failed'))
      transaction.onabort = () => reject(transaction.error ?? new Error('pending uploads transaction aborted'))
    })
  } finally {
    db.close()
  }
}

export const pendingUploads = {
  async put(upload: PendingUpload): Promise<void> {
    await run('readwrite', (store) => store.put(upload))
  },

  async remove(fileId: string): Promise<void> {
    await run('readwrite', (store) => store.delete(fileId))
  },

  /** This account's, newest first; ones the server has reaped by now are dropped. */
  async list(owner: string, now = Date.now()): Promise<PendingUpload[]> {
    const all = (await run<PendingUpload[]>('readonly', (store) => store.index('owner').getAll(owner))) ?? []
    const live: PendingUpload[] = []
    for (const upload of all) {
      if (now - upload.updatedAt >= PENDING_UPLOAD_LIFETIME_MS) await pendingUploads.remove(upload.fileId)
      else live.push(upload)
    }
    return live.sort((a, b) => b.startedAt - a.startedAt)
  },
}

const LOCK_PREFIX = 'kutup-upload:'

/**
 * Mark an upload as running in this tab until `done` settles: a Web Lock,
 * which the browser lets go when the tab closes or crashes, so an upload
 * running anywhere is never offered as interrupted.
 */
export function holdUpload(fileId: string, done: Promise<unknown>): void {
  if (!('locks' in navigator)) return
  void navigator.locks.request(`${LOCK_PREFIX}${fileId}`, () => done.catch(() => undefined))
}

/** Uploads running in some tab of this app now. */
export async function runningUploads(): Promise<Set<string>> {
  if (!('locks' in navigator)) return new Set()
  const { held = [] } = await navigator.locks.query()
  return new Set(held.map((lock) => lock.name ?? '').filter((name) => name.startsWith(LOCK_PREFIX)).map((name) => name.slice(LOCK_PREFIX.length)))
}
