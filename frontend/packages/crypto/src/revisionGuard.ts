// The highest revision this device has seen of each value the account
// replaces over time (contact cards, mail folder/label/filter names, the
// identity pin list): Rust seals the revision into the value's authenticated
// header, the server stores a new value only on top of the revision the
// write started from, and this guard refuses one older than seen, so a
// server cannot quietly hand back an old contact card, name or pin list.
//
// Revisions are times in unix milliseconds: a new one is
// max(now, highest seen + 1, base + 1), so a value deleted and made again
// (a contact imported again with the same UID, a folder with the same id)
// is newer than anything seen before it.
//
// Limits, as for identity pins (docs/plans/drive-identity-pins.md):
// - A device with no history (a new browser, site data cleared) accepts the
//   first revision it sees; the guard protects from then on.
// - A device whose clock runs behind cannot write a value another device has
//   written with a later time until it has read that value (then it writes
//   above it); a write that started from an older read gets the server's
//   409 and reads again. One whose clock runs ahead writes high revisions;
//   every device that reads them continues above them.
// - The revisions themselves are not secret (the server stores them in
//   clear), so this store keeps them plainly, per account, in IndexedDB.

/** A revision older than this device has already seen for the same value. */
export class OlderThanSeenError extends Error {
  constructor(
    readonly scope: string,
    readonly revision: number,
    readonly seen: number,
  ) {
    super(`${scope}: revision ${revision} is older than ${seen}, already seen here`)
    this.name = 'OlderThanSeenError'
  }
}

export interface RevisionStore {
  get(key: string): Promise<number | undefined>
  put(key: string, revision: number): Promise<void>
}

export function memoryRevisionStore(): RevisionStore {
  const seen = new Map<string, number>()
  return {
    get: (key) => Promise.resolve(seen.get(key)),
    put: (key, revision) => {
      seen.set(key, revision)
      return Promise.resolve()
    },
  }
}

const DB_NAME = 'kutup-revisions'
const STORE = 'seen'

function request<T>(req: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error ?? new Error('IndexedDB request failed'))
  })
}

/**
 * The browser's store; when IndexedDB is unavailable (a private window that
 * refuses it), a memory one, which is a fresh device on every visit.
 */
export function indexedDbRevisionStore(): RevisionStore {
  let opened: Promise<IDBDatabase | null> | null = null
  const fallback = memoryRevisionStore()
  const db = () =>
    (opened ??= new Promise<IDBDatabase | null>((resolve) => {
      try {
        const open = indexedDB.open(DB_NAME, 1)
        open.onupgradeneeded = () => open.result.createObjectStore(STORE)
        open.onsuccess = () => resolve(open.result)
        open.onerror = () => resolve(null)
        open.onblocked = () => resolve(null)
      } catch {
        resolve(null)
      }
    }))
  return {
    async get(key) {
      const database = await db()
      if (!database) return fallback.get(key)
      const value = await request(database.transaction(STORE, 'readonly').objectStore(STORE).get(key))
      return typeof value === 'number' ? value : undefined
    },
    async put(key, revision) {
      const database = await db()
      if (!database) return fallback.put(key, revision)
      await request(database.transaction(STORE, 'readwrite').objectStore(STORE).put(revision, key))
    },
  }
}

/** Revisions are safe integers (unix milliseconds stay far below 2^53). */
function checkRevision(revision: number): number {
  if (!Number.isSafeInteger(revision) || revision < 1) throw new Error(`invalid revision ${revision}`)
  return revision
}

export class RevisionGuard {
  constructor(
    private readonly store: RevisionStore,
    private readonly userId: string,
    private readonly now: () => number = Date.now,
  ) {}

  private key(scope: string, id: string): string {
    return `${this.userId}\u0000${scope}\u0000${id}`
  }

  /** The highest revision seen of `scope`/`id` (0: none). */
  async seen(scope: string, id: string): Promise<number> {
    return (await this.store.get(this.key(scope, id))) ?? 0
  }

  /**
   * A revision read (or written): refused when older than one seen;
   * remembered when newer.
   */
  async accept(scope: string, id: string, revision: number): Promise<void> {
    checkRevision(revision)
    const seen = await this.seen(scope, id)
    if (revision < seen) throw new OlderThanSeenError(scope, revision, seen)
    if (revision > seen) await this.store.put(this.key(scope, id), revision)
  }

  /** The revision to seal a new value of `scope`/`id` at, written on top of `base`. */
  async next(scope: string, id: string, base = 0): Promise<number> {
    return Math.max(Math.floor(this.now()), (await this.seen(scope, id)) + 1, base + 1)
  }
}

let shared: RevisionStore | null = null
const guards = new Map<string, RevisionGuard>()

/** The account's guard over the browser's store. */
export function revisionGuard(userId: string): RevisionGuard {
  let guard = guards.get(userId)
  if (!guard) {
    shared ??= indexedDbRevisionStore()
    guard = new RevisionGuard(shared, userId)
    guards.set(userId, guard)
  }
  return guard
}

/** Forgets every account's history: a fresh device, for tests. */
export function resetRevisionGuardsForTesting(): void {
  shared = memoryRevisionStore()
  guards.clear()
}
