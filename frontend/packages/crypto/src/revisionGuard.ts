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
// - The store is on disk, where anyone with the disk can read and write it:
//   entries are named by an HMAC of what they are about and hold the
//   revision sealed to that name, under keys derived from the master key
//   (Rust `revision_guard`). A disk attacker can delete an entry (the device
//   is then a fresh one for that value) or put back an older copy of it, but
//   can neither read the entries nor set one to a revision of its choosing.

import { toBase64 } from './base64'
import { getCryptoWasm } from './rustWasm'

/** The account's keys for the store (Rust `revision_guard::GuardKeys`). */
export interface GuardKeys {
  entryId(scope: string, id: string): string
  sealSeen(entry: string, revision: number): string
  /** Throws when the sealed revision was moved to another entry or altered. */
  openSeen(entry: string, sealed: string): number
}

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

/** Entries by name: each a revision sealed to its name. */
export interface RevisionStore {
  get(entry: string): Promise<string | undefined>
  put(entry: string, sealed: string): Promise<void>
}

export function memoryRevisionStore(): RevisionStore {
  const seen = new Map<string, string>()
  return {
    get: (key) => Promise.resolve(seen.get(key)),
    put: (key, revision) => {
      seen.set(key, revision)
      return Promise.resolve()
    },
  }
}

const DB_NAME = 'kutup-revisions-v2'
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
      return typeof value === 'string' ? value : undefined
    },
    async put(key, revision) {
      const database = await db()
      if (!database) return fallback.put(key, revision)
      // Done only once the transaction commits: a request's success comes
      // first, and a page closed (or reloaded) in between loses the write.
      const transaction = database.transaction(STORE, 'readwrite')
      transaction.objectStore(STORE).put(revision, key)
      await new Promise<void>((resolve, reject) => {
        transaction.oncomplete = () => resolve()
        transaction.onerror = () => reject(transaction.error ?? new Error('IndexedDB write failed'))
        transaction.onabort = () => reject(transaction.error ?? new Error('IndexedDB write aborted'))
      })
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
    private readonly keys: () => Promise<GuardKeys>,
    private readonly now: () => number = Date.now,
  ) {}

  private async entry(scope: string, id: string): Promise<{ keys: GuardKeys; entry: string }> {
    const keys = await this.keys()
    return { keys, entry: keys.entryId(scope, id) }
  }

  /** The highest revision seen of `scope`/`id` (0: none, or an entry that was altered). */
  async seen(scope: string, id: string): Promise<number> {
    const { keys, entry } = await this.entry(scope, id)
    const sealed = await this.store.get(entry)
    if (!sealed) return 0
    try {
      return keys.openSeen(entry, sealed)
    } catch {
      // Altered or moved: no better than deleted, which the disk allows anyway.
      return 0
    }
  }

  /**
   * A revision read (or written): refused when older than one seen;
   * remembered when newer.
   */
  async accept(scope: string, id: string, revision: number): Promise<void> {
    checkRevision(revision)
    const { keys, entry } = await this.entry(scope, id)
    // One read-then-write at a time per entry, so two accepts at once
    // cannot leave the lower of them stored.
    await serialized(entry, async () => {
      const seen = await this.seen(scope, id)
      if (revision < seen) throw new OlderThanSeenError(scope, revision, seen)
      if (revision > seen) await this.store.put(entry, keys.sealSeen(entry, revision))
    })
  }

  /** The revision to seal a new value of `scope`/`id` at, written on top of `base`. */
  async next(scope: string, id: string, base = 0): Promise<number> {
    return Math.max(Math.floor(this.now()), (await this.seen(scope, id)) + 1, base + 1)
  }
}

const chains = new Map<string, Promise<unknown>>()

/**
 * Runs `task` after every earlier task on `entry` in this page, and under the
 * browser's lock of the same name where there is one (other tabs too).
 */
function serialized<T>(entry: string, task: () => Promise<T>): Promise<T> {
  const locks = typeof navigator !== 'undefined' ? navigator.locks : undefined
  const run = (): Promise<T> => (locks ? (locks.request(`kutup-revision:${entry}`, task) as Promise<T>) : task())
  const result = (chains.get(entry) ?? Promise.resolve()).then(run, run)
  const settled = result.catch(() => undefined)
  chains.set(entry, settled)
  void settled.then(() => {
    if (chains.get(entry) === settled) chains.delete(entry)
  })
  return result
}

let shared: RevisionStore | null = null
/** By account: the guard, for the master key it was made with. */
const guards = new Map<string, { masterKey: string; guard: RevisionGuard }>()
/** Set by tests: keys that need no WASM. */
let testKeys: ((userId: string) => GuardKeys) | null = null

/** The account's guard over the browser's store. */
export function revisionGuard(session: { userId: string; masterKey: Uint8Array }): RevisionGuard {
  const masterKey = toBase64(session.masterKey)
  const known = guards.get(session.userId)
  // Made again when the master key is another (the keys derive from it).
  if (known?.masterKey === masterKey) return known.guard
  shared ??= indexedDbRevisionStore()
  let keys: Promise<GuardKeys> | null = null
  const forTests = testKeys
  const load = (): Promise<GuardKeys> => {
    if (forTests) return Promise.resolve(forTests(session.userId))
    keys ??= getCryptoWasm()
      .then((wasm): GuardKeys => new wasm.RevisionGuardKeys(masterKey))
      .catch((error: unknown) => {
        // Not kept: the next call loads again.
        keys = null
        throw error
      })
    return keys
  }
  const guard = new RevisionGuard(shared, load)
  guards.set(session.userId, { masterKey, guard })
  return guard
}

/** Forgets every account's history (a fresh device) and uses keys that need no WASM: for tests. */
export function resetRevisionGuardsForTesting(): void {
  shared = memoryRevisionStore()
  guards.clear()
  chains.clear()
  testKeys = plainGuardKeysForTesting
}

/** Keys for tests: entries named as they are, revisions as text, checked against their entry. */
export function plainGuardKeysForTesting(account: string): GuardKeys {
  return {
    entryId: (scope, id) => `${account}:${scope}:${id}`,
    sealSeen: (entry, revision) => `${entry}=${revision}`,
    openSeen: (entry, sealed) => {
      const [name, revision] = sealed.split('=')
      if (name !== entry) throw new Error('moved')
      return Number(revision)
    },
  }
}
