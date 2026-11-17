// The server instance id (docs/plans/api-surface.md §5). A server mints it
// on an empty database and keeps it for that database's life; a wipe changes
// it. Each app origin remembers the id it last saw. Before it reads any local
// state, boot compares the two: another id (or none remembered while Kutup
// data is here, as in browsers from before ids) means the data here belongs
// to a server that is gone, so this origin's storage is cleared, keeping
// only the anti-rollback anchors, which a lying server must not be able to
// erase. Every API answer also carries the id (`X-Kutup-Instance`): a change
// mid-session reloads the page, and the reload's boot does the clearing.

import axios from 'axios'

/** Where this origin remembers the id. */
export const INSTANCE_KEY = 'kutup.instance'
/** The answer header naming the id. */
export const INSTANCE_HEADER = 'x-kutup-instance'
/** Set once the storage was cleared, for the sign-in page's notice. */
export const SERVER_RESET_NOTICE = 'kutup.session.serverReset'

/**
 * Names kept across an instance change: the anti-rollback anchors. They are
 * keyed by account id, and a wiped server mints new ones, so a real wipe's
 * anchors never match again; a server that only claims a new id can't make
 * clients forget what they pinned.
 */
const ANCHOR_DATABASES = ['kutup.account.revisionsSeen', 'kutup-revisions-v2']
const ANCHOR_KEY = /^(kutup\.account\.manifestPins:|kutup-manifest-pins:)/
/** Not account data: the look of the page. Kept too. */
const KEPT_KEY = /^(kutup\.ui\.(theme|language)$|kutup-theme$|kutup-lang$)/

/** Every Kutup database name this code and earlier versions used, for browsers without indexedDB.databases(). */
const KNOWN_DATABASES = [
  'kutup.account.records',
  'kutup.files.ciphertextCache',
  'kutup.drive.pendingUploads',
  'kutup-account-records',
  'kutup-private-ciphertext-cache-v1',
  'kutup-pending-uploads',
]

function isKutupKey(key: string): boolean {
  return key.startsWith('kutup')
}

function storageKeys(storage: Storage): string[] {
  const keys: string[] = []
  for (let i = 0; i < storage.length; i++) {
    const key = storage.key(i)
    if (key !== null) keys.push(key)
  }
  return keys
}

/** Whether this origin holds any Kutup data (beyond the kept look). */
function hasKutupData(): boolean {
  return storageKeys(localStorage).some((key) => isKutupKey(key) && !KEPT_KEY.test(key))
}

function deleteDatabase(name: string): Promise<void> {
  return new Promise((resolve) => {
    const request = indexedDB.deleteDatabase(name)
    request.onsuccess = () => resolve()
    request.onerror = () => resolve()
    // Another tab holds it open: it reloads on the broadcast and lets go.
    request.onblocked = () => resolve()
  })
}

/**
 * Clears this origin's Kutup storage but the anchors and the look: every
 * IndexedDB database, every `kutup` key in localStorage and sessionStorage.
 */
export async function clearOriginState(): Promise<void> {
  let names: string[] = KNOWN_DATABASES
  if (typeof indexedDB !== 'undefined') {
    try {
      const listed = await indexedDB.databases?.()
      if (listed) names = listed.map((db) => db.name).filter((name): name is string => !!name)
    } catch {
      // Older browsers: the known names.
    }
    await Promise.all(names.filter((name) => !ANCHOR_DATABASES.includes(name)).map(deleteDatabase))
  }
  for (const key of storageKeys(localStorage)) {
    if (isKutupKey(key) && !ANCHOR_KEY.test(key) && !KEPT_KEY.test(key)) localStorage.removeItem(key)
  }
  for (const key of storageKeys(sessionStorage)) {
    if (isKutupKey(key)) sessionStorage.removeItem(key)
  }
}

function remembered(): string | null {
  try {
    return localStorage.getItem(INSTANCE_KEY)
  } catch {
    return null
  }
}

/**
 * Brings this origin's storage in line with the server's id: nothing when it
 * matches; else clear, remember the new id, and leave a notice for the
 * sign-in page. Returns whether it cleared.
 */
export async function reconcileInstance(instanceId: string): Promise<boolean> {
  const known = remembered()
  if (known === instanceId) return false
  const clear = known !== null || hasKutupData()
  if (clear) await clearOriginState()
  try {
    localStorage.setItem(INSTANCE_KEY, instanceId)
    if (clear) sessionStorage.setItem(SERVER_RESET_NOTICE, '1')
  } catch {
    // Storage refused (private mode): nothing kept, nothing to clear later.
  }
  return clear
}

/** Unversioned: any client of any version may ask it. */
const HEALTH_PATH = '/api/health'

let checked: Promise<void> | null = null

/**
 * Once per page load, before any local state is read: asks the server for
 * its id and reconciles. Boot awaits it (restoreSession).
 */
export function ensureInstance(): Promise<void> {
  checked ??= (async () => {
    const { data } = await axios.get<{ instanceId?: unknown }>(HEALTH_PATH, {
      headers: { 'Cache-Control': 'no-store' },
    })
    if (typeof data.instanceId === 'string' && data.instanceId) await reconcileInstance(data.instanceId)
  })().catch((error: unknown) => {
    checked = null
    throw error
  })
  return checked
}

/**
 * An API answer's id: another one than this origin remembers means the
 * server was reset under a running page, which reloads so boot clears.
 */
export function noteInstance(value: unknown): void {
  if (typeof value !== 'string' || !value) return
  const known = remembered()
  if (known === null || known === value) return
  if (typeof window !== 'undefined') window.location.reload()
}

/** Whether this page load's boot cleared the storage, once (the sign-in page's notice). */
export function takeServerResetNotice(): boolean {
  try {
    if (sessionStorage.getItem(SERVER_RESET_NOTICE) === null) return false
    sessionStorage.removeItem(SERVER_RESET_NOTICE)
    return true
  } catch {
    return false
  }
}

/** Test seam: forget this page load's check. */
export function resetInstanceCheckForTesting(): void {
  checked = null
}
