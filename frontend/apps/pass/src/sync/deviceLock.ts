// One lock for Pass on this device, not one per tab (as Proton Pass locks
// the whole app): a vault locked in one tab is locked in every tab, a new
// tab included, and so is one opened from Drive. What opens it again is the
// same everywhere (`autoLock.ts`, the unlock mode).
//
// Kept in localStorage per account, and forgotten on sign-out, so a new
// sign-in starts unlocked (the account password was just given); a session
// that merely expired and is renewed keeps what was locked. Open tabs hear of a lock
// at once (BroadcastChannel) and close what they hold. Idling is counted for
// the device too: use in any tab keeps every tab's vaults open, and a tab
// opened after the device has idled past the delay starts locked.

const STATE_KEY = 'kutup-pass-lock'
const ACTIVITY_KEY = 'kutup-pass-activity'
const CHANNEL = 'kutup-pass-lock'
/** Activity is written at most this often (every keystroke need not be). */
const ACTIVITY_WRITE_MS = 5_000

interface LockState {
  /** The account it belongs to (its user id). */
  account: string
  /** Every vault locked (idle, or all at once), save those unlocked since. */
  all: boolean
  /** Vaults locked one by one. */
  ids: string[]
  /** Vaults unlocked on purpose since everything locked. */
  unlocked: string[]
}

type Message = { type: 'lockAll' } | { type: 'lock'; fileId: string }

function empty(account: string): LockState {
  return { account, all: false, ids: [], unlocked: [] }
}

/** The stored state, or null when storage can't be read. */
function read(account: string): LockState | null {
  let raw: string | null
  try {
    raw = localStorage.getItem(STATE_KEY)
  } catch {
    return null
  }
  try {
    const parsed = JSON.parse(raw ?? 'null') as Partial<LockState> | null
    if (!parsed || parsed.account !== account) return empty(account)
    return {
      account,
      all: parsed.all === true,
      ids: Array.isArray(parsed.ids) ? parsed.ids.filter((id) => typeof id === 'string') : [],
      unlocked: Array.isArray(parsed.unlocked) ? parsed.unlocked.filter((id) => typeof id === 'string') : [],
    }
  } catch {
    return empty(account)
  }
}

function write(state: LockState): void {
  try {
    localStorage.setItem(STATE_KEY, JSON.stringify(state))
  } catch {
    // Storage blocked: this tab's memory below still holds it.
  }
  memory = state
}

/** The state for a tab whose storage is blocked: this tab only. */
let memory: LockState | null = null

function current(account: string): LockState {
  return read(account) ?? (memory?.account === account ? memory : empty(account))
}

/** Whether the vault waits for an unlock before its kept key opens it. */
export function isLocked(account: string, fileId: string): boolean {
  const state = current(account)
  return state.ids.includes(fileId) || (state.all && !state.unlocked.includes(fileId))
}

/** Whether every vault is locked already (nothing unlocked since). */
export function allLocked(account: string): boolean {
  const state = current(account)
  return state.all && state.unlocked.length === 0
}

/** The vault was unlocked on purpose: open, here and in new tabs. */
export function markUnlocked(account: string, fileId: string): void {
  const state = current(account)
  write({
    ...state,
    ids: state.ids.filter((id) => id !== fileId),
    unlocked: state.all && !state.unlocked.includes(fileId) ? [...state.unlocked, fileId] : state.unlocked,
  })
}

/** One vault locked: in every tab. */
export function markLocked(account: string, fileId: string): void {
  const state = current(account)
  write({
    ...state,
    ids: state.ids.includes(fileId) ? state.ids : [...state.ids, fileId],
    unlocked: state.unlocked.filter((id) => id !== fileId),
  })
  post({ type: 'lock', fileId })
}

/** Every vault locked: in every tab. */
export function markAllLocked(account: string): void {
  write({ account, all: true, ids: [], unlocked: [] })
  post({ type: 'lockAll' })
}

/** Signed out: nothing of this sign-in's lock is kept. */
export function forgetLock(): void {
  try {
    localStorage.removeItem(STATE_KEY)
  } catch {
    // Nothing kept.
  }
  memory = null
}

/**
 * Starts this tab's part: what another tab locks is closed here too. Returns
 * what stops it.
 */
export function joinDeviceLock(handlers: { lockAll: () => void; lock: (fileId: string) => void }): () => void {
  if (typeof BroadcastChannel === 'undefined') return () => {}
  const channel = new BroadcastChannel(CHANNEL)
  channel.onmessage = (event: MessageEvent<Message>) => {
    const message = event.data
    if (message?.type === 'lockAll') handlers.lockAll()
    else if (message?.type === 'lock' && typeof message.fileId === 'string') handlers.lock(message.fileId)
  }
  sender = channel
  return () => {
    if (sender === channel) sender = null
    channel.close()
  }
}

let sender: BroadcastChannel | null = null

function post(message: Message): void {
  try {
    sender?.postMessage(message)
  } catch {
    // The channel is closed: other tabs read the state when they next open a vault.
  }
}

/** The last use of Pass in any tab of this device (ms), if any is known. */
export function lastDeviceActivity(): number | null {
  try {
    const value = Number(localStorage.getItem(ACTIVITY_KEY))
    return Number.isFinite(value) && value > 0 ? value : null
  } catch {
    return null
  }
}

let lastWritten = 0

/** Pass was used in this tab at `now`. */
export function recordActivity(now: number): void {
  if (now - lastWritten < ACTIVITY_WRITE_MS) return
  lastWritten = now
  try {
    localStorage.setItem(ACTIVITY_KEY, String(now))
  } catch {
    // This tab's own count still applies.
  }
}

/** Whether the account has a lock state on this device yet. */
export function knownAccount(account: string): boolean {
  try {
    const parsed = JSON.parse(localStorage.getItem(STATE_KEY) ?? 'null') as { account?: unknown } | null
    return parsed?.account === account
  } catch {
    return memory?.account === account
  }
}

/** Starts the account's lock state on this device, unlocked. */
export function startAccount(account: string): void {
  write(empty(account))
}
