import { storageReady } from '@kutup/crypto/storageGate'
const CHAT_DEVICE_RESET_REQUEST = 'kutup.chat.resetDevice'
const CHAT_DEVICE_ID = 'kutup.chat.deviceId'
const CHAT_DEVICE_REPLACED = 'kutup.chat.replacedDevice'

/**
 * The account's Chat store on this origin (docs/plans/api-surface.md §6):
 * named by its permanent account id. Each server is its own origin, and a
 * server reset clears the origin (instance.ts), so the id alone scopes it.
 */
export async function chatDeviceDatabaseName(accountId: string): Promise<string> {
  // Opened by whoever asks for the name: the instance check comes first.
  await storageReady()
  return `kutup.chat.store:${accountId}`
}

/**
 * Remove only this browser's Chat device state. The continuous-backup
 * database and private media cache deliberately remain intact so a subsequent
 * device registration can restore acknowledged display history.
 */
export async function resetLocalChatDevice(accountId: string): Promise<void> {
  const name = await chatDeviceDatabaseName(accountId)
  await new Promise<void>((resolve, reject) => {
    const request = indexedDB.deleteDatabase(name)
    request.onsuccess = () => resolve()
    request.onerror = () => reject(
      request.error ?? new Error('Could not reset this browser Chat device'),
    )
    request.onblocked = () => reject(new Error(
      'Close other Kutup tabs before resetting this browser Chat device',
    ))
  })
}

export function requestLocalChatDeviceReset(accountId: string): void {
  sessionStorage.setItem(CHAT_DEVICE_RESET_REQUEST, accountId)
}

/** Complete a user-confirmed reset after navigation has closed old IDB handles. */
export async function completeRequestedLocalChatDeviceReset(accountId: string): Promise<boolean> {
  if (sessionStorage.getItem(CHAT_DEVICE_RESET_REQUEST) !== accountId) return false
  await resetLocalChatDevice(accountId)
  // The device this browser was is gone for good: once the new one is
  // registered it is revoked (takeReplacedLocalChatDevice), or it would stay
  // in the account's signed device list and in its groups.
  const previous = readStored(localStorage, `${CHAT_DEVICE_ID}:${accountId}`)
  if (previous) writeStored(localStorage, `${CHAT_DEVICE_REPLACED}:${accountId}`, previous)
  sessionStorage.removeItem(CHAT_DEVICE_RESET_REQUEST)
  return true
}

/** Record which Chat device this browser is (its id is not a secret). */
export function rememberLocalChatDevice(accountId: string, deviceId: number): void {
  writeStored(localStorage, `${CHAT_DEVICE_ID}:${accountId}`, String(deviceId))
}

/** The device a reset of this browser replaced and has not yet revoked. */
export function replacedLocalChatDevice(accountId: string): number | null {
  const value = Number(readStored(localStorage, `${CHAT_DEVICE_REPLACED}:${accountId}`))
  return Number.isSafeInteger(value) && value >= 1 && value <= 127 ? value : null
}

export function forgetReplacedLocalChatDevice(accountId: string): void {
  try {
    localStorage.removeItem(`${CHAT_DEVICE_REPLACED}:${accountId}`)
  } catch {
    // Storage can be unavailable; the revocation is then offered again.
  }
}

function readStored(storage: Storage, key: string): string | null {
  try {
    return storage.getItem(key)
  } catch {
    return null
  }
}

function writeStored(storage: Storage, key: string, value: string): void {
  try {
    storage.setItem(key, value)
  } catch {
    // Storage can be full or blocked; the old device is then revoked by hand.
  }
}
