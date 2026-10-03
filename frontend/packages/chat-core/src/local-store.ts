import { resolveApiBase } from '@kutup/session/apiBase'

const CHAT_DEVICE_DATABASE_VERSION = 'v2'
const CHAT_DEVICE_RESET_REQUEST = 'kutup:chat:reset-device'
const CHAT_DEVICE_ID = 'kutup:chat:device-id'
const CHAT_DEVICE_REPLACED = 'kutup:chat:replaced-device'

export async function chatDeviceDatabaseName(userId: string): Promise<string> {
  return `kutup-chat-${CHAT_DEVICE_DATABASE_VERSION}:${await chatAccountScope(userId)}`
}

/**
 * Remove only this browser's Direct/MLS device state. The continuous-backup
 * database and private media cache deliberately remain intact so a subsequent
 * device registration can restore acknowledged display history.
 */
export async function resetLocalChatDevice(userId: string): Promise<void> {
  const name = await chatDeviceDatabaseName(userId)
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

export function requestLocalChatDeviceReset(userId: string): void {
  sessionStorage.setItem(CHAT_DEVICE_RESET_REQUEST, userId)
}

/** Complete a user-confirmed reset after navigation has closed old IDB handles. */
export async function completeRequestedLocalChatDeviceReset(userId: string): Promise<boolean> {
  if (sessionStorage.getItem(CHAT_DEVICE_RESET_REQUEST) !== userId) return false
  await resetLocalChatDevice(userId)
  // The device this browser was is gone for good: once the new one is
  // registered it is revoked (takeReplacedLocalChatDevice), or it would stay
  // in the account's signed device list and in its groups.
  const previous = readStored(localStorage, `${CHAT_DEVICE_ID}:${userId}`)
  if (previous) writeStored(localStorage, `${CHAT_DEVICE_REPLACED}:${userId}`, previous)
  sessionStorage.removeItem(CHAT_DEVICE_RESET_REQUEST)
  return true
}

/** Record which Chat device this browser is (its id is not a secret). */
export function rememberLocalChatDevice(userId: string, deviceId: number): void {
  writeStored(localStorage, `${CHAT_DEVICE_ID}:${userId}`, String(deviceId))
}

/** The device a reset of this browser replaced and has not yet revoked. */
export function replacedLocalChatDevice(userId: string): number | null {
  const value = Number(readStored(localStorage, `${CHAT_DEVICE_REPLACED}:${userId}`))
  return Number.isSafeInteger(value) && value >= 1 && value <= 127 ? value : null
}

export function forgetReplacedLocalChatDevice(userId: string): void {
  try {
    localStorage.removeItem(`${CHAT_DEVICE_REPLACED}:${userId}`)
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

async function chatAccountScope(userId: string): Promise<string> {
  const apiBase = await resolveApiBase()
  const canonicalServer = new URL(apiBase, window.location.href).href
  const digest = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(`${canonicalServer}\0${userId}`),
  )
  return Array.from(new Uint8Array(digest).slice(0, 16), byte =>
    byte.toString(16).padStart(2, '0'),
  ).join('')
}
