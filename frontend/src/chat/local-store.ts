import { resolveApiBase } from '@/lib/apiBase'

const CHAT_DEVICE_DATABASE_VERSION = 'v2'
const CHAT_DEVICE_RESET_REQUEST = 'kutup:chat:reset-device'

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
  sessionStorage.removeItem(CHAT_DEVICE_RESET_REQUEST)
  return true
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
