import api from '@kutup/session/client'

/**
 * Signal's per-device password, Kutup's `X-Kutup-Device`
 * (docs/plans/account-identity-key.md): once this browser's Chat device is
 * registered or opened, every device-bound Chat call carries
 * `<deviceId>.<credential>` beside the session token. Anonymous routes never
 * do: a credential there would tie a sealed request to its device.
 */
export const DEVICE_HEADER = 'X-Kutup-Device'

let header: string | null = null
let installed = false
let refused = false

export function setChatDeviceAuth(deviceId: number, credential: string): void {
  header = `${deviceId}.${credential}`
  refused = false
  if (installed) return
  installed = true
  api.interceptors.request.use((config) => {
    // A call that names its device already (an editing device's, on an
    // origin that also runs Chat) keeps it.
    if (header && isDeviceBoundChatRoute(config.url, config.method) && !config.headers.has(DEVICE_HEADER)) {
      config.headers.set(DEVICE_HEADER, header)
    }
    return config
  })
  api.interceptors.response.use(undefined, (error: unknown) => {
    const response = (error as { response?: { status?: number; data?: unknown } }).response
    if (
      response?.status === 401 &&
      (response.data as { code?: unknown } | undefined)?.code === 'deviceCredential'
    ) {
      refused = true
    }
    return Promise.reject(error)
  })
}

/**
 * Whether the server refused this browser's device credential since it was
 * set (`401 deviceCredential`): the device was removed, here or on another
 * device, or dropped by a re-registration. Reading it clears it.
 */
export function takeDeviceCredentialRefusal(): boolean {
  const value = refused
  refused = false
  return value
}

/** Forget the credential (sign-out, a closed service). */
export function clearChatDeviceAuth(): void {
  header = null
}

/**
 * Every `/chat/*` call but the registration itself, the provisioning ticket
 * (a device being linked has no credential yet) and the anonymous routes;
 * and the socket ticket (`/device-ticket`, shared with the editing devices).
 */
export function isDeviceBoundChatRoute(url: string | undefined, method?: string): boolean {
  if (url?.split('?')[0] === '/device-ticket') return true
  if (!url || !url.startsWith('/chat/')) return false
  const path = url.split('?')[0]
  if (path === '/chat/device' && method?.toLowerCase() === 'post') return false
  if (path === '/chat/provisioning/ticket') return false
  return !path.startsWith('/chat/anonymous')
}
