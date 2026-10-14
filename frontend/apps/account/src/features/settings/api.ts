import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import api from '@kutup/session/client'
import { broadcastColor } from '@kutup/session/sessionSync'
import { getSession, updateSession } from '@kutup/session/store'
import { toBase64 } from '@kutup/crypto/base64'
import { signDeviceRevocation } from '@kutup/crypto/deviceRegistration'

// --- profile ------------------------------------------------------------

export const meKey = ['me'] as const

export interface Me {
  id: string
  username: string
  totpEnabled: boolean
  storageQuotaBytes: number
  storageUsedBytes: number
  isAdmin: boolean
  color: string
  /** How long file versions are kept, in days (docs/plans/drive-versions-v2.md). */
  versionRetentionDays: number
}


export function useMe() {
  return useQuery({
    queryKey: meKey,
    queryFn: async () => (await api.get<Me>('/user/me')).data,
  })
}

/** Presence colour for collaborative editing; '' resets to the automatic one. */
export function useUpdateColor() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (color: string) => {
      await api.patch('/user/me', { color })
      return color || null
    },
    onSuccess: async (color) => {
      updateSession({ color })
      broadcastColor(color)
      await queryClient.invalidateQueries({ queryKey: meKey })
    },
  })
}


// --- two-factor ---------------------------------------------------------

export interface TotpEnrolment {
  secret: string
  qrUri: string
}

export function useStartTotp() {
  return useMutation({
    mutationFn: async () => (await api.post<TotpEnrolment>('/user/2fa/setup')).data,
  })
}

export function useVerifyTotp() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (code: string) => {
      await api.post('/user/2fa/verify', { code })
    },
    onSuccess: async () => {
      updateSession({ totpEnabled: true })
      await queryClient.invalidateQueries({ queryKey: meKey })
    },
  })
}

export function useDisableTotp() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (code: string) => {
      await api.delete('/user/2fa', { data: { code } })
    },
    onSuccess: async () => {
      updateSession({ totpEnabled: false })
      await queryClient.invalidateQueries({ queryKey: meKey })
    },
  })
}

// --- sessions -----------------------------------------------------------

export const sessionsKey = ['sessions'] as const

export interface SessionView {
  id: string
  clientType: string
  parentId: string | null
  userAgent: string | null
  createdAt: string
  lastUsedAt: string
  current: boolean
}

export function useSessions() {
  return useQuery({
    queryKey: sessionsKey,
    queryFn: async () => (await api.get<SessionView[]>('/auth/sessions')).data,
  })
}

function useSessionMutation<T>(fn: (input: T) => Promise<void>) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: fn,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: sessionsKey })
    },
  })
}

export function useRevokeSession() {
  return useSessionMutation(async (id: string) => {
    await api.delete(`/auth/sessions/${encodeURIComponent(id)}`)
  })
}

export function useRevokeOtherSessions() {
  return useSessionMutation(async (_: void) => {
    await api.delete('/auth/sessions')
  })
}

// --- editor devices -----------------------------------------------------

export const devicesKey = ['devices'] as const

export interface EditorDevice {
  deviceId: number
  label: string
  /** Its Ed25519 public key, base64: what a revocation names. */
  publicSigning: string
  /** Not revoked. */
  isActive: boolean
  /** Not revoked, and its sign-in is live: edits from it are taken. */
  trusted: boolean
  /** Trusted and renewed within 30 days: one of the at most 20 in use. */
  inUse: boolean
  createdAt: string
  lastSeenAt: string | null
}

/** The most devices an account has in use (docs/plans/device-registration.md). */
export const MAX_DEVICES_IN_USE = 20

export function useDevices() {
  return useQuery({
    queryKey: devicesKey,
    queryFn: async () => (await api.get<EditorDevice[]>('/devices')).data,
  })
}

export function useRevokeDevice() {
  const queryClient = useQueryClient()
  return useMutation({
    // Revoking is the account's act: its key signs it, so a session alone
    // cannot revoke the account's devices.
    mutationFn: async (device: EditorDevice) => {
      const session = getSession()
      if (!session) throw new Error('not signed in')
      const revokedAtMs = Date.now()
      const signature = await signDeviceRevocation(
        toBase64(session.masterKey),
        serverOfAddress(session.address),
        device.publicSigning,
        revokedAtMs,
      )
      await api.delete(`/devices/${device.deviceId}`, { data: { revokedAtMs, signature } })
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: devicesKey })
    },
  })
}

/** The server part of a Kutup address (`username@server`): what device revocations name. */
function serverOfAddress(address: string): string {
  const at = address.lastIndexOf('@')
  if (at < 0 || at === address.length - 1) throw new Error('the account address has no server')
  return address.slice(at + 1)
}

// --- security events (the account's own sign-in history) ------------------

/** What happened to the way the account signs in. Later kinds are shown generically. */
export type SecurityEventKind = 'passwordChange' | 'recovery' | 'rotate' | 'adminReset' | 'accountReset' | (string & {})

export interface SecurityEvent {
  id: string
  kind: SecurityEventKind
  /** RFC 3339. */
  at: string
  /** Made by the session asking (this device). */
  thisSession: boolean
  /** Done by an administrator. */
  byAdmin: boolean
}

interface SecurityEventsPage {
  events: SecurityEvent[]
  /** Older events; null when there are none. */
  next: string | null
}

export const securityEventsKey = ['security-events'] as const

/** The account's security events, newest first, a page at a time. */
export function useSecurityEvents() {
  return useInfiniteQuery({
    queryKey: securityEventsKey,
    initialPageParam: undefined as string | undefined,
    queryFn: async ({ pageParam }) =>
      (
        await api.get<SecurityEventsPage>('/user/security-events', {
          params: { limit: 50, ...(pageParam ? { cursor: pageParam } : {}) },
        })
      ).data,
    getNextPageParam: (last) => last.next ?? undefined,
  })
}
