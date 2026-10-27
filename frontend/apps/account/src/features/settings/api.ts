import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import api from '@kutup/session/client'
import { accountGrant, type OneUseSecret } from '@kutup/session/reauth'
import { broadcastColor } from '@kutup/session/sessionSync'
import { getSession, updateSession } from '@kutup/session/store'
import { toBase64 } from '@kutup/crypto/base64'
import { removeDevicesFromManifest } from '@kutup/crypto/accountManifest'
import { listAccountDevices, ownAccount, publishNextManifest, type AccountDevice } from '@kutup/session/devices'

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

/** A code, and the account password that allows the change (a `totp` grant, made at the last moment). */
export interface TotpChange {
  code: string
  password: OneUseSecret
}

/** Turns two-factor sign-in on; its recovery codes, to show once. */
export function useVerifyTotp() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async ({ code, password }: TotpChange) => {
      const grant = await accountGrant(password.take(), 'totp')
      const { data } = await api.post<{ recoveryCodes: string[] }>('/user/2fa/verify', { code, grant })
      return data.recoveryCodes
    },
    onSuccess: async () => {
      updateSession({ totpEnabled: true })
      await queryClient.invalidateQueries({ queryKey: meKey })
      await queryClient.invalidateQueries({ queryKey: recoveryCodesKey })
    },
  })
}

export const recoveryCodesKey = ['recoveryCodes'] as const

/** How many recovery codes the account has left. */
export function useRecoveryCodesLeft(enabled: boolean) {
  return useQuery({
    queryKey: recoveryCodesKey,
    queryFn: async () => (await api.get<{ remaining: number }>('/user/2fa/recovery-codes')).data.remaining,
    enabled,
  })
}

/**
 * New recovery codes in place of the old ones, with the password (a `totp`
 * grant) and the second factor (an authenticator code or an unused recovery
 * code); the codes, to show once.
 */
export function useRenewRecoveryCodes() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async ({ code, password }: TotpChange) => {
      const grant = await accountGrant(password.take(), 'totp')
      const { data } = await api.post<{ recoveryCodes: string[] }>('/user/2fa/recovery-codes', { code, grant })
      return data.recoveryCodes
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: recoveryCodesKey })
    },
  })
}

export function useDisableTotp() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async ({ code, password }: TotpChange) => {
      const grant = await accountGrant(password.take(), 'totp')
      await api.delete('/user/2fa', { data: { code, grant } })
    },
    onSuccess: async () => {
      updateSession({ totpEnabled: false })
      await queryClient.invalidateQueries({ queryKey: meKey })
      await queryClient.invalidateQueries({ queryKey: recoveryCodesKey })
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

/** An editing app or the CLI, as the account's device list has it. */
export type EditorDevice = AccountDevice & { kind: 'editor' | 'cli' }

/**
 * The account's editing devices and CLIs (docs/plans/one-device-list.md).
 * Chat devices are listed, and removed, in their own section: removing one
 * takes it out of every group, which only Chat can do.
 */
export function useDevices() {
  return useQuery({
    queryKey: devicesKey,
    queryFn: async () =>
      (await listAccountDevices()).filter((d): d is EditorDevice => d.kind === 'editor' || d.kind === 'cli'),
  })
}

/**
 * Removes a device: the account's next manifest without it, signed with the
 * master key's authority and published by this sign-in alone (the server
 * takes one that only removes devices without a device of the app's own, so
 * the Account app registers none). The server then drops the device's row
 * and closes its connections.
 */
export function useRevokeDevice() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (device: EditorDevice) => {
      const session = getSession()
      if (!session) throw new Error('not signed in')
      const masterKey = toBase64(session.masterKey)
      await publishNextManifest(await ownAccount(session), null, async (head) =>
        // Listed: the next manifest leaves it out. Not listed (yet, or any
        // more): nothing to sign; the next publication drops its row.
        head?.devices.some((listed) => listed.deviceId === device.deviceId)
          ? removeDevicesFromManifest(head, [device.deviceId], new Date().toISOString(), masterKey)
          : null,
      )
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: devicesKey })
    },
  })
}

// --- security events (the account's own sign-in history) ------------------

/** What happened to the way the account signs in. Later kinds are shown generically. */
export type SecurityEventKind =
  | 'passwordChange'
  | 'recovery'
  | 'rotate'
  | 'adminReset'
  | 'accountReset'
  | 'rename'
  | 'nameDropped'
  | 'nameClosed'
  | 'nameFreed'
  | (string & {})

export interface SecurityEvent {
  id: string
  kind: SecurityEventKind
  /** RFC 3339. */
  at: string
  /** Made by the session asking (this device). */
  thisSession: boolean
  /** The kind of session that made it (`web-account`, `cli`, …), as the session list has it; null for a recovery or an administrator's reset. */
  client: string | null
  /** That session's User-Agent; null as `client` is. */
  userAgent: string | null
  /** Done by an administrator. */
  byAdmin: boolean
  /** For a name event: the name it was about (the old one, for a rename). */
  oldName?: string
  /** For a rename: the new name. */
  newName?: string
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
