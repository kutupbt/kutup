import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import api from '@kutup/session/client'
import { broadcastColor } from '@kutup/session/sessionSync'
import { updateSession } from '@kutup/session/store'

// --- profile ------------------------------------------------------------

export const meKey = ['me'] as const

export interface Me {
  id: string
  email: string
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
  isActive: boolean
  createdAt: string
  lastSeenAt: string | null
}

export function useDevices() {
  return useQuery({
    queryKey: devicesKey,
    queryFn: async () => (await api.get<EditorDevice[]>('/devices')).data,
  })
}

export function useRevokeDevice() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (id: number) => {
      await api.delete(`/devices/${id}`)
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: devicesKey })
    },
  })
}

// --- storage ------------------------------------------------------------

export const storageKey = ['storage'] as const

/** `GET /api/user/storage`: the account's one pool and what fills it, as the server stores it. */
export interface StorageUsage {
  quotaBytes: number
  usedBytes: number
  reservedBytes: number
  drive: {
    filesBytes: number
    filesCount: number
    trashBytes: number
    trashCount: number
    versionsBytes: number
    thumbnailsBytes: number
    assetsBytes: number
  }
  chat: {
    mediaBytes: number
    historyBytes: number
    historyMediaBytes: number
  }
}

export function useStorageUsage() {
  return useQuery({
    queryKey: storageKey,
    queryFn: async () => (await api.get<StorageUsage>('/user/storage')).data,
  })
}
