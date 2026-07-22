import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import api from '../client'
import type {
  UserRow,
  AdminStats,
  AdminSettings,
  AdminActivityResponse,
  AdminFederationPolicy,
  BulkFederationPeerRetryResponse,
  FederationPeerEvidence,
  FederationMode,
  FederationMinimumTrust,
  FederationRuleAction,
  FederationTrustRequirement,
} from '@/types/api'

export function useAdminUsers() {
  return useQuery<UserRow[]>({
    queryKey: ['admin', 'users'],
    queryFn: () => api.get<UserRow[]>('/admin/users').then((r) => r.data),
  })
}

export function useAdminStats() {
  return useQuery<AdminStats>({
    queryKey: ['admin', 'stats'],
    queryFn: () => api.get<AdminStats>('/admin/stats').then((r) => r.data),
  })
}

/** The audit-log feed for the Recent-activity cards (newest first). */
export function useAdminActivity(limit = 10) {
  return useQuery<AdminActivityResponse>({
    queryKey: ['admin', 'activity', limit],
    queryFn: () =>
      api.get<AdminActivityResponse>(`/admin/activity?limit=${limit}`).then((r) => r.data),
  })
}

export function useAdminFederationActivity(limit = 20, domain?: string) {
  return useQuery<AdminActivityResponse>({
    queryKey: ['admin', 'activity', 'federation', limit, domain ?? ''],
    queryFn: () => {
      const params = new URLSearchParams({ limit: String(limit), actionPrefix: 'federation.' })
      if (domain) params.set('domain', domain)
      return api
        .get<AdminActivityResponse>(`/admin/activity?${params.toString()}`)
        .then((response) => response.data)
    },
  })
}

export function useExportAdminFederationActivity() {
  return useMutation({
    mutationFn: async (domain?: string) => {
      const params = new URLSearchParams({ limit: '5000', actionPrefix: 'federation.' })
      if (domain) params.set('domain', domain)
      const response = await api.get<Blob>(`/admin/activity/export?${params.toString()}`, {
        responseType: 'blob',
      })
      const url = URL.createObjectURL(response.data)
      const anchor = document.createElement('a')
      anchor.href = url
      anchor.download = domain
        ? `kutup-federation-audit-${domain}.csv`
        : 'kutup-federation-audit.csv'
      document.body.appendChild(anchor)
      anchor.click()
      anchor.remove()
      window.setTimeout(() => URL.revokeObjectURL(url), 0)
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.error ?? 'Federation audit export failed')
    },
  })
}

export function useAdminSettings() {
  return useQuery<AdminSettings>({
    queryKey: ['admin', 'settings'],
    queryFn: () => api.get<AdminSettings>('/admin/settings').then((r) => r.data),
  })
}

export function useAdminFederationPolicy() {
  return useQuery<AdminFederationPolicy>({
    queryKey: ['admin', 'federation'],
    queryFn: () =>
      api.get<AdminFederationPolicy>('/admin/federation').then((r) => r.data),
  })
}

export function useAdminFederationPeerEvidence(domain: string, enabled: boolean) {
  return useQuery<FederationPeerEvidence>({
    queryKey: ['admin', 'federation', 'evidence', domain],
    queryFn: () =>
      api
        .get<FederationPeerEvidence>(
          `/admin/federation/peers/${encodeURIComponent(domain)}/evidence`,
        )
        .then((response) => response.data),
    enabled,
  })
}

export function useBulkRetryAdminFederationPeers() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (domains: string[]) =>
      api
        .post<BulkFederationPeerRetryResponse>('/admin/federation/peers/retry', { domains })
        .then((response) => response.data),
    onSuccess: (response) => {
      qc.invalidateQueries({ queryKey: ['admin', 'federation'] })
      qc.invalidateQueries({ queryKey: ['admin', 'activity'] })
      const failed = response.results.filter((result) => !result.refreshed).length
      if (failed === 0) toast.success(`Retried ${response.results.length} federation peers`)
      else toast.warning(
        `Retried ${response.results.length} federation peers; ${failed} still need attention`,
      )
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.error ?? 'Federation peer retry failed')
    },
  })
}

export function useUpdateAdminFederationPolicy() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (policy: {
      globalEnabled: boolean
      feature: 'chat' | 'drive'
      mode: FederationMode
      minimumTrust: FederationMinimumTrust
    }) => api.put<AdminFederationPolicy>('/admin/federation', policy),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin', 'federation'] })
      qc.invalidateQueries({ queryKey: ['admin', 'activity'] })
      toast.success('Federation policy updated')
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.error ?? 'Federation policy update failed')
    },
  })
}

export function useUpsertAdminFederationRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({
      feature,
      domain,
      inbound,
      outbound,
      trustRequirement,
    }: {
      feature: 'chat' | 'drive'
      domain: string
      inbound: FederationRuleAction
      outbound: FederationRuleAction
      trustRequirement: FederationTrustRequirement
    }) =>
      api.put<AdminFederationPolicy>(
        `/admin/federation/rules/${feature}/${encodeURIComponent(domain)}`,
        { inbound, outbound, trustRequirement },
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin', 'federation'] })
      qc.invalidateQueries({ queryKey: ['admin', 'activity'] })
      toast.success('Federation server rule saved')
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.error ?? 'Federation server rule update failed')
    },
  })
}

export function useDeleteAdminFederationRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ feature, domain }: { feature: 'chat' | 'drive'; domain: string }) =>
      api.delete<AdminFederationPolicy>(
        `/admin/federation/rules/${feature}/${encodeURIComponent(domain)}`,
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin', 'federation'] })
      qc.invalidateQueries({ queryKey: ['admin', 'activity'] })
      toast.success('Federation server rule removed')
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.error ?? 'Federation server rule removal failed')
    },
  })
}

function peerMutation(
  path: (domain: string) => string,
  success: string,
) {
  return function usePeerMutation() {
    const qc = useQueryClient()
    return useMutation({
      mutationFn: ({ domain, body }: { domain: string; body?: Record<string, string> }) =>
        api.post<AdminFederationPolicy>(path(domain), body ?? {}),
      onSuccess: () => {
        qc.invalidateQueries({ queryKey: ['admin', 'federation'] })
        qc.invalidateQueries({ queryKey: ['admin', 'activity'] })
        toast.success(success)
      },
      onError: (err: any) => toast.error(err.response?.data?.error ?? 'Federation peer action failed'),
    })
  }
}

export const useVerifyAdminFederationPeer = peerMutation(
  (domain) => `/admin/federation/peers/${encodeURIComponent(domain)}/verify`,
  'Federation peer verified',
)
export const useRetryAdminFederationPeer = peerMutation(
  (domain) => `/admin/federation/peers/${encodeURIComponent(domain)}/retry`,
  'Federation discovery retried',
)
export const useRepinAdminFederationPeer = peerMutation(
  (domain) => `/admin/federation/peers/${encodeURIComponent(domain)}/repin`,
  'Federation peer re-pinned',
)

export function useCreateUser() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: {
      email: string
      username: string
      tempPassword: string
      storageQuotaBytes: number
    }) => api.post('/admin/users', body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin', 'users'] })
      qc.invalidateQueries({ queryKey: ['admin', 'stats'] })
      qc.invalidateQueries({ queryKey: ['admin', 'activity'] })
      toast.success('User created')
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.error ?? 'Failed to create user')
    },
  })
}

export function useUpdateUser() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({
      id,
      body,
    }: {
      id: string
      // `isAdmin` promotes/demotes; the backend rejects demoting the
      // break-glass admin (403) and the last usable admin (400).
      body: Partial<{ isActive: boolean; storageQuotaBytes: number; isAdmin: boolean }>
    }) => api.put(`/admin/users/${id}`, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin', 'users'] })
      qc.invalidateQueries({ queryKey: ['admin', 'activity'] })
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.error ?? 'Update failed')
    },
  })
}

/**
 * Admin override that force-disables a user's TOTP 2FA — for users locked
 * out of their authenticator. The account becomes password-only until the
 * user re-enables 2FA from their Security page.
 */
export function useForceDisable2fa() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.delete(`/admin/users/${id}/2fa`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin', 'users'] })
      qc.invalidateQueries({ queryKey: ['admin', 'activity'] })
      toast.success('Two-factor authentication disabled for this user')
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.error ?? 'Failed to disable 2FA')
    },
  })
}

/**
 * Replaces the temp password of a user still in first-login state (no key
 * material yet, so nothing is destroyed). 409 for established accounts —
 * E2EE means only the user can reset their own password (recovery phrase).
 */
export function useRotateTempPassword() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, tempPassword }: { id: string; tempPassword: string }) =>
      api.post(`/admin/users/${id}/rotate-temp-password`, { tempPassword }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin', 'activity'] })
      toast.success('Temporary password rotated')
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.error ?? 'Failed to rotate temp password')
    },
  })
}

/**
 * Destructive account wipe — for a user who lost both password and recovery
 * phrase. Purges all their data + keys and resets the account to first-login
 * with a new temp password. Irreversible.
 */
export function useWipeUser() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, tempPassword }: { id: string; tempPassword: string }) =>
      api.post(`/admin/users/${id}/wipe`, { tempPassword }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin', 'users'] })
      qc.invalidateQueries({ queryKey: ['admin', 'stats'] })
      qc.invalidateQueries({ queryKey: ['admin', 'activity'] })
      toast.success('Account wiped and reset to first-login')
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.error ?? 'Wipe failed')
    },
  })
}

export function useDeleteUser() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.delete(`/admin/users/${id}`),
    onMutate: async (id: string) => {
      await qc.cancelQueries({ queryKey: ['admin', 'users'] })
      const prev = qc.getQueryData<UserRow[]>(['admin', 'users'])
      qc.setQueryData<UserRow[]>(['admin', 'users'], (old) => old?.filter((u) => u.id !== id) ?? [])
      return { prev }
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin', 'stats'] })
      qc.invalidateQueries({ queryKey: ['admin', 'activity'] })
      toast.success('User deleted')
    },
    onError: (err: any, _id, ctx: any) => {
      qc.setQueryData(['admin', 'users'], ctx?.prev)
      toast.error(err.response?.data?.error ?? 'Delete failed')
    },
  })
}

export function useUpdateAdminSettings() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: Partial<AdminSettings>) =>
      api.put('/admin/settings', body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin', 'settings'] })
      qc.invalidateQueries({ queryKey: ['admin', 'activity'] })
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.error ?? 'Settings update failed')
    },
  })
}
