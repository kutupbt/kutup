import { keepPreviousData, useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import api from '@kutup/session/client'
import type {
  AdminActivityResponse,
  AdminFederationPolicy,
  AdminSettings,
  AdminStats,
  BulkFederationPeerRetryResponse,
  FederationDomainRule,
  FederationMinimumTrust,
  FederationMode,
  FederationPeerEvidence,
  UserRow,
} from '@kutup/session/api-types'

export const adminKey = ['admin'] as const
const usersKey = [...adminKey, 'users'] as const
const federationKey = [...adminKey, 'federation'] as const

/** Every admin mutation invalidates the admin tree: one server change can move stats, rows and the audit log. */
function useAdminMutation<TInput, TResult = unknown>(mutationFn: (input: TInput) => Promise<TResult>) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: adminKey })
    },
  })
}

// --- overview + users ---------------------------------------------------

export function useAdminStats() {
  return useQuery({
    queryKey: [...adminKey, 'stats'],
    queryFn: async () => (await api.get<AdminStats>('/admin/stats')).data,
  })
}

export function useAdminUsers() {
  return useQuery({
    queryKey: usersKey,
    queryFn: async () => (await api.get<UserRow[]>('/admin/users')).data,
  })
}

export interface CreateUserInput {
  email: string
  username: string
  tempPassword: string
  storageQuotaBytes: number
  chatStorageQuotaBytes: number
}

export function useCreateUser() {
  return useAdminMutation(async (body: CreateUserInput) => {
    await api.post('/admin/users', body)
  })
}

export type UserPatch = Partial<{
  isActive: boolean
  isAdmin: boolean
  storageQuotaBytes: number
  chatStorageQuotaBytes: number
}>

export function useUpdateUser() {
  return useAdminMutation(async ({ id, patch }: { id: string; patch: UserPatch }) => {
    await api.put(`/admin/users/${encodeURIComponent(id)}`, patch)
  })
}

export function useForceDisable2fa() {
  return useAdminMutation(async (id: string) => {
    await api.delete(`/admin/users/${encodeURIComponent(id)}/2fa`)
  })
}

export function useRotateTempPassword() {
  return useAdminMutation(async ({ id, tempPassword }: { id: string; tempPassword: string }) => {
    await api.post(`/admin/users/${encodeURIComponent(id)}/rotate-temp-password`, { tempPassword })
  })
}

export function useWipeUser() {
  return useAdminMutation(async ({ id, tempPassword }: { id: string; tempPassword: string }) => {
    await api.post(`/admin/users/${encodeURIComponent(id)}/wipe`, { tempPassword })
  })
}

export function useDeleteUser() {
  return useAdminMutation(async (id: string) => {
    await api.delete(`/admin/users/${encodeURIComponent(id)}`)
  })
}

// --- activity -----------------------------------------------------------

export interface ActivityFilter {
  federationOnly: boolean
  domain: string
}

function activityParams(filter: ActivityFilter, limit: number, before?: number) {
  const params: Record<string, string> = { limit: String(limit) }
  if (before !== undefined) params.before = String(before)
  if (filter.federationOnly) params.actionPrefix = 'federation.'
  if (filter.federationOnly && filter.domain.trim()) params.domain = filter.domain.trim()
  return params
}

export function useAdminActivity(filter: ActivityFilter) {
  return useInfiniteQuery({
    queryKey: [...adminKey, 'activity', filter],
    initialPageParam: undefined as number | undefined,
    queryFn: async ({ pageParam }) =>
      (await api.get<AdminActivityResponse>('/admin/activity', { params: activityParams(filter, 50, pageParam) }))
        .data,
    getNextPageParam: (last) => last.nextBefore ?? undefined,
    placeholderData: keepPreviousData,
  })
}

/** CSV of the (federation) audit trail, as the server renders it. */
export async function exportActivityCsv(filter: ActivityFilter): Promise<Blob> {
  const response = await api.get<Blob>('/admin/activity/export', {
    params: activityParams(filter, 5000),
    responseType: 'blob',
  })
  return response.data
}

// --- server settings ----------------------------------------------------

export function useAdminSettings() {
  return useQuery({
    queryKey: [...adminKey, 'settings'],
    queryFn: async () => (await api.get<AdminSettings>('/admin/settings')).data,
  })
}

export function useUpdateAdminSettings() {
  return useAdminMutation(async (body: Partial<AdminSettings>) => {
    await api.put('/admin/settings', body)
  })
}

// --- federation ---------------------------------------------------------

export type FederationFeature = 'chat' | 'drive'

export function useFederationPolicy() {
  return useQuery({
    queryKey: federationKey,
    queryFn: async () => (await api.get<AdminFederationPolicy>('/admin/federation')).data,
  })
}

export function useUpdateFederationPolicy() {
  return useAdminMutation(
    async (body: {
      globalEnabled: boolean
      feature: FederationFeature
      mode: FederationMode
      minimumTrust: FederationMinimumTrust
    }) => {
      await api.put('/admin/federation', body)
    },
  )
}

export type RuleInput = Pick<FederationDomainRule, 'feature' | 'domain' | 'inbound' | 'outbound' | 'trustRequirement'>

export function useUpsertFederationRule() {
  return useAdminMutation(async ({ feature, domain, inbound, outbound, trustRequirement }: RuleInput) => {
    await api.put(`/admin/federation/rules/${feature}/${encodeURIComponent(domain)}`, {
      inbound,
      outbound,
      trustRequirement,
    })
  })
}

export function useDeleteFederationRule() {
  return useAdminMutation(async ({ feature, domain }: { feature: FederationFeature; domain: string }) => {
    await api.delete(`/admin/federation/rules/${feature}/${encodeURIComponent(domain)}`)
  })
}

export type PeerAction = 'verify' | 'retry' | 'repin'

export function usePeerAction() {
  return useAdminMutation(
    async ({ domain, action, body }: { domain: string; action: PeerAction; body?: Record<string, string> }) => {
      await api.post(`/admin/federation/peers/${encodeURIComponent(domain)}/${action}`, body ?? {})
    },
  )
}

export function useBulkRetryPeers() {
  return useAdminMutation(
    async (domains: string[]) =>
      (await api.post<BulkFederationPeerRetryResponse>('/admin/federation/peers/retry', { domains })).data,
  )
}

export function usePeerEvidence(domain: string | null) {
  return useQuery({
    queryKey: [...federationKey, 'evidence', domain],
    queryFn: async () =>
      (await api.get<FederationPeerEvidence>(`/admin/federation/peers/${encodeURIComponent(domain!)}/evidence`)).data,
    enabled: domain !== null,
  })
}
