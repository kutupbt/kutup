import { keepPreviousData, useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { conflictCode, opaqueRegister } from '@kutup/session/opaque'
import { accountGrant, type OneUseSecret } from '@kutup/session/reauth'
import api from '@kutup/session/client'
import type {
  AdminActivityResponse,
  AdminFederationPolicy,
  AdminSettings,
  AdminStats,
  RegistrySetting,
  BulkFederationPeerRetryResponse,
  CreatedRegistrationCode,
  FederationDomainRule,
  FederationMinimumTrust,
  FederationMode,
  FederationPeerEvidence,
  RegistrationCode,
  RegistrationCodeUse,
  SignedUpWith,
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

/** The domain after the @ of this server's addresses. */
export function useServerName() {
  return useQuery({
    queryKey: ['auth-settings', 'server-name'],
    staleTime: Infinity,
    queryFn: async () => (await api.get<{ chat?: { serverName?: string } }>('/auth/settings')).data.chat?.serverName ?? '',
  })
}

export function useAdminUsers() {
  return useQuery({
    queryKey: usersKey,
    queryFn: async () => (await api.get<UserRow[]>('/admin/users')).data,
  })
}

/**
 * A temporary password registered for a new key binding (OPAQUE,
 * docs/plans/opaque.md): the server keeps a record it cannot test guesses
 * against, and never sees the password. The account sets up its own keys,
 * and its own password, at its first sign-in.
 */
async function temporaryPassword(tempPassword: string, auth: { grant: string } | null) {
  const draw = async () => {
    const keyBinding = crypto.randomUUID()
    return { keyBinding, ...(await opaqueRegister(tempPassword, keyBinding, null, auth)) }
  }
  // A binding someone else has is drawn again, once.
  try {
    return await draw()
  } catch (error) {
    if (conflictCode(error) !== 'keyBindingTaken') throw error
    return await draw()
  }
}


/**
 * A grant to reset `id`: the administrator proves their own password first
 * (a reauth grant for `adminReset`), which the server exchanges for one bound
 * to that account.
 */
async function resetGrant(id: string, adminPassword: string): Promise<string> {
  const grant = await accountGrant(adminPassword, 'adminReset')
  const { data } = await api.post<{ grant: string }>(`/admin/users/${encodeURIComponent(id)}/reset-grant`, { grant })
  return data.grant
}

export interface CreateUserInput {
  username: string
  tempPassword: string
  storageQuotaBytes: number
}

export function useCreateUser() {
  return useAdminMutation(async ({ username, tempPassword, storageQuotaBytes }: CreateUserInput) => {
    await api.post('/admin/users', { username, ...(await temporaryPassword(tempPassword, null)), storageQuotaBytes })
  })
}

export type UserPatch = Partial<{
  isActive: boolean
  isAdmin: boolean
  storageQuotaBytes: number
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

export interface ResetInput {
  id: string
  tempPassword: string
  /** The administrator's own password, proven again first; read once. */
  adminPassword: OneUseSecret
}

export function useRotateTempPassword() {
  return useAdminMutation(async ({ id, tempPassword, adminPassword }: ResetInput) => {
    const grant = await resetGrant(id, adminPassword.take())
    await api.post(`/admin/users/${encodeURIComponent(id)}/rotate-temp-password`, {
      grant,
      ...(await temporaryPassword(tempPassword, { grant })),
    })
  })
}

export function useWipeUser() {
  return useAdminMutation(async ({ id, tempPassword, adminPassword }: ResetInput) => {
    const grant = await resetGrant(id, adminPassword.take())
    await api.post(`/admin/users/${encodeURIComponent(id)}/wipe`, { grant, ...(await temporaryPassword(tempPassword, { grant })) })
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

/** Every whole-number setting with its section, unit and range (the registry). */
export function useSettingsRegistry() {
  return useQuery({
    queryKey: [...adminKey, 'settings', 'registry'],
    queryFn: async () => (await api.get<{ settings: RegistrySetting[] }>('/admin/settings/registry')).data.settings,
  })
}

export function useUpdateAdminSettings() {
  return useAdminMutation(async (body: Partial<AdminSettings>) => {
    await api.put('/admin/settings', body)
  })
}

// --- referral codes (docs/plans/registration-codes.md) -------------------

const codesKey = [...adminKey, 'registration-codes'] as const

export function useRegistrationCodes() {
  return useQuery({
    queryKey: codesKey,
    queryFn: async () => (await api.get<RegistrationCode[]>('/admin/registration-codes')).data,
  })
}

/** Makes a code; the result holds its text, which the server never returns again. */
export function useCreateRegistrationCode() {
  return useAdminMutation(
    async (body: { note: string; expiresAt: string | null; maxUses: number | null }) =>
      (await api.post<CreatedRegistrationCode>('/admin/registration-codes', body)).data,
  )
}

export function useRevokeRegistrationCode() {
  return useAdminMutation(async (id: string) => (await api.post<RegistrationCode>(`/admin/registration-codes/${id}/revoke`)).data)
}

export function useRegistrationCodeUses(id: string | null) {
  return useQuery({
    queryKey: [...codesKey, id, 'uses'],
    enabled: id !== null,
    queryFn: async () => (await api.get<RegistrationCodeUse[]>(`/admin/registration-codes/${id}/uses`)).data,
  })
}

/** The code an account signed up with, or null. */
export function useUserRegistrationCode(userId: string) {
  return useQuery({
    queryKey: [...usersKey, userId, 'registration-code'],
    queryFn: async () => (await api.get<SignedUpWith | null>(`/admin/users/${userId}/registration-code`)).data,
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

// --- reports on public links ---------------------------------------------

export type ReportReason = 'phishing' | 'malware' | 'illegal' | 'abuse' | 'other'

/** One report on a public link (`GET /api/admin/reports`). */
export interface LinkReport {
  id: string
  reason: ReportReason
  details: string
  /** The whole link, key included, when the reporter gave it; open reports only. */
  link: string | null
  createdAt: string
  resolvedAt: string | null
  resolution: 'dismissed' | 'removed' | 'disabled' | null
  shareId: string
  shareType: 'collection' | 'file'
  shareCreatedAt: string
  shareRemovedAt: string | null
  ownerUserId: string
  ownerUsername: string
  ownerIsActive: boolean
  openReportsOnLink: number
}

// --- feedback ------------------------------------------------------------

export interface FeedbackItem {
  id: string
  kind: 'bug' | 'feature' | 'other'
  app: string
  message: string
  details: Partial<Record<'version' | 'browser' | 'language' | 'screen', string>> | null
  createdAt: string
  /** Null when the account was deleted since. */
  userId: string | null
  userUsername: string | null
  resolvedAt: string | null
  resolution: 'done' | 'dismissed' | 'forwarded' | null
  githubUrl: string | null
}

export const feedbackKey = [...adminKey, 'feedback'] as const

export function useFeedback(status: 'open' | 'resolved') {
  return useQuery({
    queryKey: [...feedbackKey, status],
    queryFn: async () => (await api.get<FeedbackItem[]>('/admin/feedback', { params: { status } })).data,
  })
}

export function useResolveFeedback() {
  return useAdminMutation(async (input: { id: string; resolution: 'done' | 'dismissed' | 'forwarded'; githubUrl?: string }) => {
    await api.post(`/admin/feedback/${encodeURIComponent(input.id)}/resolve`, {
      resolution: input.resolution,
      ...(input.githubUrl ? { githubUrl: input.githubUrl } : {}),
    })
  })
}

export function useDeleteFeedback() {
  return useAdminMutation(async (id: string) => {
    await api.delete(`/admin/feedback/${encodeURIComponent(id)}`)
  })
}

export const reportsKey = [...adminKey, 'reports'] as const

export function useLinkReports(status: 'open' | 'resolved') {
  return useQuery({
    queryKey: [...reportsKey, status],
    queryFn: async () => (await api.get<LinkReport[]>('/admin/reports', { params: { status } })).data,
  })
}

export function useDismissReport() {
  return useAdminMutation(async (id: string) => {
    await api.post(`/admin/reports/${encodeURIComponent(id)}/dismiss`)
  })
}

export function useRemoveReportedLink() {
  return useAdminMutation(async (id: string) => {
    await api.post(`/admin/reports/${encodeURIComponent(id)}/remove-link`)
  })
}
