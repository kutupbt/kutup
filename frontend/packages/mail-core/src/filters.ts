import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { openMailName, sealMailName, toBase64 } from '@kutup/crypto'
import api from '@kutup/session/client'
import { useRequiredSession } from '@kutup/session/store'
import { mailKey, useMailAccount } from './api'

// Mail filters (docs/plans/mail-filters.md, F2), as Proton's simple
// filters. The server runs them as mail arrives, so conditions and actions
// are readable to it; the name is sealed here like folder names.

export type FilterField = 'sender' | 'recipient' | 'subject' | 'attachments'
export type FilterOp = 'contains' | 'is' | 'begins' | 'ends' | 'matches'

export interface FilterCondition {
  field: FilterField
  op: FilterOp
  negate: boolean
  value: string
}

export interface FilterActions {
  /** `inbox`, `archive`, `spam`, `trash`, or `custom:<folder id>`. */
  folder?: string
  labels?: string[]
  markRead?: boolean
  star?: boolean
}

export interface MailFilter {
  id: string
  name: string
  enabled: boolean
  position: number
  match: 'all' | 'any'
  conditions: FilterCondition[]
  actions: FilterActions
  source: 'manual' | 'sender'
}

export interface FilterRun {
  id: string
  total: number
  done: number
  changed: number
  finished: boolean
  failed: boolean
}

export const filtersKey = ['mail', 'filters'] as const

/** The account's filters, in the order they run, with their names opened. */
export function useFilters() {
  const session = useRequiredSession()
  const account = useMailAccount()
  const address = account.data?.address
  return useQuery({
    queryKey: [...filtersKey, address],
    enabled: !!address,
    queryFn: async (): Promise<MailFilter[]> => {
      const { data } = await api.get<MailFilter[]>('/mail/filters')
      const masterKey = toBase64(session.masterKey)
      return Promise.all(
        data.map(async (filter) => ({
          ...filter,
          name: await openMailName(masterKey, address!, 'filter', filter.id, filter.name).catch(() => '…'),
        })),
      )
    },
  })
}

function useFilterMutation<T, R>(fn: (input: T, seal: (id: string, name: string) => Promise<string>) => Promise<R>) {
  const session = useRequiredSession()
  const account = useMailAccount()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (input: T) => {
      const address = account.data?.address
      if (!address) throw new Error('mail is not ready')
      const masterKey = toBase64(session.masterKey)
      return fn(input, (id, name) => sealMailName(masterKey, address, 'filter', id, name))
    },
    onSettled: () => queryClient.invalidateQueries({ queryKey: filtersKey }),
  })
}

export type FilterDraft = Pick<MailFilter, 'name' | 'match' | 'conditions' | 'actions'> & { enabled?: boolean; source?: MailFilter['source'] }

export function useCreateFilter() {
  return useFilterMutation(async (draft: FilterDraft, seal) => {
    const id = crypto.randomUUID()
    const { name, ...rest } = draft
    await api.post('/mail/filters', { id, name: await seal(id, name.trim()), ...rest })
    return id
  })
}

export function useUpdateFilter() {
  return useFilterMutation(async (input: Partial<FilterDraft> & { id: string }, seal) => {
    // The source is fixed when a filter is made.
    const { id, name, enabled, match, conditions, actions } = input
    await api.patch(`/mail/filters/${id}`, { enabled, match, conditions, actions, ...(name !== undefined ? { name: await seal(id, name.trim()) } : {}) })
  })
}

export function useDeleteFilter() {
  return useFilterMutation(async (id: string) => {
    await api.delete(`/mail/filters/${id}`)
  })
}

export function useOrderFilters() {
  return useFilterMutation(async (ids: string[]) => {
    await api.put('/mail/filters/order', { ids })
  })
}

/** Starts "apply to existing messages" (all switched-on filters, or `ids`). */
export function useApplyFilters() {
  return useMutation({
    mutationFn: async (ids?: string[]) => (await api.post<FilterRun>('/mail/filters/apply', ids ? { ids } : {})).data,
  })
}

/** A run's progress, polled until it finishes; the mail lists refresh then. */
export function useFilterRun(runId: string | null) {
  const queryClient = useQueryClient()
  return useQuery({
    queryKey: ['mail', 'filter-run', runId],
    enabled: !!runId,
    refetchInterval: (query) => (query.state.data?.finished ? false : 1000),
    queryFn: async () => {
      const run = (await api.get<FilterRun>(`/mail/filters/runs/${runId}`)).data
      if (run.finished) void queryClient.invalidateQueries({ queryKey: mailKey })
      return run
    },
  })
}

/** Whether a draft is complete: a name, at least one condition with a value, at least one action. */
export function filterProblems(draft: FilterDraft): ('name' | 'conditions' | 'actions')[] {
  const problems: ('name' | 'conditions' | 'actions')[] = []
  if (!draft.name.trim()) problems.push('name')
  if (draft.conditions.length === 0 || draft.conditions.some((c) => c.field !== 'attachments' && !c.value.trim())) problems.push('conditions')
  const a = draft.actions
  if (!a.folder && !a.labels?.length && !a.markRead && !a.star) problems.push('actions')
  return problems
}
