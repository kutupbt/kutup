import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { revisionGuard } from '@kutup/crypto'
import api from '@kutup/session/client'
import { useRequiredSession } from '@kutup/session/store'
import { mailKey, useMailAccount } from './api'
import { isRevisionConflict, MAIL_NAME_SCOPE, openGuardedName, sealGuardedName } from './places'

// Mail filters (docs/plans/mail-filters.md, F2), as Proton's simple
// filters. The server runs them as mail arrives, so conditions and actions
// are readable to it; the name is sealed here like folder names, with its
// revision, and a rename names the revision it started from.

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
  /** The revision of the sealed name (0 when it did not open). */
  nameRevision: number
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
    queryFn: () => loadFilters(session),
  })
}

interface FilterTools {
  seal: (id: string, name: string) => Promise<string>
  /** Renames on top of the name it started from; once more over a newer one if another device renamed first. */
  rename: (id: string, name: string, patch: (body: { name: string; baseNameRevision: number }) => Promise<unknown>) => Promise<void>
}

/** The account's filters, read now, with their names opened. */
async function loadFilters(session: { masterKey: Uint8Array; envelopeBinding: string; userId: string }): Promise<MailFilter[]> {
  const { data } = await api.get<Omit<MailFilter, 'nameRevision'>[]>('/mail/filters')
  return Promise.all(
    data.map(async (filter) => {
      const opened = await openGuardedName(session, 'filter', filter.id, filter.name)
      return { ...filter, name: opened?.name ?? '…', nameRevision: opened?.revision ?? 0 }
    }),
  )
}

function useFilterMutation<T, R>(fn: (input: T, tools: FilterTools) => Promise<R>) {
  const session = useRequiredSession()
  const account = useMailAccount()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (input: T) => {
      const address = account.data?.address
      if (!address) throw new Error('mail is not ready')
      const key = [...filtersKey, address]
      let filters = queryClient.getQueryData<MailFilter[]>(key)
      const baseOf = (id: string) => filters?.find((f) => f.id === id)?.nameRevision ?? 0
      return fn(input, {
        seal: async (id, name) => (await sealGuardedName(session, 'filter', id, name)).sealed,
        rename: async (id, name, patch) => {
          for (let attempt = 0; ; attempt++) {
            const base = baseOf(id)
            const { sealed, revision } = await sealGuardedName(session, 'filter', id, name, base)
            try {
              await patch({ name: sealed, baseNameRevision: base })
              await revisionGuard(session).accept(MAIL_NAME_SCOPE, `filter:${id}`, revision)
              return
            } catch (error) {
              if (attempt > 0 || !isRevisionConflict(error)) throw error
              // Read again now, also when no page shows the filters.
              filters = await queryClient.fetchQuery({ queryKey: key, queryFn: () => loadFilters(session), staleTime: 0 })
            }
          }
        },
      })
    },
    onSettled: () => queryClient.invalidateQueries({ queryKey: filtersKey }),
  })
}

export type FilterDraft = Pick<MailFilter, 'name' | 'match' | 'conditions' | 'actions'> & {
  enabled?: boolean
  source?: MailFilter['source']
  /** The new filter's id, made once by the caller: a second save of the same draft is refused (409), never a second filter. */
  id?: string
}

export function useCreateFilter() {
  return useFilterMutation(async (draft: FilterDraft, { seal }) => {
    const { id = crypto.randomUUID(), name, ...rest } = draft
    await api.post('/mail/filters', { id, name: await seal(id, name.trim()), ...rest })
    return id
  })
}

export function useUpdateFilter() {
  return useFilterMutation(async (input: Partial<FilterDraft> & { id: string }, { rename }) => {
    // The source is fixed when a filter is made.
    const { id, name, enabled, match, conditions, actions } = input
    const rest = { enabled, match, conditions, actions }
    if (name === undefined) await api.patch(`/mail/filters/${id}`, rest)
    else await rename(id, name.trim(), (body) => api.patch(`/mail/filters/${id}`, { ...rest, ...body }))
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
