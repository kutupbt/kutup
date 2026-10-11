import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import api from '@kutup/session/client'

// Block, spam and allow lists (docs/plans/mail-filters.md, F3), as Proton's
// "incoming defaults": an address or a whole domain.

export type SenderRuleKind = 'spam' | 'block' | 'allow'

export interface SenderRule {
  id: string
  /** A lowercase address, or a domain. */
  pattern: string
  kind: SenderRuleKind
}

export const senderRulesKey = ['mail', 'sender-rules'] as const

export function useSenderRules() {
  return useQuery({
    queryKey: senderRulesKey,
    queryFn: async () => (await api.get<SenderRule[]>('/mail/sender-rules')).data,
  })
}

function useRuleMutation<T, R>(fn: (input: T) => Promise<R>) {
  const queryClient = useQueryClient()
  return useMutation({ mutationFn: fn, onSettled: () => queryClient.invalidateQueries({ queryKey: senderRulesKey }) })
}

/** Puts addresses or domains on a list (one already on another list moves). */
export function useSetSenderRules() {
  return useRuleMutation(async (input: { patterns: string[]; kind: SenderRuleKind }) => (await api.post<SenderRule[]>('/mail/sender-rules', input)).data)
}

export function useUpdateSenderRule() {
  return useRuleMutation(async (input: { id: string; kind: SenderRuleKind }) => {
    await api.patch(`/mail/sender-rules/${input.id}`, { kind: input.kind })
  })
}

export function useDeleteSenderRules() {
  return useRuleMutation(async (ids: string[]) => {
    await api.post('/mail/sender-rules/delete', { ids })
  })
}

/** Whether `value` reads as an address or a domain (the server checks it too). */
export function isSenderPattern(value: string): boolean {
  const v = value.trim().replace(/^@/, '')
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v) || /^[^\s@]+\.[^\s@]+$/.test(v)
}
