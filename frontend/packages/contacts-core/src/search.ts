import { useQuery } from '@tanstack/react-query'
import api from '@kutup/session/client'

// Contact suggestions for other apps' pickers. Kept apart from api.ts so a
// picker does not pull the vCard parser and contact crypto into its app.

export interface ContactEmailMatch {
  contactId: string
  name: string
  address: string
  label: string | null
}

/** Addresses matching `q` (name or address), for recipient and share pickers. */
export function useContactEmailSearch(q: string, enabled = true) {
  return useQuery({
    queryKey: ['contacts', 'emails', q],
    enabled,
    staleTime: 30_000,
    queryFn: async () => (await api.get<ContactEmailMatch[]>('/contacts/emails', { params: { q, limit: 20 } })).data,
  })
}
