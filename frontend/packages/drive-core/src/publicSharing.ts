// Whether this account may make public links now
// (docs/plans/server-personal-data.md, A11): an administrator can turn them
// off for the whole server or for one account. The share dialogs say so in
// place of the button; a refusal that races a change says the same.

import { useQuery } from '@tanstack/react-query'
import { isAxiosError } from 'axios'
import { loadServerSettings } from '@kutup/session/apps'
import api from '@kutup/session/client'

/** Why public links are off: for the whole server, or for this account. */
export type SharingOff = 'site' | 'account'

/** Whether public links are off for the signed-in account, and why (null: they're on). */
export function usePublicSharing() {
  return useQuery({
    queryKey: ['publicSharing'],
    queryFn: async (): Promise<SharingOff | null> => {
      const settings = await loadServerSettings<{ publicSharing?: string }>()
      if (settings.publicSharing === 'off') return 'site'
      const { data } = await api.get<{ publicSharing?: string }>('/user/me')
      return data.publicSharing === 'off' ? 'account' : null
    },
    staleTime: 60_000,
  })
}

/** A new link refused because the server's operators blocked links to its target. */
export function isTargetBlocked(error: unknown): boolean {
  return isAxiosError(error) && (error.response?.data as { code?: string } | undefined)?.code === 'targetBlocked'
}

/** The scope of a `403 sharing_off` refusal; null for any other error. */
export function sharingOffScope(error: unknown): SharingOff | null {
  if (!isAxiosError(error)) return null
  const data = error.response?.data as { code?: string; scope?: string } | undefined
  if (data?.code !== 'sharing_off') return null
  return data.scope === 'account' ? 'account' : 'site'
}
