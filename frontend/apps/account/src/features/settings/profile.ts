import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import axios from 'axios'
import { loadChatWasm } from '@kutup/chat-core/wasm'
import type { AccountProfileInput, AccountProfileView } from '@kutup/chat-core/types'
import api from '@kutup/session/client'
import { useRequiredSession } from '@kutup/session/store'

// The account's one profile (docs/plans/unified-profile.md): name, picture
// and "about", end-to-end encrypted. The server keeps sealed envelopes and
// the profile key wrapped under a key only the account master key derives;
// this app opens and re-seals them in the browser (the chat engine's Rust
// code, through its WASM), and the people you chat with read it with the
// profile key you share with them.

export const profileKey = ['profile'] as const

interface ChatSettings {
  chat?: { serverName?: string | null }
}

/** `username@server`: the address the profile belongs to. */
export function useAccountAddress(): string | null {
  const session = useRequiredSession()
  const { data } = useQuery({
    queryKey: ['auth-settings'],
    queryFn: async () => (await api.get<ChatSettings>('/auth/settings')).data,
    staleTime: Infinity,
  })
  const server = data?.chat?.serverName
  return session.username && server ? `${session.username.toLowerCase()}@${server}` : null
}

async function fetchSealed(): Promise<unknown> {
  try {
    return (await api.get('/chat/profile')).data
  } catch (error) {
    if (axios.isAxiosError(error) && error.response?.status === 404) return null
    throw error
  }
}

export interface OwnProfile {
  /** What the server holds, for the next revision. */
  sealed: unknown
  /** Opened; null before a first profile is saved. */
  view: AccountProfileView | null
}

export function useOwnProfile() {
  const session = useRequiredSession()
  const address = useAccountAddress()
  return useQuery({
    queryKey: [...profileKey, address],
    enabled: address !== null,
    queryFn: async (): Promise<OwnProfile> => {
      const sealed = await fetchSealed()
      if (!sealed) return { sealed: null, view: null }
      const wasm = await loadChatWasm()
      return { sealed, view: wasm.accountProfileOpen(session.masterKey, sealed, address!) }
    },
  })
}

export function useSaveProfile() {
  const session = useRequiredSession()
  const address = useAccountAddress()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (update: AccountProfileInput) => {
      if (!address) throw new Error('the account has no chat address yet')
      const wasm = await loadChatWasm()
      // Seal over what the server holds now, so another device's edit is
      // not lost to a stale copy.
      const current = await fetchSealed()
      const upload = wasm.accountProfileSeal(session.masterKey, current, update, address)
      await api.put('/chat/profile', upload)
    },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: profileKey }),
  })
}
