import { useQuery } from '@tanstack/react-query'
import api from '@/api/client'
import type { ChatCapabilities } from './types'
import { parseAccountAddress } from './identity'

const PROTOCOL_VERSION = 1
const REQUIRED_SUITE = 1

export function isSupportedChat(capabilities: ChatCapabilities | null | undefined): boolean {
  const serverName = capabilities?.serverName
  const canonicalServer = serverName
    ? parseAccountAddress(`server@${serverName}`)?.server === serverName
    : false
  return Boolean(
    capabilities?.enabled &&
      capabilities.protocolVersion === PROTOCOL_VERSION &&
      capabilities.suites?.includes(REQUIRED_SUITE) &&
      capabilities.manifests &&
      (!capabilities.federation || canonicalServer),
  )
}

/** One cached capability decision shared by navigation and the route gate. */
export function useChatCapabilities() {
  return useQuery({
    queryKey: ['public-settings', 'chat'],
    queryFn: () =>
      api
        .get<{ chat: ChatCapabilities }>('/auth/settings')
        .then((response) => response.data.chat),
    staleTime: 5 * 60 * 1000,
  })
}
