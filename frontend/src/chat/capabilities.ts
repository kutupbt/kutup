import { useQuery } from '@tanstack/react-query'
import api from '@/api/client'
import type { ChatCapabilities } from './types'
import { parseAccountAddress } from './identity'
import { DIRECT_CHAT_SUITE, isDirectChatSuiteId } from './suites'

const PROTOCOL_VERSION = 1
const REQUIRED_SUITE = DIRECT_CHAT_SUITE.PqxdhTripleRatchetV1

export function isSupportedChat(capabilities: ChatCapabilities | null | undefined): boolean {
  const serverName = capabilities?.serverName
  const canonicalServer = serverName
    ? parseAccountAddress(`server@${serverName}`)?.server === serverName
    : false
  return Boolean(
    capabilities?.enabled &&
      capabilities.protocolVersion === PROTOCOL_VERSION &&
      Array.isArray(capabilities.suites) &&
      capabilities.suites.some(
        suite => isDirectChatSuiteId(suite) && suite === REQUIRED_SUITE,
      ) &&
      capabilities.manifests &&
      capabilities.profiles &&
      capabilities.keyTransparency &&
      /^[0-9a-f]{64}$/.test(capabilities.transparencyOperatorKeyId ?? '') &&
      Boolean(capabilities.transparencyOperatorPublicKey) &&
      (capabilities.transparencyWitnessQuorum ?? 0) <=
        (capabilities.transparencyWitnesses?.length ?? 0) &&
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
