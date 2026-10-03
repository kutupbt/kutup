import api from '@kutup/session/client'
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
      Number.isInteger(capabilities.maximumActiveDevices) &&
      capabilities.maximumActiveDevices >= 1 &&
      capabilities.maximumActiveDevices <= 10 &&
      canonicalServer,
  )
}

/** The server's public Chat capability advertisement (`GET /auth/settings`). */
export async function fetchChatCapabilities(): Promise<ChatCapabilities | null> {
  const response = await api.get<{ chat?: ChatCapabilities | null }>('/auth/settings')
  return response.data.chat ?? null
}
