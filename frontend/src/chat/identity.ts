import type { AccountAddress, ConversationId } from './types'

const USERNAME = /^[a-z0-9_-]{3,32}$/
const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/

/** Parse only Kutup's canonical account syntax: username or username@server. */
export function parseAccountAddress(value: string): AccountAddress | null {
  const trimmed = value.trim()
  let candidate = trimmed
  if (trimmed.startsWith('kutup://contact/')) {
    try {
      candidate = decodeURIComponent(trimmed.slice('kutup://contact/'.length))
    } catch {
      return null
    }
  }
  const parts = candidate.split('@')
  if (parts.length > 2 || !USERNAME.test(parts[0] ?? '')) return null
  if (parts.length === 1) return { username: parts[0]! }

  const server = parts[1]!.toLowerCase()
  if (
    !server ||
    server.length > 253 ||
    server.endsWith('.') ||
    /^\d{1,3}(?:\.\d{1,3}){3}$/.test(server) ||
    server.includes(':') ||
    !server.split('.').every((label) => DNS_LABEL.test(label))
  ) {
    return null
  }
  return { username: parts[0]!, server }
}

export function canonicalAccountAddress(address: AccountAddress): string {
  return address.server ? `${address.username}@${address.server}` : address.username
}

export function directConversation(address: AccountAddress): ConversationId {
  return { kind: 'direct', address }
}

export function conversationKey(conversation: ConversationId): string {
  return conversation.kind === 'direct'
    ? `direct:${canonicalAccountAddress(conversation.address)}`
    : `group:${conversation.groupId}`
}

export function directAddress(conversation: ConversationId): string | null {
  return conversation.kind === 'direct' ? canonicalAccountAddress(conversation.address) : null
}

/** Add this account's home server for display/links without changing the
 * legacy local libsignal/session key used by the current web database. */
export function withHomeServer(address: AccountAddress, homeServer?: string): AccountAddress {
  return !address.server && homeServer ? { ...address, server: homeServer } : address
}

/** Translate a canonical same-server address at the transport/core boundary. */
export function toCoreAccountAddress(address: AccountAddress, homeServer?: string): string {
  return address.server && address.server === homeServer
    ? address.username
    : canonicalAccountAddress(address)
}

export function contactUri(address: AccountAddress): string {
  return `kutup://contact/${encodeURIComponent(canonicalAccountAddress(address))}`
}
