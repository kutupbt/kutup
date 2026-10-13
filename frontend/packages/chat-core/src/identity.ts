import type { AccountAddress, ConversationId } from './types'

const USERNAME = /^[a-z0-9_-]{3,32}$/
const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/

/**
 * Parse Kutup's canonical account syntax, `username@server` (or a
 * `kutup://contact/` link to one). A bare username is not an account address.
 */
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
  if (parts.length !== 2 || !USERNAME.test(parts[0] ?? '')) return null

  const server = parts[1]!.toLowerCase()
  if (
    !server ||
    server.length > 253 ||
    server.endsWith('.') ||
    // One rule with the server's: a DNS name with a dot, never an IP.
    !server.includes('.') ||
    /^\d{1,3}(?:\.\d{1,3}){3}$/.test(server) ||
    server.includes(':') ||
    !server.split('.').every((label) => DNS_LABEL.test(label))
  ) {
    return null
  }
  return { username: parts[0]!, server }
}

/**
 * Read what a person typed: a full address, a contact link, or a bare
 * username, which names an account on this (home) server.
 */
export function parseAccountInput(value: string, homeServer: string): AccountAddress | null {
  const trimmed = value.trim()
  return parseAccountAddress(
    trimmed.includes('@') || trimmed.startsWith('kutup://') ? trimmed : `${trimmed}@${homeServer}`,
  )
}

export function canonicalAccountAddress(address: AccountAddress): string {
  return `${address.username}@${address.server}`
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

export function contactUri(address: AccountAddress): string {
  return `kutup://contact/${encodeURIComponent(canonicalAccountAddress(address))}`
}
