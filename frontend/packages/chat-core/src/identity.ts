import { accountKeyOf, accountOfKey, sameAccount, type AccountRef } from '@kutup/crypto/accountRef'
import type { ConversationId } from './types'

export type { AccountRef }
export { sameAccount }

// Who a chat is with is an account (docs/plans/account-ids.md): its server
// and permanent id, Signal's ACI. An address is what a person types or
// shares; it can change and can later belong to someone else, so it only
// leads to an account (`resolveAddress`) and is never kept as one.

/** An address as typed or shared, `username@server`: a lookup handle. */
export interface TypedAddress {
  username: string
  server: string
}

const USERNAME = /^[a-z0-9_-]{3,32}$/
const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/

/**
 * Parse an address, `username@server` (or a `kutup://contact/` link to
 * one). A bare username is not an address.
 */
export function parseAddress(value: string): TypedAddress | null {
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
 * username, which names an address on this (home) server.
 */
export function parseAddressInput(value: string, homeServer: string): TypedAddress | null {
  const trimmed = value.trim()
  return parseAddress(
    trimmed.includes('@') || trimmed.startsWith('kutup://') ? trimmed : `${trimmed}@${homeServer}`,
  )
}

export function addressString(address: TypedAddress): string {
  return `${address.username}@${address.server}`
}

/** A link that shares an address (what a QR code or a profile shows). */
export function contactUri(address: TypedAddress): string {
  return `kutup://contact/${encodeURIComponent(addressString(address))}`
}

/** An account's key, `aci:<uuid>@<server>`: store keys, routes, senders. Never shown. */
export function accountKey(account: AccountRef): string {
  return accountKeyOf(account)
}

/** Whether `account` is a canonical reference (lowercase id, valid server). */
export function isAccount(account: AccountRef): boolean {
  return parseAccount(`aci:${account.accountId}@${account.server}`) !== null
}

/** The account a key names; null for anything else, an address included. */
export function parseAccount(value: string): AccountRef | null {
  return accountOfKey(value)
}

export function directConversation(account: AccountRef): ConversationId {
  return { kind: 'direct', account }
}

export function conversationKey(conversation: ConversationId): string {
  return conversation.kind === 'direct'
    ? `direct:${accountKeyOf(conversation.account)}`
    : `group:${conversation.groupId}`
}

/** The other account's key in a direct chat (`aci:<uuid>@<server>`); null for a group. */
export function directKey(conversation: ConversationId): string | null {
  return conversation.kind === 'direct' ? accountKeyOf(conversation.account) : null
}

/** The other account of a direct chat; null for a group. */
export function directAccount(conversation: ConversationId): AccountRef | null {
  return conversation.kind === 'direct' ? conversation.account : null
}
