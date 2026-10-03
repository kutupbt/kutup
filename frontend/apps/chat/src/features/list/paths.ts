import { conversationKey, directConversation, parseAccountAddress } from '@kutup/chat-core/identity'
import type { AccountAddress, ConversationId } from '@kutup/chat-core/types'

/** Where a conversation opens: `/c/<conversation key>`. */
export function conversationPath(key: string): string {
  return `/c/${encodeURIComponent(key)}`
}

export function pathForConversation(conversation: ConversationId): string {
  return conversationPath(conversationKey(conversation))
}

export function pathForAddress(address: AccountAddress): string {
  return pathForConversation(directConversation(address))
}

/** The conversation a key names (`direct:<address>` or `group:<id>`), if valid. */
export function parseConversationKey(key: string): ConversationId | null {
  if (key.startsWith('direct:')) {
    const address = parseAccountAddress(key.slice('direct:'.length))
    return address ? directConversation(address) : null
  }
  if (key.startsWith('group:')) {
    const groupId = key.slice('group:'.length)
    return /^[A-Za-z0-9_-]{8,128}$/.test(groupId) ? { kind: 'group', groupId } : null
  }
  return null
}
