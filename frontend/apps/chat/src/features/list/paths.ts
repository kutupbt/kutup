import { conversationKey, directConversation, parseAccount, type AccountRef } from '@kutup/chat-core/identity'
import type { ConversationId } from '@kutup/chat-core/types'

/** Where a conversation opens: `/c/<conversation key>`. */
export function conversationPath(key: string): string {
  return `/c/${encodeURIComponent(key)}`
}

export function pathForConversation(conversation: ConversationId): string {
  return conversationPath(conversationKey(conversation))
}

export function pathForAccount(account: AccountRef): string {
  return pathForConversation(directConversation(account))
}

/** The conversation a key names (`direct:aci:<uuid>@<server>` or `group:<id>`), if valid. */
export function parseConversationKey(key: string): ConversationId | null {
  if (key.startsWith('direct:')) {
    const account = parseAccount(key.slice('direct:'.length))
    return account ? directConversation(account) : null
  }
  if (key.startsWith('group:')) {
    const groupId = key.slice('group:'.length)
    return /^[A-Za-z0-9_-]{8,128}$/.test(groupId) ? { kind: 'group', groupId } : null
  }
  return null
}
