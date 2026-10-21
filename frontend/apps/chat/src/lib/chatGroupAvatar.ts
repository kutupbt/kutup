import { useEffect, useState } from 'react'
import type { ChatGroupAvatar, ChatGroupSummary } from '@kutup/chat-core/types'
import { useChat } from '../app/chatStore'

// Pictures by their blob's hash: a group's picture is fetched once per
// change of picture, and every view of the group shares it.
const pictures = new Map<string, ChatGroupAvatar | null>()
const pending = new Map<string, Promise<ChatGroupAvatar | null>>()

/** A pairwise group's picture, once fetched; null meanwhile, or when it has none. */
export function useChatGroupAvatar(group: ChatGroupSummary | null | undefined): ChatGroupAvatar | null {
  const { service } = useChat()
  const groupId = group?.status === 'member' ? group.groupId : null
  const hash = groupId ? (group?.avatarHash ?? null) : null
  const [picture, setPicture] = useState<ChatGroupAvatar | null>(() => (hash ? (pictures.get(hash) ?? null) : null))

  useEffect(() => {
    if (!service || !groupId || !hash) {
      setPicture(null)
      return
    }
    if (pictures.has(hash)) {
      setPicture(pictures.get(hash) ?? null)
      return
    }
    let current = true
    let request = pending.get(hash)
    if (!request) {
      request = service
        .chatGroupAvatar(groupId)
        .then((fetched) => {
          // Not cached when the home couldn't be reached: asked again later.
          if (fetched.kind === 'unreachable') return null
          const value = fetched.kind === 'image' ? { data: fetched.data, contentType: fetched.contentType } : null
          pictures.set(hash, value)
          return value
        })
        .catch((error: unknown) => {
          console.warn('chat: the group picture could not be read', error)
          return null
        })
        .finally(() => pending.delete(hash))
      pending.set(hash, request)
    }
    void request.then((value) => current && setPicture(value))
    return () => {
      current = false
    }
  }, [service, groupId, hash])
  return picture
}
