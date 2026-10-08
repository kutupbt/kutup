import { useEffect, useState } from 'react'
import type { ChatHistoryEntry } from '@kutup/chat-core/types'
import { useChat } from '../app/chatStore'

/**
 * The whole history, for the one view that needs it (search; until the
 * search index of Phase 3). Read only while mounted, once per change: the
 * service shares one load per change.
 */
export function useFullHistory(): readonly ChatHistoryEntry[] {
  const { service, snapshot } = useChat()
  const [history, setHistory] = useState<readonly ChatHistoryEntry[]>(snapshot.history)
  useEffect(() => {
    if (!service) return
    let current = true
    void service.history().then((entries) => {
      if (current) setHistory(entries)
    }).catch((error: unknown) => console.warn('chat: could not read the history', error))
    return () => {
      current = false
    }
  }, [service, snapshot.history])
  return history
}
