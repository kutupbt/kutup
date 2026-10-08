import { useEffect, useState } from 'react'
import type { ChatHistoryEntry } from '@kutup/chat-core/types'
import { useChat } from '../app/chatStore'

/** How long typing settles before the index is asked. */
const SETTLE_MS = 150

/**
 * Candidates for the search on screen, from the core's search index
 * (`ChatService.searchCandidates`): asked again once typing settles and
 * after every change. `null` until the first answer; the previous answer
 * stays while the next is on its way.
 */
export function useSearchCandidates(query: string): readonly ChatHistoryEntry[] | null {
  const { service, snapshot } = useChat()
  const [candidates, setCandidates] = useState<readonly ChatHistoryEntry[] | null>(null)
  useEffect(() => {
    if (!service) return
    let current = true
    const timer = setTimeout(() => {
      void service.searchCandidates(query).then((entries) => {
        if (current) setCandidates(entries)
      }).catch((error: unknown) => console.warn('chat: could not search', error))
    }, SETTLE_MS)
    return () => {
      current = false
      clearTimeout(timer)
    }
  }, [service, query, snapshot.history])
  return candidates
}
