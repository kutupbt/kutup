import { useCallback, useEffect, useRef, useState } from 'react'
import type { ChatHistoryEntry } from '@kutup/chat-core/types'
import { useChat } from '../app/chatStore'

/**
 * Older pages of the conversation on screen, beyond the live window the
 * chat store keeps (`liveTimeline.ts`). Only the thread view sees them:
 * nothing that acts on new arrivals takes an old message for a new one.
 */

const PAGE = 100

interface ThreadPages {
  key: string | null
  /** Newest first. */
  entries: ChatHistoryEntry[]
  before?: string
  complete: boolean
}

export function useThreadPages(key: string | null): {
  entries: readonly ChatHistoryEntry[]
  complete: boolean
  loadOlder: () => void
} {
  const { service, snapshot } = useChat()
  const [pages, setPages] = useState<ThreadPages>({ key: null, entries: [], complete: false })
  const loading = useRef(false)

  // The newest page on opening and after every change: entries already
  // loaded that are older than it stay, so a page boundary that new
  // messages pushed back loses nothing.
  useEffect(() => {
    if (!service || !key) return
    let current = true
    void service.conversationPage(key, undefined, PAGE).then((page) => {
      if (!current) return
      setPages((previous) => {
        const newest = page.entries
        const oldest = newest.at(-1)?.timestampMs ?? Infinity
        const ids = new Set(newest.map((entry) => entry.id))
        const kept = previous.key === key
          ? previous.entries.filter((entry) => !ids.has(entry.id) && entry.timestampMs <= oldest)
          : []
        const reachedOlder = previous.key === key && kept.length > 0
        return {
          key,
          entries: [...newest, ...kept],
          before: reachedOlder ? previous.before : page.before,
          complete: reachedOlder ? previous.complete : page.before === undefined,
        }
      })
    }).catch((error: unknown) => console.warn('chat: could not read the conversation', error))
    return () => {
      current = false
    }
  }, [service, key, snapshot.history])

  const loadOlder = useCallback(() => {
    if (!service || !key || loading.current || pages.key !== key || pages.complete || !pages.before) return
    loading.current = true
    void service.conversationPage(key, pages.before, PAGE).then((page) => {
      setPages((previous) => previous.key !== key ? previous : {
        key,
        entries: [...previous.entries, ...page.entries.filter((entry) => !previous.entries.some((known) => known.id === entry.id))],
        before: page.before,
        complete: page.before === undefined,
      })
    }).catch((error: unknown) => console.warn('chat: could not read older messages', error))
      .finally(() => {
        loading.current = false
      })
  }, [service, key, pages])

  return {
    entries: pages.key === key ? pages.entries : [],
    complete: pages.key === key && pages.complete,
    loadOlder,
  }
}
