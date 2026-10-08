// @vitest-environment jsdom
import { describe, expect, it, vi } from 'vitest'
import { act, renderHook, waitFor } from '@testing-library/react'
import type { ChatHistoryEntry } from '@kutup/chat-core/types'

/** A conversation of 350 messages, newest first, paged as the service does. */
const all: ChatHistoryEntry[] = Array.from({ length: 350 }, (_, i): ChatHistoryEntry => ({
  id: `m${350 - i}`,
  conversation: { kind: 'group', groupId: 'g1' },
  peer: '',
  direction: 'incoming',
  timestampMs: 350 - i,
  delivered: true,
  deduplicated: false,
  content: { version: 1, kind: 'text', sentAt: '', seq: '1', body: {}, text: '' },
}))

const conversationPage = vi.fn((_key: string, before: string | undefined, limit: number) => {
  const start = before === undefined ? 0 : all.findIndex((entry) => entry.id === before)
  const entries = all.slice(start, start + limit)
  return Promise.resolve({ entries, before: start + limit < all.length ? all[start + limit].id : undefined })
})
const chat = { service: { conversationPage }, snapshot: { history: [] } }

vi.mock('../app/chatStore', () => ({ useChat: () => chat }))

const { useThreadPages } = await import('./threadPages')

describe('useThreadPages', () => {
  it('reads older pages as asked, and lets them go back at the newest messages', async () => {
    const { result } = renderHook(() => useThreadPages('group:g1'))
    await waitFor(() => expect(result.current.entries).toHaveLength(100))

    for (const length of [200, 300]) {
      act(() => result.current.loadOlder())
      await waitFor(() => expect(result.current.entries).toHaveLength(length))
    }
    expect(result.current.entries.at(-1)?.id).toBe('m51')

    act(() => result.current.trim())
    await waitFor(() => expect(conversationPage).toHaveBeenLastCalledWith('group:g1', undefined, 100))
    expect(result.current.entries).toHaveLength(100)

    // Reading back continues from the newest page.
    await waitFor(() => {
      act(() => result.current.loadOlder())
      expect(conversationPage).toHaveBeenLastCalledWith('group:g1', 'm250', 100)
    })
    await waitFor(() => expect(result.current.entries).toHaveLength(200))
  })

  it('keeps a short thread as it is', async () => {
    conversationPage.mockClear()
    const { result } = renderHook(() => useThreadPages('group:g1'))
    await waitFor(() => expect(result.current.entries).toHaveLength(100))
    act(() => result.current.trim())
    expect(conversationPage).toHaveBeenCalledTimes(1)
  })
})
