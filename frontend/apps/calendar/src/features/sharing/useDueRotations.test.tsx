import { act, renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

// The owner's key upkeep: a due rotation made unasked only for people the
// owner already trusts; otherwise, or when it fails, the calendar is listed
// for review (the row's "Key change pending — review").

const state = vi.hoisted(() => ({
  calendars: [] as unknown[],
  outcome: (): Promise<unknown> => Promise.resolve({ kind: 'rotated' }),
  compacted: [] as string[],
}))
vi.mock('@kutup/calendar-core/api', () => ({ useCalendars: () => ({ data: { calendars: state.calendars, unreadable: 0 } }) }))
vi.mock('@kutup/drive-core/identity', () => ({ useDriveIdentity: () => ({ data: { accountRef: {} } }) }))
vi.mock('@kutup/mail-core/api', () => ({ useMailAccount: () => ({ data: { key: 'k' } }) }))
vi.mock('@kutup/session/store', () => ({ useRequiredSession: () => ({ sessionId: 's' }) }))
vi.mock('./client', () => ({
  COMPACT_AT: 0.9,
  dueRotation: () => state.outcome(),
  keyGenerationCap: () => Promise.resolve(10),
  compactKeys: (calendar: { id: string }) => {
    state.compacted.push(calendar.id)
    return Promise.resolve(1)
  },
}))

const { useKeyUpkeep } = await import('./useDueRotations')

function wrapper({ children }: { children: ReactNode }) {
  return <QueryClientProvider client={new QueryClient()}>{children}</QueryClientProvider>
}

const due = (id: string) => ({ id, owned: true, rotationDue: true, keyGenerations: 2 })

beforeEach(() => {
  state.calendars = []
  state.outcome = () => Promise.resolve({ kind: 'rotated' })
  state.compacted = []
})

describe('the owner’s key upkeep', () => {
  it('rotates unasked and lists nothing when everyone is trusted', async () => {
    state.calendars = [due('c1')]
    const { result } = renderHook(() => useKeyUpkeep(), { wrapper })
    await act(() => Promise.resolve())
    expect(result.current.pending.size).toBe(0)
  })

  it('lists a calendar for review when someone isn’t trusted, and when the rotation fails; settles it after', async () => {
    state.calendars = [due('c1'), due('c2')]
    let calls = 0
    state.outcome = () => (calls++ === 0 ? Promise.resolve({ kind: 'review', recipients: [] }) : Promise.reject(new Error('changed under it')))
    const { result } = renderHook(() => useKeyUpkeep(), { wrapper })
    await waitFor(() => expect([...result.current.pending].sort()).toEqual(['c1', 'c2']))
    act(() => result.current.settle('c1'))
    expect([...result.current.pending]).toEqual(['c2'])
  })

  it('compacts a calendar near the cap, and leaves one far from it', async () => {
    state.calendars = [
      { id: 'near', owned: true, rotationDue: false, keyGenerations: 9 },
      { id: 'far', owned: true, rotationDue: false, keyGenerations: 3 },
    ]
    renderHook(() => useKeyUpkeep(), { wrapper })
    await waitFor(() => expect(state.compacted).toEqual(['near']))
  })
})
