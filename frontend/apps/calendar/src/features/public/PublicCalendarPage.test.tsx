import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import '../sharing/testI18n'

const pub = vi.hoisted(() => ({
  link: undefined as object | undefined,
  opened: vi.fn(),
  busy: [] as unknown[],
}))
vi.mock('./publicClient', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./publicClient')>()
  return {
    ...actual,
    loadPublicLink: () => Promise.resolve(pub.link),
    openPublicCalendar: (linkId: string, link: unknown, secret: string) => {
      pub.opened(linkId, link, secret)
      if (!secret) return Promise.reject(new actual.LinkKeyMissing())
      return Promise.resolve({ calendarId: 'cal', name: 'Family', description: '', keyring: new Map() })
    },
    closePublicCalendar: () => undefined,
    loadPublicEvents: () =>
      Promise.resolve({
        events: [{ id: 'e1', calendarId: 'cal', fields: { summary: 'Dinner', start: { utc: '2026-11-18T18:00:00Z' }, end: { utc: '2026-11-18T19:00:00Z' } }, startUtc: '2026-11-18T18:00:00Z', endUtc: '2026-11-18T19:00:00Z', fullDay: false, revision: 0, reminders: null, verified: false }],
        unreadable: 0,
      }),
    loadBusyBlocks: () => Promise.resolve(pub.busy),
  }
})
// Times in UTC, as given: the view's own zone is the test's.
vi.mock('@kutup/crypto/calendar', () => ({
  localToUtc: (local: string) => Promise.resolve(`${local}Z`),
  utcToLocal: (instant: string) => Promise.resolve(instant.replace('Z', '')),
}))
// Nothing on this page may touch the session.
vi.mock('@kutup/session/client', () => ({ default: new Proxy({}, { get: () => () => Promise.reject(new Error('the session client was used')) }) }))

const { PublicCalendarPage } = await import('./PublicCalendarPage')

function open(hash: string) {
  window.location.hash = hash
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={['/l/l1']}>
        <Routes>
          <Route path="/l/:linkId" element={<PublicCalendarPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date'] })
  vi.setSystemTime(new Date('2026-11-18T12:00:00Z'))
  pub.opened.mockReset()
  pub.busy = []
})

describe('a calendar link’s page', () => {
  it('opens a full link with the key in the fragment and lists the week’s events', async () => {
    pub.link = { calendarId: 'cal', kind: 'full', metadata: {}, keys: [] }
    open('#SECRET')
    expect(await screen.findByText('Family')).toBeInTheDocument()
    expect(pub.opened).toHaveBeenCalledWith('l1', pub.link, 'SECRET')
    expect(await screen.findByText('Dinner')).toBeInTheDocument()
  })

  it('shows a busy link’s blocks as busy, nothing more', async () => {
    pub.link = { calendarId: 'cal', kind: 'busy' }
    pub.busy = [{ startUtc: '2026-11-18T09:00:00Z', endUtc: '2026-11-18T10:00:00Z', fullDay: false }]
    open('')
    expect(await screen.findByText('Busy times')).toBeInTheDocument()
    expect(await screen.findByText('Busy')).toBeInTheDocument()
    expect(pub.opened).not.toHaveBeenCalled()
  })

  it('says a full link without its key is incomplete', async () => {
    pub.link = { calendarId: 'cal', kind: 'full', metadata: {}, keys: [] }
    open('')
    expect(await screen.findByText('This link is incomplete')).toBeInTheDocument()
  })

  it('sends a link for calendar apps to one', async () => {
    pub.link = { calendarId: 'cal', kind: 'query' }
    open('')
    expect(await screen.findByText('This link is for calendar apps')).toBeInTheDocument()
  })
})
