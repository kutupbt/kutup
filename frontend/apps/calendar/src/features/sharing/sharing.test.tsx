import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { Calendar } from '@kutup/calendar-core/api'
import './testI18n'

// The sharing dialogs over a stand-in client (client.test.ts covers the
// client itself): what they offer, and how they handle a doubtful identity.

const client = vi.hoisted(() => ({
  settings: { queryLinksAllowed: true, membersPerCalendar: 49, linksPerCalendar: 5 },
  links: [] as unknown[],
  sharing: { members: [] as unknown[], invitations: [] as unknown[] },
  invitations: [] as unknown[],
  invite: vi.fn(),
  createLink: vi.fn(),
  openInvitation: vi.fn(),
  acceptInvitation: vi.fn(),
}))
vi.mock('./client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./client')>()
  return {
    ...actual,
    loadSharingSettings: () => Promise.resolve(client.settings),
    loadLinks: () => Promise.resolve(client.links),
    loadSharing: () => Promise.resolve(client.sharing),
    loadInvitations: () => Promise.resolve(client.invitations),
    invite: client.invite,
    createLink: client.createLink,
    openInvitation: client.openInvitation,
    acceptInvitation: client.acceptInvitation,
  }
})
vi.mock('@kutup/drive-core/identity', () => ({ useDriveIdentity: () => ({ data: { accountRef: { server: 'kutup.test', accountId: 'me' } } }) }))
vi.mock('@kutup/drive-ui/IdentityWarning', () => ({
  IdentityShareWarning: ({ onShareAnyway }: { onShareAnyway: () => void }) => (
    <button type="button" onClick={onShareAnyway}>
      share anyway
    </button>
  ),
}))
vi.mock('@kutup/mail-core/api', () => ({ useMailAccount: () => ({ data: {} }) }))
vi.mock('@kutup/session/store', () => ({ useRequiredSession: () => ({ sessionId: 's' }) }))
vi.mock('sonner', () => ({ toast: Object.assign(vi.fn(), { success: vi.fn(), error: vi.fn() }) }))

const { LinksPanel } = await import('./LinksPanel')
const { ShareCalendarDialog } = await import('./ShareCalendarDialog')
const { SharedWithYou } = await import('./SharedWithYou')
const { IdentityNotConfirmed, PersonNotConfirmed } = await import('./client')

const calendar = { id: 'cal-1', name: 'Team', owned: true } as unknown as Calendar

function wrap(node: ReactNode) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(<QueryClientProvider client={queryClient}>{node}</QueryClientProvider>)
}

beforeEach(() => {
  client.settings = { queryLinksAllowed: true, membersPerCalendar: 49, linksPerCalendar: 5 }
  client.links = []
  client.invitations = []
  client.sharing = { members: [], invitations: [] }
  for (const fn of [client.invite, client.createLink, client.openInvitation, client.acceptInvitation]) fn.mockReset()
})

describe('the link dialog', () => {
  it('starts on busy times only, and warns before a link whose key goes to the server', async () => {
    client.createLink.mockResolvedValue({ link: { id: 'l1', kind: 'query' }, urls: { ics: 'https://calendar.kutup.test/api/calendar/links/l1/calendar.ics?key=K' } })
    wrap(<LinksPanel calendar={calendar} />)
    await waitFor(() => expect(screen.getByTestId('link-create')).toBeEnabled())
    fireEvent.click(screen.getByTestId('link-create'))
    expect(screen.getByTestId<HTMLInputElement>('link-kind-busy').checked).toBe(true)
    expect(screen.queryByText('The server reads this calendar')).toBeNull()
    fireEvent.click(screen.getByTestId('link-kind-query'))
    expect(screen.getByText('The server reads this calendar')).toBeInTheDocument()
    fireEvent.click(screen.getByTestId('link-create-submit'))
    await waitFor(() => expect(client.createLink).toHaveBeenCalledWith(expect.anything(), calendar, 'query'))
    expect(await screen.findByTestId<HTMLInputElement>('link-url-ics')).toHaveValue('https://calendar.kutup.test/api/calendar/links/l1/calendar.ics?key=K')
  })

  it('offers no query link where the administrator disallows it', async () => {
    client.settings = { ...client.settings, queryLinksAllowed: false }
    wrap(<LinksPanel calendar={calendar} />)
    await waitFor(() => expect(screen.getByTestId('link-create')).toBeEnabled())
    fireEvent.click(screen.getByTestId('link-create'))
    expect(screen.getByTestId('link-kind-full')).toBeInTheDocument()
    expect(screen.queryByTestId('link-kind-query')).toBeNull()
  })

  it('creates no more links than the site allows', async () => {
    client.settings = { ...client.settings, linksPerCalendar: 1 }
    client.links = [{ id: 'l1', kind: 'busy', secret: null, createdAt: '2026-11-18T00:00:00Z' }]
    wrap(<LinksPanel calendar={calendar} />)
    expect(await screen.findByText('A calendar can have 1 link.')).toBeInTheDocument()
    expect(screen.getByTestId('link-create')).toBeDisabled()
  })
})

describe('sharing with people', () => {
  it('stops at a changed identity and shares only once the owner says so', async () => {
    client.invite.mockRejectedValueOnce(new IdentityNotConfirmed('bo@kutup.test', { kind: 'changed' })).mockResolvedValueOnce(undefined)
    wrap(<ShareCalendarDialog calendar={calendar} open onOpenChange={() => undefined} />)
    fireEvent.change(await screen.findByTestId('share-address'), { target: { value: 'bo@kutup.test' } })
    fireEvent.click(screen.getByTestId('share-invite'))
    fireEvent.click(await screen.findByText('share anyway'))
    await waitFor(() => expect(client.invite).toHaveBeenCalledTimes(2))
    expect(client.invite.mock.calls[0][5]).toBe(false)
    expect(client.invite.mock.calls[1][5]).toBe(true)
    // "See all event details" is the preset offered first, as Proton's.
    expect(client.invite.mock.calls[0][4]).toBe('view')
  })

  it('lists members with their preset, and invitations by state', async () => {
    client.sharing = {
      members: [{ accountId: 'b', address: 'bo@kutup.test', permissions: 112, addedAt: '' }],
      invitations: [{ id: 'i1', accountId: 'c', address: 'cy@kutup.test', permissions: 96, state: 'declined', createdAt: '', expiresAt: '' }],
    }
    wrap(<ShareCalendarDialog calendar={calendar} open onOpenChange={() => undefined} />)
    const list = await screen.findByTestId('share-members')
    expect(list).toHaveTextContent('bo@kutup.test')
    expect(list).toHaveTextContent('Edit event details')
    expect(list).toHaveTextContent('cy@kutup.test')
    expect(list).toHaveTextContent('Declined')
  })
})

describe('an invitation', () => {
  it('opens only after a doubtful owner is confirmed, and joins with it', async () => {
    const invitation = { id: 'inv', calendarId: 'c9', owner: { accountId: 'b', address: 'bo@kutup.test', incarnationId: 'i', signingPublicKey: 's' }, permissions: 112, metadata: {}, keys: [], createdAt: '', expiresAt: '' }
    client.openInvitation.mockImplementation((_s: unknown, _me: unknown, _inv: unknown, confirmed: boolean) =>
      confirmed ? Promise.resolve({ name: 'Team', description: '', ownerAddress: 'bo@kutup.test', preset: 'edit' }) : Promise.reject(new PersonNotConfirmed('bo@kutup.test', { kind: 'changed' })),
    )
    client.acceptInvitation.mockResolvedValue(undefined)
    client.invitations = [invitation]
    wrap(
      <ul>
        <SharedWithYou ownerChanged={[]} />
      </ul>,
    )
    fireEvent.click(await screen.findByTestId('calendar-invitation'))
    expect(await screen.findByText(/bo@kutup\.test's identity changed/)).toBeInTheDocument()
    expect(screen.getByTestId('invitation-join')).toBeDisabled()
    fireEvent.click(screen.getByTestId('invitation-open-anyway'))
    expect(await screen.findByText('Join Team')).toBeInTheDocument()
    fireEvent.click(screen.getByTestId('invitation-join'))
    await waitFor(() => expect(client.acceptInvitation).toHaveBeenCalled())
    expect(client.acceptInvitation.mock.calls[0][4]).toBe(true)
  })
})
