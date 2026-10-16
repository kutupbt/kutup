// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { TooltipProvider } from '@kutup/ui/components/tooltip'
import '../media/testI18n'

const ADA_CARD = { id: 'card-ada', draft: { name: 'Ada Lovelace', emails: [{ address: 'ada@a.test' }] } }
const holds = vi.fn<(me: unknown, account: { accountId: string }, address: string) => Promise<boolean>>()
vi.mock('@kutup/contacts-core/api', () => ({
  useContactLookup: () => ({ ready: true, find: (address: string) => (address.toLowerCase() === 'ada@a.test' ? ADA_CARD : undefined) }),
}))
vi.mock('@kutup/drive-core/identityPins', () => ({ holdsAddress: (...a: Parameters<typeof holds>) => holds(...a) }))
vi.mock('../../state/accountNames', () => ({ driveIdentity: () => Promise.resolve({ account: 'me@a.test' }) }))
vi.mock('./saveContactState', () => ({ useSaveContact: () => vi.fn() }))
vi.mock('@kutup/session/apps', () => ({ appUrl: (app: string, path = '/') => `https://${app}.test${path}` }))

const { ContactEntry } = await import('./ContactEntry')
const { NotInContactsBanner } = await import('./NotInContactsBanner')

const ADA = 'aci:00000000-0000-4000-8000-00000000000a@a.test'
const MALLORY = 'aci:00000000-0000-4000-8000-0000000000ff@a.test'

function show(ui: React.ReactNode) {
  return render(
    <QueryClientProvider client={new QueryClient()}>
      <TooltipProvider>{ui}</TooltipProvider>
    </QueryClientProvider>,
  )
}

afterEach(() => holds.mockReset())

describe('an address book card belongs to an account only when it holds the address', () => {
  it('shows Ada her card', async () => {
    holds.mockResolvedValue(true)
    show(<ContactEntry peer={ADA} address="ada@a.test" />)
    expect(await screen.findByTestId('chat-in-contacts')).toBeVisible()
    expect(holds).toHaveBeenCalledWith(expect.anything(), { server: 'a.test', accountId: '00000000-0000-4000-8000-00000000000a' }, 'ada@a.test')
  })

  it("never gives Mallory, at the name Ada left, Ada's card, nor offers it again", async () => {
    holds.mockResolvedValue(false)
    const { container } = show(<ContactEntry peer={MALLORY} address="ada@a.test" />)
    await vi.waitFor(() => expect(holds).toHaveBeenCalled())
    await new Promise((resolve) => setTimeout(resolve, 0))
    expect(screen.queryByTestId('chat-in-contacts')).toBeNull()
    expect(screen.queryByTestId('chat-save-contact')).toBeNull()
    expect(container).toBeEmptyDOMElement()
  })

  it('the banner offers saving someone with no card, and stays away from a taken card', async () => {
    holds.mockResolvedValue(false)
    show(<NotInContactsBanner peer={MALLORY} address="ada@a.test" />)
    await vi.waitFor(() => expect(holds).toHaveBeenCalled())
    expect(screen.queryByTestId('chat-not-in-contacts')).toBeNull()
    show(<NotInContactsBanner peer={MALLORY} address="mallory@a.test" />)
    expect(await screen.findByTestId('chat-not-in-contacts')).toBeVisible()
  })
})
