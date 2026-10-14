import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { AxiosError, AxiosHeaders, type AxiosResponse } from 'axios'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import '../../testI18n'

const get = vi.hoisted(() => vi.fn())
const post = vi.hoisted(() => vi.fn())
const del = vi.hoisted(() => vi.fn())
const accountGrant = vi.hoisted(() => vi.fn())
const recheckAccount = vi.hoisted(() => vi.fn())
const signAccountRename = vi.hoisted(() => vi.fn())
const firstAddressKey = vi.hoisted(() => vi.fn())

vi.mock('@kutup/session/client', () => ({ default: { get, post, delete: del } }))
vi.mock('@kutup/session/reauth', async (original) => ({ ...(await original<object>()), accountGrant }))
vi.mock('@kutup/session/profile', () => ({ recheckAccount }))
vi.mock('@kutup/session/apps', () => ({
  loadServerSettings: () => Promise.resolve({ oldAddressReceiveDays: 90, nameHoldDays: 180 }),
}))
vi.mock('@kutup/crypto/accountRename', () => ({
  foldName: (name: string) => Promise.resolve(name.replace(/[._-]/g, '').toLowerCase()),
  signAccountRename,
}))
vi.mock('@kutup/crypto/identityPins', () => ({ signDriveKeyBinding: () => Promise.resolve('binding') }))
vi.mock('@kutup/mail-core/addressKey', () => ({ firstAddressKey }))
const session = { address: 'ada.l@kutup.test', username: 'ada.l', masterKey: new Uint8Array(32), envelopeBinding: 'b' }
vi.mock('@kutup/session/store', () => ({ useRequiredSession: () => session, getSession: () => session }))

const { UsernameSection } = await import('./UsernameSection')

function refused(status: number, data: object): AxiosError {
  const response = { status, data, headers: {}, config: { headers: new AxiosHeaders() }, statusText: '' } as AxiosResponse
  return new AxiosError('refused', String(status), undefined, undefined, response)
}

let me = { address: 'ada.l@kutup.test', renames: { sequence: 0 } }
let names: object[] = [{ name: 'ada.l', state: 'current', receiveUntil: null, freeAt: null }]
let check: object = { available: true, needsKey: true }

beforeEach(() => {
  vi.clearAllMocks()
  me = { address: 'ada.l@kutup.test', renames: { sequence: 0 } }
  names = [{ name: 'ada.l', state: 'current', receiveUntil: null, freeAt: null }]
  check = { available: true, needsKey: true }
  get.mockImplementation((path: string) => {
    if (path === '/user/me') return Promise.resolve({ data: me })
    if (path === '/user/names') return Promise.resolve({ data: names })
    if (path === '/user/rename/check') return Promise.resolve({ data: check })
    return Promise.reject(new Error(`unexpected ${path}`))
  })
  accountGrant.mockResolvedValue('grant-1')
  recheckAccount.mockResolvedValue(undefined)
  firstAddressKey.mockResolvedValue({ publicKey: 'pk', privateKeyEnvelope: 'env', keyList: { data: 'd', signature: 's' } })
  signAccountRename.mockImplementation((_key: string, sequence: number, previous: string, current: string) =>
    Promise.resolve({ incarnationId: 'i', sequence, previous, current, issuedAtMs: 1, signature: 'sig' }),
  )
})

function show() {
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <UsernameSection />
    </QueryClientProvider>,
  )
}

/** Waits for the name's status line to say `text`. */
async function said(dialog: HTMLElement, text: string) {
  await waitFor(() => expect(within(dialog).getByRole('status').textContent).toContain(text))
}

async function openAndType(name: string) {
  fireEvent.click(await screen.findByRole('button', { name: 'Change username' }))
  const dialog = await screen.findByRole('dialog')
  fireEvent.change(within(dialog).getByLabelText(/New username/), { target: { value: name } })
  return dialog
}

describe('the rename dialog', () => {
  it('says why a name cannot be had, and does not let it be sent', async () => {
    check = { available: false, reason: 'held' }
    show()
    const dialog = await openAndType('grace')
    await within(dialog).findByText('This name is held for its earlier owner.')
    expect(within(dialog).getByRole('button', { name: 'Change username' })).toBeDisabled()
  })

  it('takes another spelling of the current name for no change, without asking the server', async () => {
    show()
    const dialog = await openAndType('ada_l')
    await within(dialog).findByText('That is your username now.')
    expect(get.mock.calls.some(([path]) => path === '/user/rename/check')).toBe(false)
  })

  it('warns with the server windows, then sends the signed rename with the new address key', async () => {
    post.mockResolvedValue({
      data: { username: 'ada.lovelace', address: 'ada.lovelace@kutup.test', sequence: 1, oldAddressReceivesUntil: '', oldNameFreeAt: '' },
    })
    show()
    const dialog = await openAndType('ada.lovelace'.replace('.', '-'))
    await within(dialog).findByText(/will receive mail for 90 days and cannot send/)
    expect(within(dialog).getByText(/after 180 days someone else can take the name/)).toBeTruthy()
    fireEvent.change(within(dialog).getByLabelText(/Current password/), { target: { value: 'pw' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Change username' }))
    await waitFor(() => expect(post).toHaveBeenCalledTimes(1))
    expect(accountGrant).toHaveBeenCalledWith('pw', 'rename')
    expect(firstAddressKey).toHaveBeenCalledWith(session, 'ada-lovelace@kutup.test')
    const [path, body] = post.mock.calls[0] as [string, Record<string, unknown>]
    expect(path).toBe('/user/rename')
    expect(body).toMatchObject({
      grant: 'grant-1',
      rename: { sequence: 1, previous: 'ada.l@kutup.test', current: 'ada-lovelace@kutup.test' },
      driveKeyBinding: 'binding',
      mailAddress: { publicKey: 'pk' },
    })
    await waitFor(() => expect(recheckAccount).toHaveBeenCalled())
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
  })

  it('sends no key for a name taken back whose address kept its keys', async () => {
    check = { available: true, takeBack: true, needsKey: false }
    post.mockResolvedValue({ data: { username: 'ada', address: 'ada@kutup.test', sequence: 2, oldAddressReceivesUntil: '', oldNameFreeAt: '' } })
    show()
    const dialog = await openAndType('ada')
    await said(dialog, 'One of your earlier names: you can take it back.')
    fireEvent.change(within(dialog).getByLabelText(/Current password/), { target: { value: 'pw' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Change username' }))
    await waitFor(() => expect(post).toHaveBeenCalledTimes(1))
    expect(firstAddressKey).not.toHaveBeenCalled()
    expect((post.mock.calls[0] as [string, object])[1]).not.toHaveProperty('mailAddress')
  })

  it('signs once more on the chain another device moved, with the same grant', async () => {
    post.mockImplementationOnce(() => {
      // Another device renamed meanwhile: the chain is one longer now.
      me = { address: 'ada.x@kutup.test', renames: { sequence: 1 } }
      return Promise.reject(refused(409, { error: 'moved', code: 'renameConflict' }))
    })
    post.mockResolvedValueOnce({ data: { username: 'grace', address: 'grace@kutup.test', sequence: 2, oldAddressReceivesUntil: '', oldNameFreeAt: '' } })
    show()
    const dialog = await openAndType('grace')
    await said(dialog, 'Available.')
    fireEvent.change(within(dialog).getByLabelText(/Current password/), { target: { value: 'pw' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Change username' }))
    await waitFor(() => expect(post).toHaveBeenCalledTimes(2))
    expect(accountGrant).toHaveBeenCalledTimes(1)
    expect((post.mock.calls[1] as [string, { grant: string; rename: object }])[1]).toMatchObject({
      grant: 'grant-1',
      rename: { sequence: 2, previous: 'ada.x@kutup.test', current: 'grace@kutup.test' },
    })
    // The address key is the same whatever the chain says: made once.
    expect(firstAddressKey).toHaveBeenCalledTimes(1)
  })

  it('says when the next rename is allowed', async () => {
    post.mockRejectedValue(refused(429, { error: 'too soon', code: 'renameTooSoon', retryAt: '2026-11-14T10:00:00Z' }))
    show()
    const dialog = await openAndType('grace')
    await said(dialog, 'Available.')
    fireEvent.change(within(dialog).getByLabelText(/Current password/), { target: { value: 'pw' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Change username' }))
    await within(dialog).findByText(/You can change your username once every 30 days\. You can change it again on/)
  })
})

describe('the held names', () => {
  it('lists each with its dates and stops receiving with the password', async () => {
    const soon = new Date(Date.now() + 86_400_000).toISOString()
    names = [
      { name: 'ada.lovelace', state: 'current', receiveUntil: null, freeAt: null },
      { name: 'ada.l', state: 'held', receiveUntil: soon, freeAt: '2027-04-01T00:00:00Z' },
      { name: 'ada', state: 'held', receiveUntil: '2026-01-01T00:00:00Z', freeAt: '2027-01-01T00:00:00Z' },
    ]
    del.mockResolvedValue({ status: 204 })
    show()
    const list = await screen.findByRole('list', { name: 'Earlier names' })
    const items = within(list).getAllByRole('listitem')
    expect(items).toHaveLength(2)
    expect(within(items[1]!).getByText('No longer receives mail')).toBeTruthy()
    expect(within(items[1]!).queryByRole('button', { name: 'Stop receiving' })).toBeNull()
    fireEvent.click(within(items[0]!).getByRole('button', { name: 'Stop receiving' }))
    const dialog = await screen.findByRole('alertdialog')
    fireEvent.change(within(dialog).getByLabelText(/Current password/), { target: { value: 'pw' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Stop receiving' }))
    await waitFor(() => expect(del).toHaveBeenCalledWith('/user/names/ada.l', { data: { grant: 'grant-1' } }))
    expect(accountGrant).toHaveBeenCalledWith('pw', 'rename')
  })
})
