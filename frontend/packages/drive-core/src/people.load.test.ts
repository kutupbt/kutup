import { beforeEach, describe, expect, it, vi } from 'vitest'

// The exchange with the people you share with, end to end through the
// transport: profiles are fetched and opened by account, never by address.

const get = vi.fn<(url: string, config?: unknown) => Promise<{ data: unknown }>>()
const put = vi.fn<(url: string, body?: unknown) => Promise<{ data: unknown }>>()
vi.mock('@kutup/session/client', () => ({ default: { get: (...a: [string, unknown?]) => get(...a), put: (...a: [string, unknown?]) => put(...a) } }))

const wasm = {
  accountProfileKey: vi.fn(() => ({ version: 'own-v', key: 'b3du', accessKey: 'own-access' })),
  profileLookup: vi.fn(() => ({ version: 'v/1', key: 'cGVlcg==', accessKey: 'peer-access' })),
  profileOpenPeer: vi.fn(() => ({ displayName: 'Ada Lovelace' })),
}
vi.mock('@kutup/chat-core/wasm', () => ({ loadChatWasm: () => Promise.resolve(wasm) }))
vi.mock('@kutup/crypto', () => ({
  fromBase64: (value: string) => new TextEncoder().encode(value),
  toBase64: () => 'a2V5',
  openProfileKeyEnvelope: vi.fn(() => Promise.resolve(new Uint8Array(32))),
  sealProfileKeyEnvelope: vi.fn(() => Promise.resolve('sealed-envelope')),
}))

const { loadPeople } = await import('./people')

const ADA_ID = '00000000-0000-4000-8000-000000000001'
const ME = {
  userId: '00000000-0000-4000-8000-00000000000e',
  account: 'me@kutup.dev',
  accountRef: { server: 'kutup.dev', accountId: '00000000-0000-4000-8000-00000000000e' },
  binding: 'binding',
  incarnationId: 'inc-me',
  masterKey: new Uint8Array(32),
  privateKey: new Uint8Array(32),
  authorityPublicKey: 'auth-me',
}

beforeEach(() => {
  get.mockReset()
  put.mockReset()
  for (const fn of Object.values(wasm)) fn.mockClear()
  get.mockImplementation((url) => {
    if (url === '/drive/people') {
      return Promise.resolve({
        data: {
          people: [
            {
              server: 'kutup.dev',
              accountId: ADA_ID,
              account: 'ada_l@kutup.dev',
              local: true,
              accountIncarnationId: 'inc-ada',
              drivePublicKey: 'hpke-ada',
              driveSigningPublicKey: 'sign-ada',
              receivedEnvelope: 'from-ada',
              sentProfileVersion: null,
            },
          ],
        },
      })
    }
    if (url === '/chat/profile') return Promise.resolve({ data: { sealed: 'own' } })
    return Promise.resolve({ data: { encrypted: 'profile' } })
  })
  put.mockResolvedValue({ data: {} })
})

describe('loadPeople', () => {
  it('reads a profile through the account route and opens it for the account key', async () => {
    const people = await loadPeople(ME)
    expect(get).toHaveBeenCalledWith(`/chat/accounts/${ADA_ID}/profile/v%2F1`, {
      params: { server: 'kutup.dev' },
      headers: { 'x-kutup-profile-access-key': 'peer-access' },
    })
    expect(wasm.profileOpenPeer).toHaveBeenCalledWith(`aci:${ADA_ID}@kutup.dev`, { encrypted: 'profile' }, 'cGVlcg==')
    expect(people.byAccount.get(`aci:${ADA_ID}@kutup.dev`)).toEqual({ displayName: 'Ada Lovelace' })
    // The address is only an index to the account.
    expect(people.accountAt.get('ada_l@kutup.dev')).toBe(`aci:${ADA_ID}@kutup.dev`)
    expect(get.mock.calls.some(([url]) => url.includes('ada_l'))).toBe(false)
  })

  it('opens its own profile key for its own account key, and gives it to them by account', async () => {
    await loadPeople(ME)
    expect(wasm.accountProfileKey).toHaveBeenCalledWith(ME.masterKey, { sealed: 'own' }, `aci:${ME.userId}@kutup.dev`, 'binding')
    expect(put).toHaveBeenCalledWith('/drive/profile-keys', {
      recipientServer: 'kutup.dev',
      recipientAccountId: ADA_ID,
      envelope: 'sealed-envelope',
      profileVersion: 'own-v',
    })
  })
})
