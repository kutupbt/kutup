import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { renderHook, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import { describe, expect, it, vi } from 'vitest'

// Mail's account checks the own key lists strictly: a list older than one
// this device has seen stops Mail (it says the keys can't be trusted).
const strict = vi.hoisted(() => [] as unknown[])
vi.mock('./keyList', async (original) => {
  const actual = await original<typeof import('./keyList')>()
  return {
    ...actual,
    checkedAddresses: (_session: unknown, _rows: unknown, options?: { strict?: boolean }) => {
      strict.push(options?.strict)
      return Promise.reject(new actual.OwnKeyListRolledBack('ada@kutup.test'))
    },
  }
})
vi.mock('@kutup/session/client', () => ({
  default: {
    get: (path: string) => {
      if (path === '/mail/addresses') {
        return Promise.resolve({ data: [{ id: 'a', address: 'ada@kutup.test', state: 'active', keys: [{}], keyList: { data: 'd', signature: 's' } }] })
      }
      if (path === '/user/me') return Promise.resolve({ data: { server: 'kutup.test', accountId: 'me' } })
      return Promise.resolve({ data: null })
    },
  },
}))
vi.mock('@kutup/session/store', () => ({
  useRequiredSession: () => ({ sessionId: 's', address: 'ada@kutup.test', userId: 'me', masterKey: new Uint8Array(32) }),
}))
vi.mock('@kutup/crypto/accountRename', () => ({
  addressFolder: () => Promise.resolve((address: string) => address.toLowerCase()),
  foldAddress: (address: string) => Promise.resolve(address.toLowerCase()),
}))

const { useMailAccount } = await import('./api')
const { OwnKeyListRolledBack } = await import('./keyList')

function wrapper({ children }: { children: ReactNode }) {
  return <QueryClientProvider client={new QueryClient()}>{children}</QueryClientProvider>
}

describe('the mail account', () => {
  it('stops on an own key list older than one this device has seen', async () => {
    const { result } = renderHook(() => useMailAccount(), { wrapper })
    await waitFor(() => expect(result.current.isError).toBe(true), { timeout: 5_000 })
    expect(result.current.error).toBeInstanceOf(OwnKeyListRolledBack)
    expect(strict).toContain(true)
  })
})
