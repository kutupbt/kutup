import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { renderHook, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import { describe, expect, it, vi } from 'vitest'
import type { MailKeyListInput } from '@kutup/crypto'

// What the key page's mutations sign and send, end to end through the
// hooks: always the signed list's keys, never the server's rows.
const signed = vi.hoisted(() => [] as MailKeyListInput[])
const sent = vi.hoisted(() => [] as { method: string; url: string; body: unknown }[])
vi.mock('@kutup/crypto', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@kutup/crypto')>()),
  toBase64: () => 'master',
  signMailKeyList: (_master: string, input: MailKeyListInput) => {
    signed.push(input)
    return Promise.resolve({ ...input, data: 'data', signature: 'signature', hash: 'next' })
  },
  generateMailAddressKey: () => Promise.resolve({ publicKey: 'pk-dd', envelope: 'env-dd', fingerprint: 'dd', sha256Fingerprint: '04' }),
}))
vi.mock('@kutup/session/client', () => ({
  default: {
    put: (url: string, body: unknown) => {
      sent.push({ method: 'put', url, body })
      return Promise.resolve({ data: null })
    },
    post: (url: string, body: unknown) => {
      sent.push({ method: 'post', url, body })
      return Promise.resolve({ data: null })
    },
  },
}))
vi.mock('@kutup/session/store', () => ({
  useRequiredSession: () => ({ masterKey: new Uint8Array(32), envelopeBinding: 'binding', userId: 'me' }),
}))

const { useChangeKey, useNewKey } = await import('./mailKeys')

const a = { fingerprint: 'aa', sha256Fingerprint: '01', primary: true, flags: 3 }
const b = { fingerprint: 'bb', sha256Fingerprint: '02', primary: false, flags: 3 }
const row = (key: typeof a, listed = true) => ({ ...key, id: key.fingerprint, publicKey: '', privateKeyEnvelope: '', createdAt: '', listed })
// The server lists a key of its own as primary and marks `bb` compromised.
const address = {
  id: 'address',
  address: 'alice@kutup.test',
  state: 'active' as const,
  keys: [row({ ...a, primary: false }), row({ ...b, flags: 0 }), row({ fingerprint: 'cc', sha256Fingerprint: '03', primary: true, flags: 3 }, false)],
  keyList: { data: 'data', signature: 'signature' },
  verifiedList: { address: 'alice@kutup.test', sequence: 4, issuedAt: '2026-10-20T00:00:00Z', keys: [a, b], data: 'data', signature: 'signature', hash: 'current' },
}

function wrapper({ children }: { children: ReactNode }) {
  return <QueryClientProvider client={new QueryClient()}>{children}</QueryClientProvider>
}

describe('the key page signs only what the account signed before, and the one change', () => {
  it('marks a key obsolete over the signed entries', async () => {
    signed.length = 0
    const { result } = renderHook(() => useChangeKey(), { wrapper })
    result.current.mutate({ address, fingerprint: 'bb', change: { kind: 'obsolete', on: true } })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(signed).toEqual([expect.objectContaining({ sequence: 5, previousHash: 'current', keys: [a, { ...b, flags: 1 }] })])
  })

  it('adds a new primary to the signed entries alone', async () => {
    signed.length = 0
    sent.length = 0
    const { result } = renderHook(() => useNewKey(), { wrapper })
    result.current.mutate(address)
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(signed[0].keys.map((key) => [key.fingerprint, key.primary])).toEqual([
      ['aa', false],
      ['bb', false],
      ['dd', true],
    ])
    expect(sent.at(-1)).toMatchObject({ method: 'post', url: '/mail/addresses/address/keys' })
  })
})
