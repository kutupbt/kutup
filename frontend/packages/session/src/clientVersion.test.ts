// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ClientTooOldError, clientFetch, clientHeaders, isClientTooOld, resetClientTooOld, setClientType, withClientParam } from './clientVersion'

afterEach(() => {
  resetClientTooOld()
  vi.unstubAllGlobals()
})

describe('the client version on raw requests', () => {
  it('names the app and its release on fetches and sockets', async () => {
    setClientType('web-chat')
    expect(clientHeaders()).toEqual({ 'X-Kutup-Client': 'web-chat/0.0.0-dev' })
    expect(withClientParam('wss://chat.example/api/chat/ws?ticket=t')).toBe(
      'wss://chat.example/api/chat/ws?ticket=t&client=web-chat%2F0.0.0-dev',
    )
    const fetch = vi.fn(async () => new Response('{}', { status: 200 }))
    vi.stubGlobal('fetch', fetch)
    await clientFetch('/api/x', { headers: { Authorization: 'Bearer a' } })
    const headers = new Headers((fetch.mock.calls[0] as unknown as [string, RequestInit])[1].headers)
    expect(headers.get('X-Kutup-Client')).toBe('web-chat/0.0.0-dev')
    expect(headers.get('Authorization')).toBe('Bearer a')
  })

  it('latches a 426 clientTooOld and refuses every later fetch', async () => {
    setClientType('web-drive')
    const fetch = vi.fn(async () => new Response(JSON.stringify({ code: 'clientTooOld', minimum: '2026.1120.0' }), { status: 426 }))
    vi.stubGlobal('fetch', fetch)
    await expect(clientFetch('/api/x')).rejects.toBeInstanceOf(ClientTooOldError)
    expect(isClientTooOld()).toBe(true)
    await expect(clientFetch('/api/y')).rejects.toBeInstanceOf(ClientTooOldError)
    expect(fetch).toHaveBeenCalledTimes(1)
  })
})
