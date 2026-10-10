import { AxiosError } from 'axios'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const consume = vi.fn()
const request = vi.fn()
const restore = vi.fn()
const hasFork = vi.fn()
vi.mock('./apps', () => ({ loadAppDirectory: vi.fn(async () => ({})) }))
// Hoisted with the mock below, which uses it.
const { UnrequestedForkError } = vi.hoisted(() => ({ UnrequestedForkError: class extends Error {} }))
vi.mock('./fork', () => ({
  UnrequestedForkError,
  consumeFork: () => consume(),
  hasForkInLocation: () => hasFork(),
  requestFork: (app: string, returnTo?: string) => request(app, returnTo),
  pendingForkReturnTo: () => '/file/f1/n1',
}))
vi.mock('./persist', () => ({ restoreSession: () => restore() }))

import { bootChildApp, resetChildBootForTesting } from './childBoot'

beforeEach(() => {
  resetChildBootForTesting()
  vi.clearAllMocks()
  sessionStorage.clear()
  hasFork.mockReturnValue(false)
  restore.mockResolvedValue('none')
})

describe('bootChildApp', () => {
  it('consumes a fork in the URL', async () => {
    hasFork.mockReturnValue(true)
    consume.mockResolvedValue('/folders/x')
    expect(await bootChildApp('drive')).toEqual({ kind: 'ready', next: '/folders/x' })
    expect(request).not.toHaveBeenCalled()
  })

  it('restores a stored session without a round-trip', async () => {
    restore.mockResolvedValue('restored')
    expect(await bootChildApp('drive')).toEqual({ kind: 'ready' })
    expect(request).not.toHaveBeenCalled()
  })

  it('asks the account app when there is nothing to restore', async () => {
    expect(await bootChildApp('chat')).toEqual({ kind: 'redirecting' })
    expect(request).toHaveBeenCalledWith('chat', undefined)
  })

  it('asks for a fresh fork when a link cannot be redeemed', async () => {
    hasFork.mockReturnValue(true)
    consume.mockRejectedValue(new AxiosError('used', 'ERR', undefined, undefined, {
      status: 401, statusText: '', data: {}, headers: {}, config: {} as never,
    }))
    expect(await bootChildApp('drive')).toEqual({ kind: 'redirecting' })
  })

  it('stops bouncing between apps after repeated failures', async () => {
    // Each round-trip is a new page load.
    await bootChildApp('drive')
    resetChildBootForTesting()
    await bootChildApp('drive')
    resetChildBootForTesting()
    await expect(bootChildApp('drive')).rejects.toThrow(/keeps failing/)
    expect(request).toHaveBeenCalledTimes(2)
  })

  it('rethrows network failures instead of redirecting', async () => {
    hasFork.mockReturnValue(true)
    consume.mockRejectedValue(new AxiosError('Network Error', 'ERR_NETWORK'))
    await expect(bootChildApp('drive')).rejects.toBeInstanceOf(AxiosError)
    expect(request).not.toHaveBeenCalled()
  })

  it('starts once per page load, however often it is asked', async () => {
    hasFork.mockReturnValue(true)
    consume.mockImplementation(async () => {
      // The first start wipes the fork from the address.
      hasFork.mockReturnValue(false)
      return '/file/f1/n1'
    })
    const [first, second] = await Promise.all([bootChildApp('drive'), bootChildApp('drive')])
    expect(first).toEqual({ kind: 'ready', next: '/file/f1/n1' })
    // Where to go is said once.
    expect(second).toEqual({ kind: 'ready' })
    expect(consume).toHaveBeenCalledTimes(1)
    expect(request).not.toHaveBeenCalled()
  })

  it("ignores someone else's link: keeps this browser's own session", async () => {
    hasFork.mockReturnValue(true)
    consume.mockRejectedValue(new UnrequestedForkError())
    restore.mockResolvedValue('restored')
    expect(await bootChildApp('drive')).toEqual({ kind: 'ready', next: '/' })
    expect(request).not.toHaveBeenCalled()
  })

  it("ignores someone else's link: signs in afresh when there is no session", async () => {
    hasFork.mockReturnValue(true)
    consume.mockRejectedValue(new UnrequestedForkError())
    expect(await bootChildApp('drive')).toEqual({ kind: 'redirecting' })
    expect(request).toHaveBeenCalledWith('drive', '/')
  })

  it('asks again for the link that was wanted when a fork cannot be used', async () => {
    hasFork.mockReturnValue(true)
    consume.mockRejectedValue(new AxiosError('gone', undefined, undefined, undefined, { status: 404 } as never))
    expect(await bootChildApp('drive')).toEqual({ kind: 'redirecting' })
    expect(request).toHaveBeenCalledWith('drive', '/file/f1/n1')
  })
})
