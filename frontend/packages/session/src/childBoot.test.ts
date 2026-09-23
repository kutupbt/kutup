import { AxiosError } from 'axios'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const consume = vi.fn()
const request = vi.fn()
const restore = vi.fn()
const hasFork = vi.fn()
vi.mock('./apps', () => ({ loadAppDirectory: vi.fn(async () => ({})) }))
vi.mock('./fork', () => ({
  consumeFork: () => consume(),
  hasForkInLocation: () => hasFork(),
  requestFork: (app: string) => request(app),
}))
vi.mock('./persist', () => ({ restoreSession: () => restore() }))

import { bootChildApp } from './childBoot'

beforeEach(() => {
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
    expect(request).toHaveBeenCalledWith('chat')
  })

  it('asks for a fresh fork when a link cannot be redeemed', async () => {
    hasFork.mockReturnValue(true)
    consume.mockRejectedValue(new AxiosError('used', 'ERR', undefined, undefined, {
      status: 401, statusText: '', data: {}, headers: {}, config: {} as never,
    }))
    expect(await bootChildApp('drive')).toEqual({ kind: 'redirecting' })
  })

  it('stops bouncing between apps after repeated failures', async () => {
    await bootChildApp('drive')
    await bootChildApp('drive')
    await expect(bootChildApp('drive')).rejects.toThrow(/keeps failing/)
    expect(request).toHaveBeenCalledTimes(2)
  })

  it('rethrows network failures instead of redirecting', async () => {
    hasFork.mockReturnValue(true)
    consume.mockRejectedValue(new AxiosError('Network Error', 'ERR_NETWORK'))
    await expect(bootChildApp('drive')).rejects.toBeInstanceOf(AxiosError)
    expect(request).not.toHaveBeenCalled()
  })
})
