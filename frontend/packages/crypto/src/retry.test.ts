import { describe, expect, it, vi } from 'vitest'
import { failedModuleUrl, freshUrl, isLoadFailure, LoadFailure, retryLoad } from './retry'

const NO_WAIT = [0, 0, 0]
const cutOff = () => new TypeError('Failed to fetch dynamically imported module: https://account.kutup.dev/assets/libsodium-wrappers-Cgqskyi_.js')

describe('retryLoad', () => {
  it('succeeds on the second try', async () => {
    const attempt = vi.fn().mockRejectedValueOnce(cutOff()).mockResolvedValueOnce('ok')
    await expect(retryLoad(attempt, NO_WAIT)).resolves.toBe('ok')
    expect(attempt).toHaveBeenCalledTimes(2)
  })

  it('succeeds on the third try, numbering each', async () => {
    const attempt = vi.fn().mockRejectedValueOnce(cutOff()).mockRejectedValueOnce(new LoadFailure('worker')).mockResolvedValueOnce('ok')
    await expect(retryLoad(attempt, NO_WAIT)).resolves.toBe('ok')
    expect(attempt.mock.calls.map(([n]) => n)).toEqual([0, 1, 2])
  })

  it('never retries a real error', async () => {
    const attempt = vi.fn().mockRejectedValue(new Error('wrong password'))
    await expect(retryLoad(attempt, NO_WAIT)).rejects.toThrow('wrong password')
    expect(attempt).toHaveBeenCalledTimes(1)
  })

  it('gives up after the backoff runs out', async () => {
    const attempt = vi.fn().mockRejectedValue(cutOff())
    await expect(retryLoad(attempt, NO_WAIT)).rejects.toThrow(/Failed to fetch/)
    expect(attempt).toHaveBeenCalledTimes(4)
  })

  it('waits the backoff between tries', async () => {
    vi.useFakeTimers()
    try {
      const attempt = vi.fn().mockRejectedValueOnce(cutOff()).mockRejectedValueOnce(cutOff()).mockResolvedValueOnce('ok')
      const result = retryLoad(attempt, [500, 1000, 2000])
      await vi.advanceTimersByTimeAsync(499)
      expect(attempt).toHaveBeenCalledTimes(1)
      await vi.advanceTimersByTimeAsync(1)
      expect(attempt).toHaveBeenCalledTimes(2)
      await vi.advanceTimersByTimeAsync(1000)
      await expect(result).resolves.toBe('ok')
    } finally {
      vi.useRealTimers()
    }
  })
})

describe('load failures', () => {
  it('are told apart from real errors', () => {
    expect(isLoadFailure(cutOff())).toBe(true)
    expect(isLoadFailure(new TypeError('Failed to fetch'))).toBe(true)
    expect(isLoadFailure(new TypeError('Importing a module script failed.'))).toBe(true)
    expect(isLoadFailure(new LoadFailure('KDF worker could not start'))).toBe(true)
    expect(isLoadFailure(new TypeError('x is not a function'))).toBe(false)
    expect(isLoadFailure(new Error('decryption failed'))).toBe(false)
  })

  it('name the chunk to fetch again, under a fresh URL', () => {
    expect(failedModuleUrl(cutOff())).toBe('https://account.kutup.dev/assets/libsodium-wrappers-Cgqskyi_.js')
    expect(failedModuleUrl(new TypeError('error loading dynamically imported module: https://mail.kutup.dev/assets/main-1.js'))).toBe('https://mail.kutup.dev/assets/main-1.js')
    expect(failedModuleUrl(new TypeError('Importing a module script failed.'))).toBeNull()
    expect(freshUrl('https://a.test/x.js', 2)).toBe('https://a.test/x.js?retry=2')
    expect(freshUrl('https://a.test/x.js?v=2', 1)).toBe('https://a.test/x.js?v=2&retry=1')
  })
})
