import { describe, expect, it, vi } from 'vitest'
import { CiphertextCacheRequestCoordinatorV1 } from './requestCoordinator'

describe('ciphertext cache request coordinator', () => {
  it('deduplicates exact concurrent requests and broadcasts progress', async () => {
    const coordinator = new CiphertextCacheRequestCoordinatorV1()
    let complete!: (value: string) => void
    const operation = vi.fn((_signal: AbortSignal, report: (value: {
      receivedBytes: number
      totalBytes: number
    }) => void) => new Promise<string>(resolve => {
      complete = resolve
      report({ receivedBytes: 5, totalBytes: 10 })
    }))
    const firstProgress = vi.fn()
    const secondProgress = vi.fn()
    const first = coordinator.request('exact-binding', operation, { onProgress: firstProgress })
    const second = coordinator.request('exact-binding', operation, { onProgress: secondProgress })
    await vi.waitFor(() => expect(operation).toHaveBeenCalledOnce())
    expect(firstProgress).toHaveBeenCalledWith({ receivedBytes: 5, totalBytes: 10 })
    expect(secondProgress).toHaveBeenCalledWith({ receivedBytes: 5, totalBytes: 10 })
    complete('available')
    await expect(Promise.all([first, second])).resolves.toEqual(['available', 'available'])
  })

  it('cancels one subscriber without aborting the shared transfer', async () => {
    const coordinator = new CiphertextCacheRequestCoordinatorV1()
    let complete!: (value: string) => void
    let operationSignal!: AbortSignal
    const operation = (signal: AbortSignal) => new Promise<string>(resolve => {
      operationSignal = signal
      complete = resolve
    })
    const firstController = new AbortController()
    const first = coordinator.request('same', operation, { signal: firstController.signal })
    const second = coordinator.request('same', operation)
    await vi.waitFor(() => expect(operationSignal).toBeDefined())
    firstController.abort()
    await expect(first).rejects.toMatchObject({ name: 'AbortError' })
    expect(operationSignal.aborted).toBe(false)
    complete('done')
    await expect(second).resolves.toBe('done')
  })

  it('aborts the underlying transfer after its final subscriber cancels', async () => {
    const coordinator = new CiphertextCacheRequestCoordinatorV1()
    const controller = new AbortController()
    let operationSignal!: AbortSignal
    const pending = coordinator.request('same', async signal => {
      operationSignal = signal
      await new Promise<void>((_resolve, reject) => {
        signal.addEventListener('abort', () => reject(
          new DOMException('underlying cancelled', 'AbortError'),
        ), { once: true })
      })
      return 'unreachable'
    }, { signal: controller.signal })
    await vi.waitFor(() => expect(operationSignal).toBeDefined())
    controller.abort()
    await expect(pending).rejects.toMatchObject({ name: 'AbortError' })
    expect(operationSignal.aborted).toBe(true)
  })

  it('does not start a useful transfer for an already-cancelled subscriber', async () => {
    const coordinator = new CiphertextCacheRequestCoordinatorV1()
    const controller = new AbortController()
    controller.abort()
    const operation = vi.fn(async (signal: AbortSignal) => {
      expect(signal.aborted).toBe(true)
      throw new DOMException('cancelled', 'AbortError')
    })
    await expect(coordinator.request('same', operation, { signal: controller.signal }))
      .rejects.toMatchObject({ name: 'AbortError' })
    await vi.waitFor(() => expect(operation).toHaveBeenCalledOnce())
  })
})
