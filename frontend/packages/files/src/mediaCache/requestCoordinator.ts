export interface CacheRequestProgressV1 {
  receivedBytes: number
  totalBytes: number
}

export interface CacheRequestSubscriberV1 {
  signal?: AbortSignal
  onProgress?: (progress: CacheRequestProgressV1) => void
}

export type CoordinatedCacheOperationV1<T> = (
  signal: AbortSignal,
  report: (progress: CacheRequestProgressV1) => void,
) => Promise<T>

interface Subscriber<T> {
  resolve: (value: T) => void
  reject: (reason: unknown) => void
  onProgress?: (progress: CacheRequestProgressV1) => void
  signal?: AbortSignal
  abort?: () => void
}

interface SharedRequest<T> {
  controller: AbortController
  subscribers: Set<Subscriber<T>>
  lastProgress?: CacheRequestProgressV1
  settled: boolean
}

/** Deduplicates only exact caller-supplied binding keys. Each subscriber may
 * cancel independently; the underlying transfer stops after the final active
 * subscriber leaves. */
export class CiphertextCacheRequestCoordinatorV1 {
  private readonly active = new Map<string, SharedRequest<unknown>>()

  request<T>(
    bindingKey: string,
    operation: CoordinatedCacheOperationV1<T>,
    subscriberOptions: CacheRequestSubscriberV1 = {},
  ): Promise<T> {
    if (!bindingKey) return Promise.reject(new Error('cache request binding key is empty'))
    let shared = this.active.get(bindingKey) as SharedRequest<T> | undefined
    if (!shared) {
      shared = { controller: new AbortController(), subscribers: new Set(), settled: false }
      this.active.set(bindingKey, shared as SharedRequest<unknown>)
      const report = (progress: CacheRequestProgressV1) => {
        validateProgress(progress)
        shared!.lastProgress = progress
        for (const subscriber of shared!.subscribers) subscriber.onProgress?.(progress)
      }
      void Promise.resolve()
        .then(() => operation(shared!.controller.signal, report))
        .then(
          value => this.settle(bindingKey, shared!, subscriber => subscriber.resolve(value)),
          error => this.settle(bindingKey, shared!, subscriber => subscriber.reject(error)),
        )
    }
    return this.subscribe(shared, subscriberOptions)
  }

  cancelAll(): void {
    for (const shared of this.active.values()) shared.controller.abort()
  }

  private subscribe<T>(
    shared: SharedRequest<T>,
    options: CacheRequestSubscriberV1,
  ): Promise<T> {
    return new Promise((resolve, reject) => {
      const subscriber: Subscriber<T> = {
        resolve,
        reject,
        onProgress: options.onProgress,
        signal: options.signal,
      }
      const abort = () => {
        if (!shared.subscribers.delete(subscriber)) return
        reject(new DOMException('cache request cancelled', 'AbortError'))
        options.signal?.removeEventListener('abort', abort)
        if (!shared.settled && shared.subscribers.size === 0) shared.controller.abort()
      }
      subscriber.abort = abort
      shared.subscribers.add(subscriber)
      if (options.signal?.aborted) {
        abort()
        return
      }
      options.signal?.addEventListener('abort', abort, { once: true })
      if (shared.lastProgress) options.onProgress?.(shared.lastProgress)
    })
  }

  private settle<T>(
    bindingKey: string,
    shared: SharedRequest<T>,
    finish: (subscriber: Subscriber<T>) => void,
  ): void {
    shared.settled = true
    this.active.delete(bindingKey)
    for (const subscriber of shared.subscribers) {
      subscriber.signal?.removeEventListener('abort', subscriber.abort!)
      finish(subscriber)
    }
    shared.subscribers.clear()
  }
}

function validateProgress(progress: CacheRequestProgressV1): void {
  if (!Number.isSafeInteger(progress.receivedBytes) || progress.receivedBytes < 0 ||
      !Number.isSafeInteger(progress.totalBytes) || progress.totalBytes < 1 ||
      progress.receivedBytes > progress.totalBytes) {
    throw new Error('cache request progress is invalid')
  }
}
