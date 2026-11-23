// The page's handle on a block reader (docs/plans/drive-block-format.md §4):
// a dedicated Worker per revision where the browser has Workers, the same
// reader in the page where it has none (tests). Whole downloads read its
// blocks in order; the stream glue (../stream/page.ts) hands it the service
// worker's ports, and the Worker answers them directly.
//
// Before the first byte is released, the manifest's signer goes to the
// check drive-core set (`setManifestSignerCheck`): it warns of a forged or
// changed signer and never blocks (§8).

import { manifestSignerCheck } from '@kutup/crypto/driveBlocks'
import { answerOnPort, BlockObjectReader } from './core'
import { STREAM_PROTOCOL_VERSION, type BlockReaderSettings, type BlockReaderTarget, type OpenedObject, type ReaderRequest, type ReaderResponse, type StreamChunkAnswer } from './protocol'
import type { StreamRange } from './plan'
import { clientFetch, clientVersionValue, latchClientTooOld } from '@kutup/session/clientVersion'

/** How long the signer check may hold back the first byte; it goes on after that and still warns. */
const SIGNER_CHECK_WAIT_MS = 10_000

export type AccessToken = string | (() => Promise<string>)

export interface BlockReaderHandle {
  readonly opened: OpenedObject
  /** Block `index`'s verified plaintext. */
  block(index: number): Promise<Uint8Array>
  /** Answers one service-worker stream request on `port` (from the Worker itself where there is one). */
  serve(port: MessagePort, range: StreamRange, mimeType: string): Promise<void>
  /** Stops its fetches and drops its blocks. */
  close(): void
}

export interface OpenBlockReaderOptions {
  source: BlockReaderTarget
  settings: BlockReaderSettings
  accessToken: AccessToken
  signal?: AbortSignal
}

async function tokenOf(accessToken: AccessToken): Promise<string> {
  return typeof accessToken === 'string' ? accessToken : accessToken()
}

/** Opens a revision for reading by block, its manifest and signer checked first. */
export async function openBlockReader(options: OpenBlockReaderOptions): Promise<BlockReaderHandle> {
  options.signal?.throwIfAborted()
  const handle = typeof Worker === 'undefined' ? await openInPage(options) : await openInWorker(options)
  try {
    await checkSigner(handle)
  } catch (error) {
    handle.handle.close()
    throw error
  }
  return handle.handle
}

interface Opened {
  handle: BlockReaderHandle
  signedBy(key: string): Promise<boolean>
}

async function checkSigner({ handle, signedBy }: Opened): Promise<void> {
  const check = manifestSignerCheck()
  const signer = handle.opened.signer
  if (!check || !signer) return
  const checking = Promise.resolve()
    .then(() =>
      check({
        fileId: handle.opened.fileId,
        revisionId: handle.opened.revisionId,
        accountId: signer.accountId,
        incarnationId: signer.incarnationId,
        signedBy,
      }),
    )
    // A check that fails warns by itself or not at all; it never blocks.
    .catch(() => {})
  let timer: ReturnType<typeof setTimeout> | undefined
  await Promise.race([checking, new Promise<void>((resolve) => (timer = setTimeout(resolve, SIGNER_CHECK_WAIT_MS)))])
  clearTimeout(timer)
}

async function openInPage(options: OpenBlockReaderOptions): Promise<Opened> {
  let token = await tokenOf(options.accessToken)
  const reader = await BlockObjectReader.open(options.source, options.settings, { fetch: (input, init) => clientFetch(input, init), token: () => token }, options.signal)
  const refresh = async () => {
    token = await tokenOf(options.accessToken)
  }
  return {
    signedBy: async (key) => reader.signedBy(key),
    handle: {
      opened: reader.opened,
      block: async (index) => {
        await refresh()
        return reader.block(index)
      },
      serve: async (port, range, mimeType) => {
        await refresh().catch(() => {})
        await answerOnPort(reader, port, range, mimeType)
      },
      close: () => reader.close(),
    },
  }
}

class WorkerClosed extends Error {
  constructor(message = 'the block reader is closed') {
    super(message)
    this.name = 'AbortError'
  }
}

async function openInWorker(options: OpenBlockReaderOptions): Promise<Opened> {
  const worker = new Worker(new URL('./blockReader.worker.ts', import.meta.url), { type: 'module', name: 'kutup-block-reader' })
  const pending = new Map<number, { resolve: (response: ReaderResponse) => void; reject: (error: Error) => void }>()
  let nextId = 1
  let dead: Error | null = null
  const fail = (error: Error) => {
    if (dead) return
    dead = error
    for (const { reject } of pending.values()) reject(error)
    pending.clear()
  }
  worker.onmessage = (event: MessageEvent<ReaderResponse>) => {
    const response = event.data
    if (response.type === 'ready') return
    const waiting = pending.get(response.id)
    if (!waiting) return
    pending.delete(response.id)
    if (response.type === 'error') {
      // The server refused this build (its range answer was 426).
      if (response.message.startsWith('range HTTP 426')) latchClientTooOld()
      const error = new Error(response.message)
      if (response.aborted) error.name = 'AbortError'
      waiting.reject(error)
    } else waiting.resolve(response)
  }
  worker.onerror = (event) => fail(new Error(event.message || 'the block reader failed'))
  worker.onmessageerror = () => fail(new Error('the block reader sent a message that could not be read'))

  const call = <T extends ReaderResponse['type']>(request: ReaderRequest & { id: number }, transfer: Transferable[] = []) =>
    new Promise<Extract<ReaderResponse, { type: T }>>((resolve, reject) => {
      if (dead) {
        reject(dead)
        return
      }
      pending.set(request.id, { resolve: resolve as (response: ReaderResponse) => void, reject })
      worker.postMessage(request, transfer)
    })

  let closed = false
  const close = () => {
    if (closed) return
    closed = true
    worker.postMessage({ type: 'close' } satisfies ReaderRequest)
    fail(new WorkerClosed())
    // The Worker closes itself; this is for one that hangs.
    setTimeout(() => worker.terminate(), 1_000)
  }
  const onAbort = () => close()
  options.signal?.addEventListener('abort', onAbort, { once: true })

  try {
    const { opened } = await call<'opened'>({
      type: 'open',
      id: nextId++,
      target: options.source,
      settings: options.settings,
      token: await tokenOf(options.accessToken),
      client: clientVersionValue(),
    })
    return {
      signedBy: async (key) => (await call<'signedBy'>({ type: 'signedBy', id: nextId++, key })).ok,
      handle: {
        opened,
        block: async (index) => (await call<'block'>({ type: 'block', id: nextId++, index, token: await tokenOf(options.accessToken) })).bytes,
        serve: async (port, range, mimeType) => {
          let token = ''
          try {
            token = await tokenOf(options.accessToken)
          } catch {
            // The Worker keeps the token it has.
          }
          if (closed || dead) {
            // Answered at once: the service worker would otherwise wait for it.
            port.postMessage({ v: STREAM_PROTOCOL_VERSION, kind: 'error', message: 'the block reader is closed' } satisfies StreamChunkAnswer)
            port.close()
            return
          }
          worker.postMessage({ type: 'serve', range, mimeType, token } satisfies ReaderRequest, [port])
        },
        close,
      },
    }
  } catch (error) {
    close()
    throw error
  }
}
