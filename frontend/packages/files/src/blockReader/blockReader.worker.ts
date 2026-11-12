// The block reader's dedicated Worker (docs/plans/drive-block-format.md §4):
// one revision per Worker, opened against what it must be, then read by
// block. The file key and the plaintext stay here and in the page that
// started it; the service worker only ever gets the bytes of one answer,
// on the port it sent, transferred.
import '@kutup/crypto/polyfills'
import { exactBytes } from '@kutup/crypto/bytes'
import { answerOnPort, BlockObjectReader } from './core'
import type { ReaderRequest, ReaderResponse } from './protocol'

const scope = self as unknown as {
  postMessage(message: ReaderResponse, transfer?: Transferable[]): void
  onmessage: ((event: MessageEvent<ReaderRequest>) => void) | null
  close(): void
}

let token = ''
let reader: BlockObjectReader | null = null
let opening: Promise<BlockObjectReader> | null = null

function reply(message: ReaderResponse, transfer: Transferable[] = []) {
  scope.postMessage(message, transfer)
}

function failed(id: number, error: unknown) {
  const aborted = error instanceof DOMException && error.name === 'AbortError'
  reply({ type: 'error', id, message: error instanceof Error ? error.message : String(error), aborted })
}

scope.onmessage = (event) => {
  const request = event.data
  // A public link's reader has none; a refresh that failed sends none.
  if ('token' in request && request.token) token = request.token
  switch (request.type) {
    case 'open': {
      if (opening) {
        failed(request.id, new Error('this reader is open already'))
        return
      }
      opening = BlockObjectReader.open(request.target, request.settings, { fetch: (input, init) => fetch(input, init), token: () => token })
      opening.then(
        (opened) => {
          reader = opened
          reply({ type: 'opened', id: request.id, opened: opened.opened })
        },
        (error) => failed(request.id, error),
      )
      return
    }
    case 'block': {
      const current = reader
      if (!current) {
        failed(request.id, new Error('the reader is not open'))
        return
      }
      current.block(request.index).then(
        (plain) => {
          // A copy of its own, transferred: the cached block stays here.
          const copy = exactBytes(plain)
          reply({ type: 'block', id: request.id, bytes: new Uint8Array(copy) }, [copy])
        },
        (error) => failed(request.id, error),
      )
      return
    }
    case 'signedBy':
      reply({ type: 'signedBy', id: request.id, ok: reader?.signedBy(request.key) ?? false })
      return
    case 'serve': {
      const [port] = event.ports
      if (port) void answerOnPort(reader, port, request.range, request.mimeType)
      return
    }
    case 'close':
      reader?.close()
      reader = null
      void opening?.then((late) => late.close()).catch(() => {})
      scope.close()
      return
  }
}

reply({ type: 'ready' })
