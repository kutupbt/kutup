import { afterEach, describe, expect, it, vi } from 'vitest'
import { OpaqueAuthFailed, OpaqueWorker, OpaqueWorkerClosed, registrarOn, signInOn, type WorkerPort } from './opaqueWorker'
import type { OpaqueWorkerRequest, OpaqueWorkerResponse } from './workers/opaque.worker'

/** A stand-in worker: records what it was sent, answers when told. */
class FakeWorker implements WorkerPort {
  onmessage: ((event: MessageEvent<OpaqueWorkerResponse>) => void) | null = null
  onerror: ((event: ErrorEvent) => void) | null = null
  onmessageerror: ((event: MessageEvent) => void) | null = null
  sent: OpaqueWorkerRequest[] = []
  terminated = false
  postMessage(request: OpaqueWorkerRequest) {
    this.sent.push(request)
  }
  terminate() {
    this.terminated = true
  }
  answer(response: OpaqueWorkerResponse) {
    this.onmessage?.({ data: response } as MessageEvent<OpaqueWorkerResponse>)
  }
  crash(message: string) {
    this.onerror?.({ message } as ErrorEvent)
  }
}

const settle = () => new Promise((resolve) => setTimeout(resolve, 0))

afterEach(() => vi.useRealTimers())

describe('OpaqueWorker', () => {
  it('settles each call with its answer, and an error answer as an error', async () => {
    const port = new FakeWorker()
    const worker = new OpaqueWorker(port)
    const first = worker.call({ type: 'loginFinish', response: 'r' })
    await settle()
    port.answer({ type: 'finished', message: 'ke3' })
    await expect(first).resolves.toEqual({ type: 'finished', message: 'ke3' })
    const second = worker.call({ type: 'loginFinish', response: 'r' })
    await settle()
    port.answer({ type: 'error', message: 'opaque: authentication failed', authFailed: true })
    await expect(second).rejects.toBeInstanceOf(OpaqueAuthFailed)
  })

  it('fails the waiting call and every later one when the worker dies', async () => {
    const port = new FakeWorker()
    const worker = new OpaqueWorker(port)
    const waiting = worker.call({ type: 'loginFinish', response: 'r' })
    await settle()
    port.crash('out of memory')
    await expect(waiting).rejects.toThrow('out of memory')
    await expect(worker.call({ type: 'loginFinish', response: 'r' })).rejects.toBeInstanceOf(OpaqueWorkerClosed)
    expect(port.sent).toHaveLength(1)
  })

  it('closes by asking the worker to wipe, then ends it; calls waiting or after throw', async () => {
    const port = new FakeWorker()
    const worker = new OpaqueWorker(port)
    const waiting = worker.call({ type: 'openMasterKey', envelope: 'e', keyBinding: 'kb' })
    await settle()
    worker.close()
    await expect(waiting).rejects.toBeInstanceOf(OpaqueWorkerClosed)
    expect(port.sent.at(-1)).toEqual({ type: 'close' })
    expect(port.terminated).toBe(false)
    port.answer({ type: 'closed' })
    expect(port.terminated).toBe(true)
    await expect(worker.call({ type: 'loginFinish', response: 'r' })).rejects.toBeInstanceOf(OpaqueWorkerClosed)
    worker.close()
    expect(port.sent.filter((m) => m.type === 'close')).toHaveLength(1)
  })

  it('ends a worker that does not answer the close', () => {
    vi.useFakeTimers()
    const port = new FakeWorker()
    new OpaqueWorker(port).close()
    expect(port.terminated).toBe(false)
    vi.advanceTimersByTime(1_000)
    expect(port.terminated).toBe(true)
  })
})

/** Answers the next request once it is posted. */
async function reply(port: FakeWorker, response: OpaqueWorkerResponse) {
  await settle()
  port.answer(response)
}

describe('registrations from a held password', () => {
  it('a sign-in registers again from the password its worker holds; the page sends none', async () => {
    const port = new FakeWorker()
    const starting = signInOn(new OpaqueWorker(port), 'pw')
    await reply(port, { type: 'started', request: 'ke1' })
    const signIn = await starting
    const again = signIn.register()
    await reply(port, { type: 'started', request: 'reg' })
    expect((await again).request).toBe('reg')
    expect(port.sent.map((m) => m.type)).toEqual(['loginStart', 'registrationAgain'])
    expect(port.sent[1]).toEqual({ type: 'registrationAgain' })
  })

  it('a registrar uses its first registration, then starts again', async () => {
    const port = new FakeWorker()
    const starting = registrarOn(new OpaqueWorker(port), 'pw')
    await reply(port, { type: 'started', request: 'first' })
    const registrar = await starting
    expect((await registrar.register()).request).toBe('first')
    const second = registrar.register()
    await reply(port, { type: 'started', request: 'second' })
    expect((await second).request).toBe('second')
    expect(port.sent.map((m) => m.type)).toEqual(['registrationStart', 'registrationAgain'])
  })
})
