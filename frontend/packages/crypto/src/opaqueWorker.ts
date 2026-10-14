// OPAQUE sign-in from the page (docs/plans/opaque.md). Each sign-in or
// registration gets a worker of its own, kept across the server round trips
// and ended with `close()`: Argon2id runs there, and the password, the OPAQUE
// state and the export key never come back to the page.

import { fromBase64, toBase64 } from './base64'
import { LoadFailure, retryLoad } from './retry'
import type { OpaqueWorkerRequest, OpaqueWorkerResponse } from './workers/opaque.worker'

/** The server's answer did not authenticate: a wrong password (or an unknown name, or another server). */
export class OpaqueAuthFailed extends Error {
  constructor() {
    super('the password is not right')
    this.name = 'OpaqueAuthFailed'
  }
}

/** The worker is gone: closed, or it failed. Every call after that throws this. */
export class OpaqueWorkerClosed extends Error {
  constructor(reason = 'the OPAQUE worker is closed') {
    super(reason)
    this.name = 'OpaqueWorkerClosed'
  }
}

/** How long a closing worker gets to wipe its keys before it is ended anyway. */
const CLOSE_GRACE_MS = 1_000

/** What a worker does: requests in, responses out. Tests stand in for the real one. */
export interface WorkerPort {
  onmessage: ((event: MessageEvent<OpaqueWorkerResponse>) => void) | null
  onerror: ((event: ErrorEvent) => void) | null
  onmessageerror: ((event: MessageEvent) => void) | null
  postMessage(request: OpaqueWorkerRequest): void
  terminate(): void
}

export class OpaqueWorker {
  private queue: Promise<unknown> = Promise.resolve()
  private pending: { resolve: (response: OpaqueWorkerResponse) => void; reject: (error: Error) => void } | null = null
  private dead: OpaqueWorkerClosed | null = null

  constructor(private readonly worker: WorkerPort) {
    // For the worker's whole life: an answer settles the call waiting for it;
    // a failure settles it too, and every call after.
    worker.onmessage = (event) => {
      if (event.data.type === 'ready') return
      const pending = this.pending
      this.pending = null
      const response = event.data
      if (!pending) return
      if (response.type === 'error') pending.reject(response.authFailed ? new OpaqueAuthFailed() : new Error(response.message))
      else pending.resolve(response)
    }
    worker.onerror = (event) => this.fail(new OpaqueWorkerClosed(event.message || 'the OPAQUE worker failed'))
    worker.onmessageerror = () => this.fail(new OpaqueWorkerClosed('the OPAQUE worker sent a message that could not be read'))
  }

  static open(): Promise<OpaqueWorker> {
    // A worker that could not start (its script not fetched) is retried with a
    // new one; errors the worker reports are not.
    return retryLoad(
      () =>
        new Promise<OpaqueWorker>((resolve, reject) => {
          const worker = new Worker(new URL('./workers/opaque.worker.ts', import.meta.url), { type: 'module' })
          // Until the worker says it is ready (its script and imports loaded),
          // a failure is a load failure, retried with a new worker (a stale
          // chunk after a deploy). From then on, the lifetime handlers.
          worker.onerror = (event) => {
            worker.terminate()
            reject(new LoadFailure(event.message || 'OPAQUE worker could not start'))
          }
          worker.onmessage = (event: MessageEvent<OpaqueWorkerResponse>) => {
            if (event.data.type === 'ready') resolve(new OpaqueWorker(worker))
          }
        }),
    )
  }

  /** One request at a time: each waits for the answer to the one before. */
  call(request: OpaqueWorkerRequest): Promise<OpaqueWorkerResponse> {
    const run = () =>
      new Promise<OpaqueWorkerResponse>((resolve, reject) => {
        if (this.dead) {
          reject(this.dead)
          return
        }
        this.pending = { resolve, reject }
        this.worker.postMessage(request)
      })
    const result = this.queue.then(run, run)
    this.queue = result.catch(() => undefined)
    return result
  }

  /**
   * Ends the worker: it wipes its password, state and export key, then
   * stops (or is stopped, if it does not answer in time). Calls waiting, and
   * any made after, throw {@link OpaqueWorkerClosed}. Safe to call again.
   */
  close(): void {
    if (this.dead) return
    this.fail(new OpaqueWorkerClosed())
    const stop = setTimeout(() => this.worker.terminate(), CLOSE_GRACE_MS)
    this.worker.onmessage = (event) => {
      if (event.data.type !== 'closed') return
      clearTimeout(stop)
      this.worker.terminate()
    }
    this.worker.onerror = () => {
      clearTimeout(stop)
      this.worker.terminate()
    }
    this.worker.postMessage({ type: 'close' })
  }

  private fail(error: OpaqueWorkerClosed): void {
    if (!this.dead) this.dead = error
    const pending = this.pending
    this.pending = null
    pending?.reject(error)
  }
}

function expect<T extends OpaqueWorkerResponse['type']>(response: OpaqueWorkerResponse, type: T): Extract<OpaqueWorkerResponse, { type: T }> {
  if (response.type !== type) throw new Error('the OPAQUE worker answered out of turn')
  return response as Extract<OpaqueWorkerResponse, { type: T }>
}

/** One registration of the password the worker holds. */
export interface OpaqueRegistration {
  /** `registrationRequest` for `register/start`. */
  readonly request: string
  /** The record to upload, from the server's `registrationResponse`. Runs Argon2id. */
  finish(registrationResponse: string): Promise<string>
  /** The password envelope of `masterKey` for this password (after `finish`). */
  sealMasterKey(masterKey: Uint8Array, keyBinding: string): Promise<string>
}

/** Something holding a password in its worker, that can register it (again). */
export interface OpaqueRegistrar {
  /** A new registration of the held password (the one before it is dropped). */
  register(): Promise<OpaqueRegistration>
  /** Ends the worker; the password and any export key go with it. */
  close(): void
}

function registrationOn(worker: OpaqueWorker, request: string): OpaqueRegistration {
  return {
    request,
    finish: async (response) => expect(await worker.call({ type: 'registrationFinish', response }), 'finished').message,
    sealMasterKey: async (masterKey, keyBinding) =>
      expect(await worker.call({ type: 'sealMasterKey', masterKey: toBase64(masterKey), keyBinding }), 'sealed').envelope,
  }
}

async function registerAgain(worker: OpaqueWorker): Promise<OpaqueRegistration> {
  return registrationOn(worker, expect(await worker.call({ type: 'registrationAgain' }), 'started').request)
}

/** A sign-in (or reauthentication) in progress. */
export interface OpaqueSignIn extends OpaqueRegistrar {
  /** `credentialRequest` for `login/start`. */
  readonly request: string
  /**
   * The finalization for `login/finish`, from the server's
   * `credentialResponse`. Throws {@link OpaqueAuthFailed} for a wrong
   * password. Runs Argon2id.
   */
  finish(credentialResponse: string): Promise<string>
  /** The account's master key, from its password envelope (after the server accepted the finalization). */
  openMasterKey(envelope: string, keyBinding: string): Promise<Uint8Array>
}

/** Starts signing in with `password`. */
export async function startOpaqueSignIn(password: string): Promise<OpaqueSignIn> {
  return signInOn(await OpaqueWorker.open(), password)
}

export async function signInOn(worker: OpaqueWorker, password: string): Promise<OpaqueSignIn> {
  try {
    const { request } = expect(await worker.call({ type: 'loginStart', password }), 'started')
    return {
      request,
      finish: async (response) => expect(await worker.call({ type: 'loginFinish', response }), 'finished').message,
      openMasterKey: async (envelope, keyBinding) =>
        fromBase64(expect(await worker.call({ type: 'openMasterKey', envelope, keyBinding }), 'masterKey').masterKey),
      register: () => registerAgain(worker),
      close: () => worker.close(),
    }
  } catch (error) {
    worker.close()
    throw error
  }
}

/**
 * Starts registering `password` (sign-up, password change, recovery, a
 * temporary password). The first `register()` uses the registration started
 * here; a later one starts again from the held password.
 */
export async function startOpaqueRegistration(password: string): Promise<OpaqueRegistrar> {
  return registrarOn(await OpaqueWorker.open(), password)
}

export async function registrarOn(worker: OpaqueWorker, password: string): Promise<OpaqueRegistrar> {
  try {
    let first: OpaqueRegistration | null = registrationOn(
      worker,
      expect(await worker.call({ type: 'registrationStart', password }), 'started').request,
    )
    return {
      register: async () => {
        const started = first
        first = null
        return started ?? registerAgain(worker)
      },
      close: () => worker.close(),
    }
  } catch (error) {
    worker.close()
    throw error
  }
}
