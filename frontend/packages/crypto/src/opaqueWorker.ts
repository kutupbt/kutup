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

class OpaqueWorker {
  private queue: Promise<unknown> = Promise.resolve()

  constructor(private readonly worker: Worker) {}

  static open(): Promise<OpaqueWorker> {
    // A worker that could not start (its script not fetched) is retried with a
    // new one; errors the worker reports are not.
    return retryLoad(
      () =>
        new Promise<OpaqueWorker>((resolve, reject) => {
          const worker = new Worker(new URL('./workers/opaque.worker.ts', import.meta.url), { type: 'module' })
          worker.onerror = (event) => {
            worker.terminate()
            reject(new LoadFailure(event.message || 'OPAQUE worker could not start'))
          }
          resolve(new OpaqueWorker(worker))
        }),
    )
  }

  /** One request at a time: each waits for the answer to the one before. */
  call(request: OpaqueWorkerRequest): Promise<OpaqueWorkerResponse> {
    const run = () =>
      new Promise<OpaqueWorkerResponse>((resolve, reject) => {
        this.worker.onmessage = (event: MessageEvent<OpaqueWorkerResponse>) => {
          const response = event.data
          if (response.type === 'error') reject(response.authFailed ? new OpaqueAuthFailed() : new Error(response.message))
          else resolve(response)
        }
        this.worker.postMessage(request)
      })
    const result = this.queue.then(run, run)
    this.queue = result.catch(() => undefined)
    return result
  }

  close(): void {
    this.worker.terminate()
  }
}

function expect<T extends OpaqueWorkerResponse['type']>(response: OpaqueWorkerResponse, type: T): Extract<OpaqueWorkerResponse, { type: T }> {
  if (response.type !== type) throw new Error('the OPAQUE worker answered out of turn')
  return response as Extract<OpaqueWorkerResponse, { type: T }>
}

/** A sign-in (or reauthentication) in progress. */
export interface OpaqueSignIn {
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
  /** Ends the worker; the export key goes with it. */
  close(): void
}

/** Starts signing in with `password`. */
export async function startOpaqueSignIn(password: string): Promise<OpaqueSignIn> {
  const worker = await OpaqueWorker.open()
  try {
    const { request } = expect(await worker.call({ type: 'loginStart', password }), 'started')
    return {
      request,
      finish: async (response) => expect(await worker.call({ type: 'loginFinish', response }), 'finished').message,
      openMasterKey: async (envelope, keyBinding) =>
        fromBase64(expect(await worker.call({ type: 'openMasterKey', envelope, keyBinding }), 'masterKey').masterKey),
      close: () => worker.close(),
    }
  } catch (error) {
    worker.close()
    throw error
  }
}

/** A registration (sign-up, password change, recovery, a temporary password) in progress. */
export interface OpaqueRegistering {
  /** `registrationRequest` for `register/start`. */
  readonly request: string
  /** The record to upload, from the server's `registrationResponse`. Runs Argon2id. */
  finish(registrationResponse: string): Promise<string>
  /** The password envelope of `masterKey` for this password (after `finish`). */
  sealMasterKey(masterKey: Uint8Array, keyBinding: string): Promise<string>
  close(): void
}

/** Starts registering `password`. */
export async function startOpaqueRegistration(password: string): Promise<OpaqueRegistering> {
  const worker = await OpaqueWorker.open()
  try {
    const { request } = expect(await worker.call({ type: 'registrationStart', password }), 'started')
    return {
      request,
      finish: async (response) => expect(await worker.call({ type: 'registrationFinish', response }), 'finished').message,
      sealMasterKey: async (masterKey, keyBinding) =>
        expect(await worker.call({ type: 'sealMasterKey', masterKey: toBase64(masterKey), keyBinding }), 'sealed').envelope,
      close: () => worker.close(),
    }
  } catch (error) {
    worker.close()
    throw error
  }
}
