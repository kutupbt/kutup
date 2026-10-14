// OPAQUE Web Worker (docs/plans/opaque.md): one sign-in or registration per
// worker, held across the server round trips. Argon2id (the suite's KSF) runs
// in its finish, off the main thread. The password, the OPAQUE state and the
// export key stay in the WASM object here; the page gets messages, and the
// master key once the account's envelope opens.
import '../polyfills'
import { getCryptoWasm, type OpaqueLoginHandle, type OpaqueRegistrationHandle } from '../rustWasm'

export type OpaqueWorkerRequest =
  | { type: 'loginStart'; password: string }
  | { type: 'loginFinish'; response: string }
  | { type: 'openMasterKey'; envelope: string; keyBinding: string }
  | { type: 'registrationStart'; password: string }
  | { type: 'registrationFinish'; response: string }
  | { type: 'sealMasterKey'; masterKey: string; keyBinding: string }

export type OpaqueWorkerResponse =
  | { type: 'started'; request: string }
  | { type: 'finished'; message: string }
  | { type: 'masterKey'; masterKey: string }
  | { type: 'sealed'; envelope: string }
  | { type: 'error'; message: string; authFailed: boolean }

let login: OpaqueLoginHandle | null = null
let registration: OpaqueRegistrationHandle | null = null

async function handle(request: OpaqueWorkerRequest): Promise<OpaqueWorkerResponse> {
  const wasm = await getCryptoWasm()
  switch (request.type) {
    case 'loginStart':
      login = wasm.OpaqueLogin.start(request.password)
      return { type: 'started', request: login.request }
    case 'loginFinish':
      if (!login) throw new Error('no sign-in started')
      return { type: 'finished', message: login.finish(request.response) }
    case 'openMasterKey':
      if (!login) throw new Error('no sign-in started')
      return { type: 'masterKey', masterKey: login.openMasterKey(request.envelope, request.keyBinding) }
    case 'registrationStart':
      registration = wasm.OpaqueRegistration.start(request.password)
      return { type: 'started', request: registration.request }
    case 'registrationFinish':
      if (!registration) throw new Error('no registration started')
      return { type: 'finished', message: registration.finish(request.response) }
    case 'sealMasterKey':
      if (!registration) throw new Error('no registration started')
      return { type: 'sealed', envelope: registration.sealMasterKey(request.masterKey, request.keyBinding) }
  }
}

self.onmessage = async (event: MessageEvent<OpaqueWorkerRequest>) => {
  // Only this origin's own pages may drive a sign-in here.
  if (event.origin !== '' && event.origin !== self.location.origin) {
    self.postMessage({ type: 'error', message: 'Unauthorized origin', authFailed: false } satisfies OpaqueWorkerResponse)
    return
  }
  try {
    self.postMessage(await handle(event.data))
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    self.postMessage({ type: 'error', message, authFailed: message.includes('authentication failed') } satisfies OpaqueWorkerResponse)
  }
}
