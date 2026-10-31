// OPAQUE Web Worker (docs/plans/opaque.md): one sign-in or registration per
// worker, held across the server round trips. Argon2id (the suite's KSF) runs
// in its finish, off the main thread. The password, the OPAQUE state and the
// export key stay here; the page gets messages, and the master key once the
// account's envelope opens.
//
// The password is kept until `close`, so that a registration can start again
// from it (`registrationAgain`): a sign-in the server asks to rotate, or a
// record made under a server key that changed meanwhile. The page never holds
// it for that.
import '../polyfills'
import { getCryptoWasm, type OpaqueLoginHandle, type OpaqueRegistrationHandle } from '../rustWasm'
import { MASTER_KEY_GENERATION } from '../masterKeyGeneration'

export type OpaqueWorkerRequest =
  | { type: 'loginStart'; password: string }
  | { type: 'loginFinish'; response: string }
  | { type: 'openMasterKey'; envelope: string; keyBinding: string }
  | { type: 'registrationStart'; password: string }
  | { type: 'registrationAgain' }
  | { type: 'registrationFinish'; response: string }
  | { type: 'sealMasterKey'; masterKey: string; keyBinding: string }
  | { type: 'close' }

export type OpaqueWorkerResponse =
  | { type: 'started'; request: string }
  | { type: 'finished'; message: string }
  | { type: 'masterKey'; masterKey: string }
  | { type: 'sealed'; envelope: string }
  | { type: 'ready' }
  | { type: 'closed' }
  | { type: 'error'; message: string; authFailed: boolean }

let password: string | null = null
let login: OpaqueLoginHandle | null = null
let registration: OpaqueRegistrationHandle | null = null

function endLogin() {
  login?.close()
  login?.free()
  login = null
}

function endRegistration() {
  registration?.close()
  registration?.free()
  registration = null
}

async function handle(request: OpaqueWorkerRequest): Promise<OpaqueWorkerResponse> {
  const wasm = await getCryptoWasm()
  switch (request.type) {
    case 'loginStart':
      endLogin()
      password = request.password
      login = wasm.OpaqueLogin.start(password)
      return { type: 'started', request: login.request }
    case 'loginFinish':
      if (!login) throw new Error('no sign-in started')
      return { type: 'finished', message: login.finish(request.response) }
    case 'openMasterKey':
      if (!login) throw new Error('no sign-in started')
      return { type: 'masterKey', masterKey: login.openMasterKey(request.envelope, request.keyBinding) }
    case 'registrationStart':
      endRegistration()
      password = request.password
      registration = wasm.OpaqueRegistration.start(password)
      return { type: 'started', request: registration.request }
    case 'registrationAgain':
      if (password === null) throw new Error('no password held')
      endRegistration()
      registration = wasm.OpaqueRegistration.start(password)
      return { type: 'started', request: registration.request }
    case 'registrationFinish':
      if (!registration) throw new Error('no registration started')
      return { type: 'finished', message: registration.finish(request.response) }
    case 'sealMasterKey':
      if (!registration) throw new Error('no registration started')
      return { type: 'sealed', envelope: registration.sealMasterKey(request.masterKey, MASTER_KEY_GENERATION, request.keyBinding) }
    case 'close':
      endLogin()
      endRegistration()
      password = null
      return { type: 'closed' }
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
  if (event.data.type === 'close') self.close()
}

// Loaded (this module and its imports): the page may start sending.
self.postMessage({ type: 'ready' } satisfies OpaqueWorkerResponse)
