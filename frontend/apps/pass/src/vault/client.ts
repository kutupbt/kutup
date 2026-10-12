// The page's side of the Kutup Pass worker: one worker for the tab, a
// promise per call, and a handle per open vault.

import type { Call, Request, Response } from './protocol'
import type { Applied, EntryView, MergeOutcome, Op, OtpView, VaultKeyInput, VaultView } from './types'

/** The worker refused or failed a call; `message` is the vault library's. */
export class VaultError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'VaultError'
  }
}

let worker: Worker | null = null
let nextId = 1
const pending = new Map<number, { resolve: (value: unknown) => void; reject: (error: Error) => void }>()

function passWorker(): Worker {
  if (!worker) {
    worker = new Worker(new URL('./worker.ts', import.meta.url), { type: 'module' })
    worker.onmessage = (event: MessageEvent<Response>) => {
      const response = event.data
      const waiting = pending.get(response.id)
      if (!waiting) return
      pending.delete(response.id)
      if (response.ok) waiting.resolve(response.result)
      else waiting.reject(new VaultError(response.message))
    }
    worker.onerror = (event) => {
      // The worker itself failed (its script did not load): every call fails,
      // and the next one starts a new worker.
      const error = new VaultError(event.message || 'the vault worker stopped')
      for (const waiting of pending.values()) waiting.reject(error)
      pending.clear()
      worker?.terminate()
      worker = null
    }
  }
  return worker
}

function call<T>(message: Call): Promise<T> {
  const id = nextId++
  const request: Request = { ...message, id }
  return new Promise<T>((resolve, reject) => {
    pending.set(id, { resolve: resolve as (value: unknown) => void, reject })
    passWorker().postMessage(request)
  })
}

/** One vault open in the worker. Close it when done. */
export class VaultHandle {
  private constructor(private readonly handle: number) {}

  static async create(name: string, key: VaultKeyInput): Promise<VaultHandle> {
    return new VaultHandle(await call<number>({ call: 'create', name, password: key.password, keyFile: key.keyFile, now: Date.now() }))
  }

  /** Opens a vault's file contents; a wrong key or a file that is no vault throws {@link VaultError}. */
  static async open(contents: Uint8Array, key: VaultKeyInput): Promise<VaultHandle> {
    return new VaultHandle(await call<number>({ call: 'open', contents, password: key.password, keyFile: key.keyFile }))
  }

  view(): Promise<VaultView> {
    return call({ call: 'view', handle: this.handle })
  }

  apply(op: Op): Promise<Applied> {
    return call({ call: 'apply', handle: this.handle, op, now: Date.now() })
  }

  history(entryId: string): Promise<EntryView[]> {
    return call({ call: 'history', handle: this.handle, entryId })
  }

  attachment(entryId: string, name: string): Promise<Uint8Array> {
    return call({ call: 'attachment', handle: this.handle, entryId, name })
  }

  otp(entryId: string, now = Date.now()): Promise<OtpView | null> {
    return call({ call: 'otp', handle: this.handle, entryId, now })
  }

  /** The vault as KDBX 4.1 file contents (derives the key: slow). */
  save(): Promise<Uint8Array> {
    return call({ call: 'save', handle: this.handle })
  }

  /** Merges `theirs` into this vault against `base`; the result stays here. */
  merge(base: Uint8Array | null, theirs: Uint8Array, theirsKey?: VaultKeyInput): Promise<MergeOutcome> {
    return call({
      call: 'merge',
      handle: this.handle,
      base,
      theirs,
      theirsPassword: theirsKey?.password ?? null,
      theirsKeyFile: theirsKey?.keyFile ?? null,
    })
  }

  changeKey(key: VaultKeyInput): Promise<void> {
    return call({ call: 'changeKey', handle: this.handle, password: key.password, keyFile: key.keyFile, now: Date.now() })
  }

  close(): Promise<void> {
    return call({ call: 'close', handle: this.handle })
  }
}

/** A key file as a vault secret keeps it (large files as their SHA-256). */
export function keyFileSecret(contents: Uint8Array): Promise<Uint8Array> {
  return call({ call: 'keyFileSecret', contents })
}
