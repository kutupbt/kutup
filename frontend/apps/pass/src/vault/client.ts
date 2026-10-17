// The page's side of the Kutup Pass worker: one worker for the tab, a
// promise per call, and a handle per open vault.

import type { Call, Request, Response } from './protocol'
import type { Applied, EntryView, ImportFailure, ImportFormat, ImportPreview, MergeOutcome, Op, OtpView, VaultKeyInput, VaultView } from './types'

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
    return new VaultHandle(await call<number>({ call: 'open', contents, password: key.password, passwordHash: key.passwordHash ?? null, keyFile: key.keyFile }))
  }

  /**
   * What the account keeps of this vault's key (kutup_pass::kept), sealed for
   * `binding` and `fileId` at `revision`: the key this vault was opened or
   * made with. `generated`: its password is one Kutup Pass made. Base64.
   */
  keepKey(masterKey: Uint8Array, binding: string, fileId: string, revision: number, generated: boolean): Promise<string> {
    return call({ call: 'keepKey', handle: this.handle, masterKey, binding, fileId, revision, generated })
  }

  /** Whether the kept key `envelope` is the key this vault is open with (checked in the worker). */
  keptKeyIsMine(envelope: string, masterKey: Uint8Array, binding: string, fileId: string): Promise<boolean> {
    return call({ call: 'keptKeyIsMine', handle: this.handle, envelope, masterKey, binding, fileId })
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

/** A kept vault key, opened (kutup_pass::kept): bytes in base64. */
export interface KeptKey {
  /** SHA-256 of the password, which opens the vault in its place. */
  passwordHash: string | null
  keyFile: string | null
  /** The password, when Kutup Pass generated it (to show). */
  generatedPassword: string | null
  /** The revision it was kept at. */
  revision: number
}

/** Opens what the account keeps for vault `fileId`; throws when it does not open. */
export function openKept(envelope: string, masterKey: Uint8Array, binding: string, fileId: string): Promise<KeptKey> {
  return call({ call: 'openKept', envelope, masterKey, binding, fileId })
}

/** Reads another password manager's export, changing nothing. */
export function importPreview(contents: Uint8Array, provider: string | null): Promise<ImportPreview | ImportFailure> {
  return call({ call: 'importPreview', contents, provider })
}

/** The formats an import can be read as. */
export function importFormats(): Promise<ImportFormat[]> {
  return call({ call: 'importFormats' })
}
