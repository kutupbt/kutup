/// <reference lib="webworker" />
// The Kutup Pass worker (docs/plans/pass.md, K2c): it holds the open vaults
// in the WASM module (crates/kutup-pass-wasm) and runs everything that
// touches them here, off the page, since unlocking and saving derive the
// vault key on purpose slowly. The page receives what it asks for: the
// vault's view (every field, protected values included, which the page shows
// on request), attachments, one-time codes and the encrypted KDBX file. The
// vault's key and its decrypted database stay here; locking frees them.

import { freshUrl, retryLoad } from '@kutup/crypto/retry'
import type { Request, Response } from './protocol'

declare const __KUTUP_PASS_WASM__: string | undefined
const BASE = typeof __KUTUP_PASS_WASM__ === 'string' && __KUTUP_PASS_WASM__ ? `/pass-wasm/${__KUTUP_PASS_WASM__}` : '/pass-wasm'
const MODULE_URL = new URL(`${BASE}/kutup_pass_wasm.js`, self.location.origin).href
const WASM_URL = new URL(`${BASE}/kutup_pass_wasm_bg.wasm`, self.location.origin).href

interface WasmVault {
  view(): unknown
  apply(op: unknown, nowMs: number): unknown
  history(entryId: string): unknown
  attachment(entryId: string, name: string): Uint8Array
  otp(entryId: string, nowMs: number): unknown
  save(): Uint8Array
  mergeWith(base: Uint8Array | null | undefined, theirs: Uint8Array, password?: string | null, keyFile?: Uint8Array | null): unknown
  changeKey(password: string | null | undefined, keyFile: Uint8Array | null | undefined, nowMs: number): void
  free(): void
}

interface PassWasm {
  default(input?: unknown): Promise<unknown>
  Vault: {
    create(name: string, password: string | null | undefined, keyFile: Uint8Array | null | undefined, nowMs: number): WasmVault
    open(contents: Uint8Array, password: string | null | undefined, keyFile: Uint8Array | null | undefined): WasmVault
  }
  keyFileSecret(contents: Uint8Array): Uint8Array
}

let wasm: Promise<PassWasm> | null = null
function passWasm(): Promise<PassWasm> {
  if (!wasm) {
    wasm = retryLoad(async (n) => {
      const module = (await import(/* @vite-ignore */ n === 0 ? MODULE_URL : freshUrl(MODULE_URL, n))) as PassWasm
      await module.default({ module_or_path: WASM_URL })
      return module
    })
    wasm.catch(() => {
      wasm = null
    })
  }
  return wasm
}

const vaults = new Map<number, WasmVault>()
let nextHandle = 1

function vault(handle: number): WasmVault {
  const found = vaults.get(handle)
  if (!found) throw new Error('the vault is closed')
  return found
}

function keep(v: WasmVault): number {
  const handle = nextHandle++
  vaults.set(handle, v)
  return handle
}

async function run(request: Request): Promise<unknown> {
  const module = await passWasm()
  switch (request.call) {
    case 'create':
      return keep(module.Vault.create(request.name, request.password, request.keyFile, request.now))
    case 'open':
      return keep(module.Vault.open(request.contents, request.password, request.keyFile))
    case 'view':
      return vault(request.handle).view()
    case 'apply':
      return vault(request.handle).apply(request.op, request.now)
    case 'history':
      return vault(request.handle).history(request.entryId)
    case 'attachment':
      return vault(request.handle).attachment(request.entryId, request.name)
    case 'otp':
      return vault(request.handle).otp(request.entryId, request.now)
    case 'save':
      return vault(request.handle).save()
    case 'merge':
      return vault(request.handle).mergeWith(request.base, request.theirs, request.theirsPassword, request.theirsKeyFile)
    case 'changeKey':
      vault(request.handle).changeKey(request.password, request.keyFile, request.now)
      return null
    case 'close': {
      vaults.get(request.handle)?.free()
      vaults.delete(request.handle)
      return null
    }
    case 'keyFileSecret':
      return module.keyFileSecret(request.contents)
  }
}

self.onmessage = (event: MessageEvent<Request>) => {
  const request = event.data
  run(request).then(
    (result) => {
      const response: Response = { id: request.id, ok: true, result }
      self.postMessage(response, result instanceof Uint8Array ? [result.buffer] : [])
    },
    (error: unknown) => {
      const response: Response = { id: request.id, ok: false, message: error instanceof Error ? error.message : String(error) }
      self.postMessage(response)
    },
  )
}
