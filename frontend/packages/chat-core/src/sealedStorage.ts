import type { ChatWasmModule } from './types'

/**
 * Small per-account state the Chat app keeps in this browser (drafts, read
 * positions), sealed under a key derived from the account master key
 * (`sealLocalData`, `kutup-chat-core/src/db/store_cipher.rs`), like the
 * chat store itself (`docs/research/16-browser-storage-architecture.md`).
 * Each value is bound to its account scope and name: one cannot be swapped
 * for another. Synchronous, so the UI can read and write it while rendering.
 */
export class SealedStorage {
  constructor(
    private readonly wasm: Pick<ChatWasmModule, 'sealLocalData' | 'openLocalData'>,
    private readonly masterKey: Uint8Array,
    /** The account's chat scope (the chat store's name suffix). */
    readonly scope: string,
    private readonly storage: Storage = window.localStorage,
  ) {}

  /** The storage key a value is kept under, for cross-tab `storage` events. */
  key(name: string): string {
    return `${PREFIX}${this.scope}:${name}`
  }

  /**
   * The value kept as `name`. A value an older version kept in plaintext
   * under `legacyKey` is taken over: sealed here and the plaintext removed.
   * Unreadable values read as absent.
   */
  read<T>(name: string, legacyKey?: string): T | undefined {
    try {
      const sealed = this.storage.getItem(this.key(name))
      if (sealed !== null) return this.openValues<T>([{ name, sealed: fromBase64(sealed) }])[0]
      if (legacyKey === undefined) return undefined
      const plain = this.storage.getItem(legacyKey)
      if (plain === null) return undefined
      const value = JSON.parse(plain) as T
      this.write(name, value)
      this.storage.removeItem(legacyKey)
      return value
    } catch {
      return undefined
    }
  }

  /** Keep `value` as `name`; `undefined` removes it. */
  write(name: string, value: unknown): void {
    try {
      if (value === undefined) this.storage.removeItem(this.key(name))
      else this.storage.setItem(this.key(name), toBase64(this.sealValues([{ name, value }])[0]))
    } catch {
      // Storage full or blocked: the value still holds in memory.
    }
  }

  /** Seal values kept elsewhere (the backup mirror's records), in one call. */
  sealValues(entries: readonly { name: string; value: unknown }[]): Uint8Array[] {
    if (entries.length === 0) return []
    const encoder = new TextEncoder()
    return this.wasm.sealLocalData(
      this.masterKey,
      this.scope,
      entries.map((entry) => entry.name),
      entries.map((entry) => encoder.encode(JSON.stringify(entry.value))),
    )
  }

  /** Open values sealed with `sealValues`; one that does not open is `undefined`. */
  openValues<T>(entries: readonly { name: string; sealed: Uint8Array }[]): (T | undefined)[] {
    if (entries.length === 0) return []
    const decoder = new TextDecoder()
    return this.wasm
      .openLocalData(this.masterKey, this.scope, entries.map((entry) => entry.name), entries.map((entry) => entry.sealed))
      .map((bytes) => {
        if (!bytes) return undefined
        try {
          return JSON.parse(decoder.decode(bytes)) as T
        } catch {
          return undefined
        }
      })
  }
}

const PREFIX = 'kutup.sealed.v1:'

function toBase64(bytes: Uint8Array): string {
  let binary = ''
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000))
  }
  return btoa(binary)
}

function fromBase64(value: string): Uint8Array {
  return Uint8Array.from(atob(value), (char) => char.charCodeAt(0))
}
