import { freshUrl, retryLoad } from '@kutup/crypto/retry'

// Mail's search index module (crates/kutup-mail-search-wasm,
// docs/plans/mail-body-search.md), loaded on first use: its directory is
// named for its content hash (@kutup/config/vite), as the crypto module's.

declare const __KUTUP_MAIL_SEARCH_WASM__: string | undefined
const BASE = typeof __KUTUP_MAIL_SEARCH_WASM__ === 'string' && __KUTUP_MAIL_SEARCH_WASM__ ? `/mail-search-wasm/${__KUTUP_MAIL_SEARCH_WASM__}` : '/mail-search-wasm'
const MODULE_URL = `${BASE}/kutup_mail_search_wasm.js`
const WASM_URL = `${BASE}/kutup_mail_search_wasm_bg.wasm`

/** A record the index needs: its name (for opening) and the id it is stored under. */
export interface NeededRecord {
  name: string
  id: string
}

/** A record to store, sealed. */
export interface SealedRecord {
  id: string
  sealed: Uint8Array
}

/** A message held: its id and time, which find its period. */
export interface DocRef {
  id: string
  timeMs: number
}

/** A message found, or new data for one held: `meta` is its list row (JSON). */
export interface SearchHit extends DocRef {
  meta: string
}

export interface IndexDoc extends SearchHit {
  text: string
}

/** The generated `MailSearch` class's surface. */
export interface MailSearchIndex {
  wrappedStoreKey(): Uint8Array
  damaged(): boolean
  newer(): boolean
  directoryId(): string
  openDirectory(sealed: Uint8Array | undefined): boolean
  size(): number
  oldestTime(): number | undefined
  recordId(name: string): string
  sealRecord(name: string, value: Uint8Array): SealedRecord
  openRecord(name: string, sealed: Uint8Array): Uint8Array | undefined
  planAdd(docs: IndexDoc[]): NeededRecord[]
  add(docs: IndexDoc[], loaded: { name: string; sealed: Uint8Array }[]): SealedRecord[]
  planRemove(gone: DocRef[]): NeededRecord[]
  remove(gone: DocRef[], loaded: { name: string; sealed: Uint8Array }[]): SealedRecord[]
  planUpdateMeta(docs: SearchHit[]): NeededRecord[]
  updateMeta(docs: SearchHit[], loaded: { name: string; sealed: Uint8Array }[]): { stored: SealedRecord[]; missing: string[] }
  nextPeriods(before: number | undefined, count: number): number[]
  planSearch(query: string, periods: number[]): NeededRecord[]
  search(query: string, periods: number[], loaded: { name: string; sealed: Uint8Array }[]): { found: [number, number][]; needed: NeededRecord[] }
  hits(found: [number, number][], loaded: { name: string; sealed: Uint8Array }[]): SearchHit[]
  free(): void
}

interface MailSearchModule {
  default(input?: unknown): Promise<unknown>
  MailSearch: {
    new (masterKey: Uint8Array, wrappedStoreKey: Uint8Array | undefined): MailSearchIndex
    storeName(masterKey: Uint8Array): string
    matches(query: string, text: string): boolean
  }
}

let modulePromise: Promise<MailSearchModule> | null = null

async function getModule(): Promise<MailSearchModule> {
  if (!modulePromise) {
    modulePromise = retryLoad(async (n) => {
      const url = n === 0 ? MODULE_URL : freshUrl(MODULE_URL, n)
      const module = (await import(/* @vite-ignore */ url)) as MailSearchModule
      await module.default({ module_or_path: WASM_URL })
      return module
    })
    modulePromise.catch(() => {
      modulePromise = null
    })
  }
  return modulePromise
}

/** Whether `text` holds every word of `query`, as the index finds them (WASM loaded first). */
export async function mailSearchMatcher(): Promise<(query: string, text: string) => boolean> {
  const module = await getModule()
  return (query, text) => module.MailSearch.matches(query, text)
}

/** The browser database's name for an account: an HMAC under a key from its master key. */
export async function mailSearchStoreName(masterKey: Uint8Array): Promise<string> {
  const module = await getModule()
  return module.MailSearch.storeName(masterKey)
}

/**
 * An account's index under the store key the database keeps (`wrapped`), or
 * under a new one when there is none (then kept from `wrappedStoreKey()`).
 * Throws when `wrapped` does not open under this master key.
 */
export async function createMailSearch(masterKey: Uint8Array, wrapped: Uint8Array | undefined): Promise<MailSearchIndex> {
  const module = await getModule()
  return new module.MailSearch(masterKey, wrapped)
}
