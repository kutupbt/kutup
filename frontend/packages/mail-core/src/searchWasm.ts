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

export interface SearchHit {
  id: string
  timeMs: number
}

export interface IndexDoc {
  id: string
  timeMs: number
  text: string
}

/** The generated `MailSearch` class's surface. */
export interface MailSearchIndex {
  storeName(): string
  directoryId(): string
  openDirectory(sealed: Uint8Array | undefined): boolean
  size(): number
  oldestTime(): number | undefined
  recordId(name: string): string
  sealRecord(name: string, value: Uint8Array): SealedRecord
  openRecord(name: string, sealed: Uint8Array): Uint8Array | undefined
  planAdd(docs: IndexDoc[]): NeededRecord[]
  add(docs: IndexDoc[], loaded: { name: string; sealed: Uint8Array }[]): SealedRecord[]
  planRemove(timesMs: number[]): NeededRecord[]
  remove(gone: SearchHit[], loaded: { name: string; sealed: Uint8Array }[]): SealedRecord[]
  nextPeriods(before: number | undefined, count: number): number[]
  planSearch(query: string, periods: number[]): NeededRecord[]
  search(query: string, periods: number[], loaded: { name: string; sealed: Uint8Array }[]): SearchHit[]
  free(): void
}

interface MailSearchModule {
  default(input?: unknown): Promise<unknown>
  MailSearch: new (masterKey: Uint8Array) => MailSearchIndex
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

/** An account's index, its keys derived from the master key (bound to no name). */
export async function createMailSearch(masterKey: Uint8Array): Promise<MailSearchIndex> {
  const module = await getModule()
  return new module.MailSearch(masterKey)
}
