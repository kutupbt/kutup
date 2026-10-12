import { useQuery } from '@tanstack/react-query'
import { useEffect, useState, useSyncExternalStore } from 'react'
import api from '@kutup/session/client'
import { useRequiredSession } from '@kutup/session/store'
import { openMessageText, useMailAccount, type ListView, type MailAccount, type MailMessage, type Page, type PlaceKey } from './api'
import { createMailSearch, type IndexDoc, type MailSearchIndex, type SearchHit } from './searchWasm'

// Body search in the browser (docs/plans/mail-body-search.md), as Proton's
// "Search message content": turned on by the reader, it downloads and opens
// each message once, keeps an index of its words in IndexedDB (every record
// sealed by the WASM module: no word, name or id readable) and answers
// keyword searches from it; the server then checks every hit.

const PROGRESS = 'progress'
const BATCH = 50
const OPEN_AT_ONCE = 4
const MAX_HITS = 200

export type ContentSearchStatus = 'off' | 'building' | 'paused' | 'ready' | 'limited' | 'unsupported'

export interface ContentSearchState {
  status: ContentSearchStatus
  /** Messages indexed, of `total` (while building). */
  indexed: number
  total: number
  /** Out of room: only messages from this time on are indexed. */
  limitedFrom: number | null
}

interface Progress {
  enabled: boolean
  /** The search-index cursor to go on from; null once the oldest is done. */
  cursor: string | null
  started: boolean
  paused: boolean
  indexed: number
  total: number
  /** The newest message indexed, to catch up from. */
  newestMs: number | null
  limitedFrom: number | null
}

interface IndexPage {
  messages: MailMessage[]
  next: string | null
  total: number
}

async function indexPage(before: string | null): Promise<IndexPage> {
  const { data } = await api.get<IndexPage>('/mail/search-index', { params: { limit: BATCH, ...(before ? { before } : {}) } })
  return data
}

const FRESH: Progress = { enabled: false, cursor: null, started: false, paused: false, indexed: 0, total: 0, newestMs: null, limitedFrom: null }

function quotaExceeded(error: unknown): boolean {
  return error instanceof DOMException && (error.name === 'QuotaExceededError' || error.code === 22)
}

/** One IndexedDB database of sealed records, by id. */
class SealedStore {
  private constructor(private readonly db: IDBDatabase) {}

  static open(name: string): Promise<SealedStore> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(name, 1)
      request.onupgradeneeded = () => request.result.createObjectStore('records')
      request.onsuccess = () => resolve(new SealedStore(request.result))
      request.onerror = () => reject(request.error ?? new Error('search store'))
    })
  }

  static remove(name: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.deleteDatabase(name)
      request.onsuccess = () => resolve()
      request.onblocked = () => resolve()
      request.onerror = () => reject(request.error ?? new Error('search store'))
    })
  }

  get(ids: string[]): Promise<Map<string, Uint8Array>> {
    return new Promise((resolve, reject) => {
      const out = new Map<string, Uint8Array>()
      const tx = this.db.transaction('records', 'readonly')
      const store = tx.objectStore('records')
      for (const id of ids) {
        const request = store.get(id)
        request.onsuccess = () => {
          if (request.result instanceof Uint8Array) out.set(id, request.result)
        }
      }
      tx.oncomplete = () => resolve(out)
      tx.onerror = () => reject(tx.error ?? new Error('search store read'))
    })
  }

  put(records: { id: string; sealed: Uint8Array }[]): Promise<void> {
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction('records', 'readwrite')
      const store = tx.objectStore('records')
      for (const record of records) store.put(record.sealed, record.id)
      tx.oncomplete = () => resolve()
      tx.onerror = () => reject(tx.error ?? new Error('search store write'))
      tx.onabort = () => reject(tx.error ?? new Error('search store write'))
    })
  }

  close() {
    this.db.close()
  }
}

/** One account's body search in this browser. */
export class ContentSearch {
  private progress: Progress = FRESH
  private running = false
  private listeners = new Set<() => void>()
  private snapshot: ContentSearchState = { status: 'off', indexed: 0, total: 0, limitedFrom: null }

  private constructor(
    private readonly account: MailAccount,
    private readonly dbName: string,
    private store: SealedStore,
    private index: MailSearchIndex,
  ) {}

  static async open(masterKey: Uint8Array, account: MailAccount): Promise<ContentSearch> {
    const dbName = `kutup-mail-search:${account.address}`
    const store = await SealedStore.open(dbName)
    const index = await createMailSearch(masterKey, account.address)
    const search = new ContentSearch(account, dbName, store, index)
    await search.load()
    return search
  }

  private async load() {
    const directoryId = this.index.directoryId()
    const progressId = this.index.recordId(PROGRESS)
    const found = await this.store.get([directoryId, progressId])
    this.index.openDirectory(found.get(directoryId))
    const sealed = found.get(progressId)
    const plain = sealed ? this.index.openRecord(PROGRESS, sealed) : undefined
    this.progress = plain ? { ...FRESH, ...(JSON.parse(new TextDecoder().decode(plain)) as Partial<Progress>) } : FRESH
    // An index that lost its directory (another version) is built again.
    if (this.progress.enabled && this.index.size() === 0 && this.progress.indexed > 0) this.progress = { ...FRESH, enabled: true }
    this.publish()
  }

  /** What the reader sees. */
  get state(): ContentSearchState {
    return this.snapshot
  }

  subscribe(listener: () => void): () => void {
    this.listeners.add(listener)
    return () => this.listeners.delete(listener)
  }

  private publish() {
    const p = this.progress
    const status: ContentSearchStatus = !p.enabled ? 'off' : p.paused ? 'paused' : p.cursor !== null || !p.started ? 'building' : p.limitedFrom !== null ? 'limited' : 'ready'
    this.snapshot = { status, indexed: p.indexed, total: Math.max(p.total, p.indexed), limitedFrom: p.limitedFrom }
    this.listeners.forEach((listener) => listener())
  }

  private async saveProgress(extra: { id: string; sealed: Uint8Array }[] = []) {
    const sealed = this.index.sealRecord(PROGRESS, new TextEncoder().encode(JSON.stringify(this.progress)))
    await this.store.put([...extra, sealed])
    this.publish()
  }

  /** Turned on (Proton's Enable): builds, or carries on building. */
  async enable(): Promise<void> {
    this.progress = { ...this.progress, enabled: true, paused: false }
    await this.saveProgress()
    void this.build()
  }

  /** Turned off: searches go back to the server; the index stays, kept current. */
  async disable(): Promise<void> {
    this.progress = { ...this.progress, enabled: false }
    await this.saveProgress()
  }

  async pause(): Promise<void> {
    this.progress = { ...this.progress, paused: true }
    await this.saveProgress()
  }

  async resume(): Promise<void> {
    this.progress = { ...this.progress, paused: false }
    await this.saveProgress()
    void this.build()
  }

  /** Delete local search data: the index and its progress, in this browser. */
  async deleteAll(): Promise<void> {
    this.progress = FRESH
    this.store.close()
    await SealedStore.remove(this.dbName)
    this.store = await SealedStore.open(this.dbName)
    this.index.openDirectory(undefined)
    this.publish()
  }

  /** Whether keyword searches go to this index. */
  get active(): boolean {
    return this.progress.enabled && this.index.size() > 0
  }

  private async addDocs(docs: IndexDoc[]): Promise<boolean> {
    if (!docs.length) return true
    const needed = this.index.planAdd(docs)
    const found = await this.store.get(needed.map((n) => n.id))
    const loaded = needed.filter((n) => found.has(n.id)).map((n) => ({ name: n.name, sealed: found.get(n.id)! }))
    const changed = this.index.add(docs, loaded)
    this.progress = {
      ...this.progress,
      indexed: this.progress.indexed + docs.length,
      newestMs: Math.max(this.progress.newestMs ?? 0, ...docs.map((d) => d.timeMs)),
    }
    try {
      await this.saveProgress(changed)
      return true
    } catch (error) {
      if (!quotaExceeded(error)) throw error
      // Out of room: what is indexed stays; older mail is not searched here.
      this.index.openDirectory((await this.store.get([this.index.directoryId()])).get(this.index.directoryId()))
      this.progress = { ...this.progress, cursor: null, indexed: this.index.size(), limitedFrom: this.index.oldestTime() ?? Date.now() }
      await this.saveProgress().catch(() => this.publish())
      return false
    }
  }

  private async texts(messages: MailMessage[]): Promise<IndexDoc[]> {
    const docs: IndexDoc[] = []
    const queue = [...messages]
    const next = async (): Promise<void> => {
      const message = queue.shift()
      if (!message) return
      // A message that does not open (a key gone) is left out, not retried for ever.
      const text = await openMessageText(this.account, message).catch(() => message.subject)
      docs.push({ id: message.id, timeMs: Date.parse(message.receivedAt), text })
      return next()
    }
    await Promise.all(Array.from({ length: OPEN_AT_ONCE }, next))
    return docs
  }

  /** Builds from where it stopped, one tab at a time. */
  private async build(): Promise<void> {
    if (this.running) return
    const work = async () => {
      this.running = true
      try {
        while (this.progress.enabled && !this.progress.paused) {
          if (this.progress.started && this.progress.cursor === null) break
          const data = await indexPage(this.progress.cursor)
          this.progress = { ...this.progress, started: true, total: data.total }
          const docs = await this.texts(data.messages)
          if (!(await this.addDocs(docs))) break
          this.progress = { ...this.progress, cursor: data.next }
          await this.saveProgress()
        }
      } finally {
        this.running = false
        this.publish()
      }
    }
    if ('locks' in navigator) {
      await navigator.locks.request(`${this.dbName}:build`, { ifAvailable: true }, async (lock) => {
        if (lock) await work()
      })
    } else {
      await work()
    }
  }

  /** New mail since the newest indexed (Mail's poll); a build in progress goes on. */
  async catchUp(): Promise<void> {
    if (!this.progress.enabled || this.running) return
    if (this.progress.cursor !== null || !this.progress.started) {
      if (!this.progress.paused) void this.build()
      return
    }
    const newest = this.progress.newestMs ?? 0
    let before: string | null = null
    for (let page = 0; page < 10; page++) {
      const data: IndexPage = await indexPage(before)
      const fresh = data.messages.filter((m) => Date.parse(m.receivedAt) > newest)
      if (!(await this.addDocs(await this.texts(fresh)))) return
      if (fresh.length < data.messages.length || !data.next) return
      before = data.next
    }
  }

  /** Messages whose text holds every word of `query`, newest first (at most 200). */
  async search(query: string): Promise<SearchHit[]> {
    const hits: SearchHit[] = []
    let before: number | undefined
    for (;;) {
      const periods = this.index.nextPeriods(before, 6)
      if (!periods.length) break
      const needed = this.index.planSearch(query, periods)
      const found = await this.store.get(needed.map((n) => n.id))
      const loaded = needed.filter((n) => found.has(n.id)).map((n) => ({ name: n.name, sealed: found.get(n.id)! }))
      hits.push(...this.index.search(query, periods, loaded))
      if (hits.length >= MAX_HITS) break
      before = periods[periods.length - 1]
    }
    return hits.slice(0, MAX_HITS)
  }

  /** Forgets messages a search found gone. */
  async forget(gone: SearchHit[]): Promise<void> {
    if (!gone.length) return
    const needed = this.index.planRemove(gone.map((g) => g.timeMs))
    const found = await this.store.get(needed.map((n) => n.id))
    const loaded = needed.filter((n) => found.has(n.id)).map((n) => ({ name: n.name, sealed: found.get(n.id)! }))
    await this.store.put(this.index.remove(gone, loaded))
  }
}

// React: one ContentSearch per account, its state, and a list answered from it.

const opened = new Map<string, Promise<ContentSearch>>()

/** The account's body search in this browser (null until it opens, or where IndexedDB is missing). */
export function useContentSearch(): ContentSearch | null {
  const session = useRequiredSession()
  const account = useMailAccount()
  const [search, setSearch] = useState<ContentSearch | null>(null)
  const address = account.data?.address
  useEffect(() => {
    if (!account.data || typeof indexedDB === 'undefined') return
    let live = true
    const data = account.data
    let promise = opened.get(data.address)
    if (!promise) {
      promise = ContentSearch.open(session.masterKey, data)
      opened.set(data.address, promise)
      promise.catch(() => opened.delete(data.address))
    }
    promise.then((s) => live && setSearch(s)).catch(() => undefined)
    return () => {
      live = false
    }
    // The account's address names the index; its other fields do not change it.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [address, session.masterKey])
  return search
}

const OFF: ContentSearchState = { status: 'off', indexed: 0, total: 0, limitedFrom: null }

export function useContentSearchState(search: ContentSearch | null): ContentSearchState {
  return useSyncExternalStore(
    (listener) => search?.subscribe(listener) ?? (() => undefined),
    () => search?.state ?? OFF,
  )
}

/** A place's search answered from body search: its hits, checked by the server, in the list's shape. */
export function useContentSearchList(search: ContentSearch | null, folder: PlaceKey, view: ListView, enabled: boolean) {
  const { q = '', criteria, group, conversations, filter, page = 0, pageSize = 50 } = view
  return useQuery({
    queryKey: ['mail', 'content-search', folder, q, JSON.stringify(criteria ?? {}), group ?? null, !!conversations, filter ?? null, page, pageSize],
    enabled: enabled && !!search && !!q.trim(),
    queryFn: async (): Promise<{ pages: Page[]; pageParams: number[] }> => {
      const found = await search!.search(q)
      const hits = found.slice(page * pageSize, (page + 1) * pageSize)
      if (!hits.length) return { pages: [{ messages: [], next: null, total: found.length }], pageParams: [page] }
      const { data } = await api.post<Page>('/mail/messages/lookup', {
        ids: hits.map((h) => h.id),
        folder,
        ...criteria,
        ...(group ? { group } : {}),
        conversations: !!conversations,
        ...(filter === 'unread' ? { unread: true } : filter === 'read' ? { unread: false } : filter === 'attachments' ? { attachments: true } : {}),
      })
      // The total counts what the index found; the server keeps those still here.
      return { pages: [{ ...data, total: found.length }], pageParams: [page] }
    },
  })
}
