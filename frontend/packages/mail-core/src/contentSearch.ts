import { useQuery } from '@tanstack/react-query'
import { useEffect, useState, useSyncExternalStore } from 'react'
import api from '@kutup/session/client'
import { getSession, subscribe as subscribeSession, useRequiredSession } from '@kutup/session/store'
import { openMessageText, useMailAccount, type ListView, type MailAccount, type MailMessage, type Page, type PlaceKey } from './api'
import { contentPage } from './contentFilter'
import { createMailSearch, mailSearchStoreName, type DocRef, type IndexDoc, type MailSearchIndex, type NeededRecord, type SealedRecord } from './searchWasm'

// Body search in the browser (docs/plans/mail-body-search.md), as Proton's
// "Search message content": turned on by the reader, it downloads and opens
// each message once and keeps an index of its words and its list row in
// IndexedDB, every record sealed by the WASM module (no word, name or id
// readable) under a store key the database keeps wrapped; deleting the
// database destroys the key. A keyword search is answered, filtered and paged
// here, so the server never learns what matched; the server's change feed
// (Proton's event loop) keeps the rows current.
//
// Every change, in any tab, holds one exclusive Web Lock and reads the
// directory and progress again inside it; the other tabs hear of it on a
// BroadcastChannel.

/** The wrapped store key's record (not a secret: it opens only with the master key). */
const KEY_ID = 'store-key'
const PROGRESS = 'progress'
const BATCH = 50
const OPEN_AT_ONCE = 4
/** Periods read per step of a search (each 30 days). */
const PERIODS_AT_ONCE = 12

export type ContentSearchStatus = 'off' | 'building' | 'paused' | 'ready' | 'limited' | 'unsupported'

export interface ContentSearchState {
  status: ContentSearchStatus
  /** Messages indexed, of `total` (while building). */
  indexed: number
  total: number
  /** Out of room: only messages from this time on are indexed. */
  limitedFrom: number | null
  /** Raised by every change, so lists answered from the index refresh. */
  revision: number
}

interface Progress {
  enabled: boolean
  /** The search-index cursor to go on from; null once the oldest is done. */
  cursor: string | null
  started: boolean
  paused: boolean
  indexed: number
  total: number
  /** The change feed's cursor, taken before the first page was read. */
  feed: string | null
  limitedFrom: number | null
}

interface IndexPage {
  messages: MailMessage[]
  next: string | null
  total: number
}

interface ChangesPage {
  changed: MailMessage[]
  gone: { id: string; receivedAt: string }[]
  next: string
  more: boolean
  resync: boolean
}

async function indexPage(before: string | null): Promise<IndexPage> {
  const { data } = await api.get<IndexPage>('/mail/search-index', { params: { limit: BATCH, ...(before ? { before } : {}) } })
  return data
}

async function changesPage(since: string | null): Promise<ChangesPage> {
  const { data } = await api.get<ChangesPage>('/mail/search-index/changes', { params: since ? { since } : {} })
  return data
}

const FRESH: Progress = { enabled: false, cursor: null, started: false, paused: false, indexed: 0, total: 0, feed: null, limitedFrom: null }

function quotaExceeded(error: unknown): boolean {
  return error instanceof DOMException && (error.name === 'QuotaExceededError' || error.code === 22)
}

/** A message's list row as the index keeps it. */
function rowOf(message: MailMessage): string {
  const row: Partial<MailMessage> = { ...message }
  delete row.conversation
  return JSON.stringify(row)
}

const timeOf = (message: Pick<MailMessage, 'receivedAt'>) => Date.parse(message.receivedAt)

/** One IndexedDB database of sealed records, by id. */
class SealedStore {
  private constructor(private readonly db: IDBDatabase) {}

  /** `onClosed`: another tab deletes the database, so this one lets go. */
  static open(name: string, onClosed: () => void): Promise<SealedStore> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(name, 1)
      request.onupgradeneeded = () => request.result.createObjectStore('records')
      request.onsuccess = () => {
        const db = request.result
        db.onversionchange = () => {
          db.close()
          onClosed()
        }
        resolve(new SealedStore(db))
      }
      request.onerror = () => reject(request.error ?? new Error('search store'))
    })
  }

  static remove(name: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.deleteDatabase(name)
      request.onsuccess = () => resolve()
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

  /** Stores records in one transaction: all of them or none. */
  put(records: SealedRecord[]): Promise<void> {
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction('records', 'readwrite')
      const store = tx.objectStore('records')
      for (const record of records) store.put(record.sealed, record.id)
      tx.oncomplete = () => resolve()
      tx.onerror = () => reject(tx.error ?? new Error('search store write'))
      tx.onabort = () => reject(tx.error ?? new Error('search store write'))
    })
  }

  async load(needed: NeededRecord[]): Promise<{ name: string; sealed: Uint8Array }[]> {
    const found = await this.get(needed.map((n) => n.id))
    return needed.filter((n) => found.has(n.id)).map((n) => ({ name: n.name, sealed: found.get(n.id)! }))
  }

  close() {
    this.db.close()
  }
}

/** One account's body search in this browser. */
export class ContentSearch {
  private progress: Progress = FRESH
  private store: SealedStore | null = null
  private index: MailSearchIndex | null = null
  private building = false
  private catching: Promise<void> | null = null
  private closed = false
  /** Set when the work under the lock changed what searches find. */
  private dirty = false
  private revision = 0
  private listeners = new Set<() => void>()
  private snapshot: ContentSearchState = { status: 'off', indexed: 0, total: 0, limitedFrom: null, revision: 0 }
  private readonly channel: BroadcastChannel | null

  private constructor(
    private readonly masterKey: Uint8Array,
    private account: MailAccount,
    private readonly dbName: string,
  ) {
    this.channel = typeof BroadcastChannel === 'undefined' ? null : new BroadcastChannel(dbName)
    if (this.channel) {
      this.channel.onmessage = () => {
        // Another tab changed the index (or made it again): read it afresh.
        void this.exclusive(() => {
          this.dirty = true
          return Promise.resolve()
        }).catch(() => undefined)
      }
    }
  }

  /** Named by an HMAC under a key from the master key: bound to no name. */
  static async open(masterKey: Uint8Array, account: MailAccount): Promise<ContentSearch> {
    const dbName = `kutup-mail-search:${await mailSearchStoreName(masterKey)}`
    const search = new ContentSearch(masterKey, account, dbName)
    await search.exclusive(() => Promise.resolve())
    return search
  }

  /** The account as Mail knows it now (its keys open the messages). */
  setAccount(account: MailAccount) {
    this.account = account
  }

  /** The account's address: advanced search's Address for its own mail. */
  get address(): string {
    return this.account.address
  }

  close() {
    this.closed = true
    this.channel?.close()
    this.store?.close()
    this.store = null
    this.index?.free()
    this.index = null
  }

  /**
   * Runs `work` holding the index's lock (in every tab), on the directory and
   * progress as stored now; when `work` changed what searches find, lists
   * refresh and the other tabs are told.
   */
  private async exclusive<T>(work: () => Promise<T>): Promise<T> {
    const run = async () => {
      if (this.closed) throw new Error('body search is closed')
      await this.attach()
      await this.load()
      this.dirty = false
      try {
        return await work()
      } finally {
        if (this.dirty) {
          this.revision += 1
          this.publish()
        }
      }
    }
    if (typeof navigator !== 'undefined' && 'locks' in navigator) {
      return navigator.locks.request(`${this.dbName}:write`, run) as Promise<T>
    }
    return run()
  }

  /** Opens the database and its store key: the one kept, or a new one. */
  private async attach(): Promise<void> {
    if (this.store && this.index) return
    const store = await SealedStore.open(this.dbName, () => {
      if (this.store === store) {
        this.store = null
        this.index?.free()
        this.index = null
      }
    })
    const wrapped = (await store.get([KEY_ID])).get(KEY_ID)
    let index: MailSearchIndex
    try {
      index = await createMailSearch(this.masterKey, wrapped)
    } catch (error) {
      store.close()
      if (!wrapped) throw error
      // A store key that does not open (damaged): the index is made again.
      await SealedStore.remove(this.dbName)
      return this.attach()
    }
    if (!wrapped) await store.put([{ id: KEY_ID, sealed: index.wrappedStoreKey() }])
    this.store = store
    this.index = index
  }

  private async load() {
    const index = this.index!
    const directoryId = index.directoryId()
    const progressId = index.recordId(PROGRESS)
    const found = await this.store!.get([directoryId, progressId])
    index.openDirectory(found.get(directoryId))
    const sealed = found.get(progressId)
    const plain = sealed ? index.openRecord(PROGRESS, sealed) : undefined
    this.progress = plain ? { ...FRESH, ...(JSON.parse(new TextDecoder().decode(plain)) as Partial<Progress>) } : FRESH
    // An index that lost its directory (another version) is built again.
    if (this.progress.enabled && index.size() === 0 && this.progress.indexed > 0) this.progress = { ...FRESH, enabled: true }
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
    this.snapshot = { status, indexed: p.indexed, total: Math.max(p.total, p.indexed), limitedFrom: p.limitedFrom, revision: this.revision }
    this.listeners.forEach((listener) => listener())
  }

  /** Stores the progress with `extra` records; `changes`: what searches find changed. */
  private async saveProgress(extra: SealedRecord[] = [], changes = true) {
    const sealed = this.index!.sealRecord(PROGRESS, new TextEncoder().encode(JSON.stringify(this.progress)))
    await this.store!.put([...extra, sealed])
    if (changes) this.markChanged()
    this.publish()
  }

  private markChanged() {
    this.dirty = true
    this.channel?.postMessage('changed')
  }

  /** Turned on (Proton's Enable): builds, or carries on building. */
  async enable(): Promise<void> {
    await this.exclusive(async () => {
      this.progress = { ...this.progress, enabled: true, paused: false }
      await this.saveProgress()
    })
    void this.build()
  }

  /** Turned off: searches go back to the server; the index stays. */
  async disable(): Promise<void> {
    await this.exclusive(async () => {
      this.progress = { ...this.progress, enabled: false }
      await this.saveProgress()
    })
  }

  async pause(): Promise<void> {
    await this.exclusive(async () => {
      this.progress = { ...this.progress, paused: true }
      await this.saveProgress()
    })
  }

  async resume(): Promise<void> {
    await this.exclusive(async () => {
      this.progress = { ...this.progress, paused: false }
      await this.saveProgress()
    })
    void this.build()
  }

  /** Deletes the database, and so its store key; a new one starts empty. Under the lock. */
  private async reset() {
    this.store?.close()
    this.store = null
    this.index?.free()
    this.index = null
    await SealedStore.remove(this.dbName)
    await this.attach()
    this.progress = FRESH
    this.markChanged()
    this.publish()
  }

  /** Delete local search data: the index, its progress and its key, in this browser. */
  async deleteAll(): Promise<void> {
    await this.exclusive(() => this.reset())
  }

  /** Builds again from nothing (a damaged index, or changes no longer kept). */
  private async rebuild(): Promise<void> {
    await this.exclusive(async () => {
      if (!this.progress.enabled) return
      await this.reset()
      this.progress = { ...FRESH, enabled: true }
      await this.saveProgress()
    })
    void this.build()
  }

  /** Whether keyword searches go to this index: on, and built (or out of room). */
  get active(): boolean {
    return this.snapshot.status === 'ready' || this.snapshot.status === 'limited'
  }

  /**
   * Indexes `docs` and stores them with the progress (`next` applied), in
   * one transaction. Out of room, what is indexed stays and older mail is
   * not searched here; false then.
   */
  private async addDocs(docs: IndexDoc[], next: Partial<Progress> = {}): Promise<boolean> {
    const index = this.index!
    const changed = docs.length ? index.add(docs, await this.store!.load(index.planAdd(docs))) : []
    this.progress = { ...this.progress, ...next, indexed: index.size() }
    try {
      await this.saveProgress(changed)
      return true
    } catch (error) {
      if (!quotaExceeded(error)) throw error
      await this.load()
      this.progress = { ...this.progress, cursor: null, started: true, indexed: index.size(), limitedFrom: index.oldestTime() ?? Date.now() }
      await this.saveProgress().catch(() => this.publish())
      return false
    }
  }

  /** The messages' words: subject, people and text, with their list rows. */
  private async texts(messages: MailMessage[]): Promise<IndexDoc[]> {
    const docs: IndexDoc[] = []
    const queue = [...messages]
    const next = async (): Promise<void> => {
      const message = queue.shift()
      if (!message) return
      const people = [message.from, ...message.to, ...message.cc, ...message.bcc]
        .filter((m) => !!m)
        .map((m) => `${m.name} ${m.address}`)
        .join(' ')
      // A message that does not open (a key gone) is found by its subject and people.
      const text = await openMessageText(this.account, message).catch(() => message.subject)
      docs.push({ id: message.id, timeMs: timeOf(message), text: `${people}\n${text}`, meta: rowOf(message) })
      return next()
    }
    await Promise.all(Array.from({ length: OPEN_AT_ONCE }, next))
    return docs
  }

  /**
   * Builds from where it stopped, in one tab at a time: each page is read
   * and opened outside the lock, then stored inside it, if the progress is
   * still where the page began.
   */
  private async build(): Promise<void> {
    if (this.building) return
    const work = async () => {
      this.building = true
      try {
        for (;;) {
          const start = await this.exclusive(async () => {
            const p = this.progress
            if (!p.enabled || p.paused || (p.started && p.cursor === null)) return null
            if (p.feed === null) {
              // The feed starts before the first page, so no change is missed.
              this.progress = { ...p, feed: (await changesPage(null)).next }
              await this.saveProgress()
            }
            return { cursor: this.progress.cursor }
          })
          if (!start) break
          const data = await indexPage(start.cursor)
          const docs = await this.texts(data.messages)
          const more = await this.exclusive(async () => {
            const p = this.progress
            if (!p.enabled || p.paused || p.cursor !== start.cursor) return false
            if (!(await this.addDocs(docs, { started: true, total: data.total, cursor: data.next }))) return false
            return data.next !== null
          })
          if (!more) break
        }
      } finally {
        this.building = false
        this.publish()
      }
    }
    if (typeof navigator !== 'undefined' && 'locks' in navigator) {
      await navigator.locks.request(`${this.dbName}:build`, { ifAvailable: true }, async (lock) => {
        if (lock) await work()
      })
    } else {
      await work()
    }
  }

  /** One page of the change feed, applied. Under the lock. */
  private async followFeed(): Promise<'more' | 'done' | 'resync'> {
    const p = this.progress
    if (!p.enabled || p.paused || p.feed === null) return 'done'
    const index = this.index!
    const data = await changesPage(p.feed)
    if (data.resync) return 'resync'
    if (!data.changed.length && !data.gone.length) {
      if (data.next !== p.feed) {
        this.progress = { ...p, feed: data.next }
        await this.saveProgress([], false)
      }
      return data.more ? 'more' : 'done'
    }
    // Drafts are not searched: one that was a message is forgotten.
    const gone: DocRef[] = [...data.gone.map((g) => ({ id: g.id, timeMs: timeOf(g) })), ...data.changed.filter((m) => m.folder === 'drafts').map((m) => ({ id: m.id, timeMs: timeOf(m) }))]
    if (gone.length) await this.store!.put(index.remove(gone, await this.store!.load(index.planRemove(gone.map((g) => g.timeMs)))))
    const rows = data.changed.filter((m) => m.folder !== 'drafts')
    let fresh: MailMessage[] = []
    if (rows.length) {
      const updated = index.updateMeta(
        rows.map((m) => ({ id: m.id, timeMs: timeOf(m), meta: rowOf(m) })),
        await this.store!.load(index.planUpdateMeta(rows.map(timeOf))),
      )
      await this.store!.put(updated.stored)
      const missing = new Set(updated.missing)
      fresh = rows.filter((m) => missing.has(m.id))
    }
    // New mail is opened and indexed; out of room, the feed still goes on.
    await this.addDocs(fresh.length && p.limitedFrom === null ? await this.texts(fresh) : [], { feed: data.next })
    return data.more ? 'more' : 'done'
  }

  /**
   * Follows the change feed (Mail's poll, and before every search); a build
   * that stopped goes on. One at a time per tab.
   */
  catchUp(): Promise<void> {
    // Cleared once it settles (never before it is set, even when it ends at once).
    this.catching ??= this.followAll().finally(() => {
      this.catching = null
    })
    return this.catching
  }

  private async followAll(): Promise<void> {
    if (!this.progress.enabled) return
    if (!this.progress.paused && (this.progress.cursor !== null || !this.progress.started)) void this.build()
    for (let page = 0; page < 20; page++) {
      const step = await this.exclusive(() => this.followFeed())
      if (step === 'resync') {
        await this.rebuild()
        return
      }
      if (step === 'done') return
    }
  }

  /** Every message whose words hold all of `query`'s, as their list rows, newest first. */
  async search(query: string): Promise<MailMessage[]> {
    await this.catchUp().catch(() => undefined)
    const rows = await this.exclusive(async () => {
      const index = this.index!
      const out: MailMessage[] = []
      let unreadable = false
      let before: number | undefined
      for (;;) {
        const periods = index.nextPeriods(before, PERIODS_AT_ONCE)
        if (!periods.length) break
        const hits = index.search(query, periods, await this.store!.load(index.planSearch(query, periods)))
        for (const hit of hits) {
          try {
            out.push(JSON.parse(hit.meta) as MailMessage)
          } catch {
            // A row that does not read is left out, and the index made again below.
            unreadable = true
          }
        }
        before = periods[periods.length - 1]
      }
      return { out, damaged: unreadable || index.damaged() }
    })
    if (rows.damaged) void this.rebuild().catch(() => undefined)
    return rows.out
  }
}

// React: one ContentSearch per account, its state, and a list answered from it.

const opened = new Map<string, Promise<ContentSearch>>()

// Signed out: every index is closed, and its keys let go.
subscribeSession(() => {
  if (getSession() || !opened.size) return
  for (const promise of opened.values()) void promise.then((search) => search.close()).catch(() => undefined)
  opened.clear()
})

/** The account's body search in this browser (null until it opens, or where IndexedDB is missing). */
export function useContentSearch(): ContentSearch | null {
  const session = useRequiredSession()
  const account = useMailAccount()
  const [search, setSearch] = useState<ContentSearch | null>(null)
  useEffect(() => {
    if (!account.data || typeof indexedDB === 'undefined') return
    let live = true
    const data = account.data
    let promise = opened.get(session.userId)
    if (!promise) {
      promise = ContentSearch.open(session.masterKey, data)
      opened.set(session.userId, promise)
      promise.catch(() => opened.delete(session.userId))
    }
    promise
      .then((s) => {
        s.setAccount(data)
        if (live) setSearch(s)
      })
      .catch(() => undefined)
    return () => {
      live = false
    }
  }, [account.data, session.userId, session.masterKey])
  return search
}

const OFF: ContentSearchState = { status: 'off', indexed: 0, total: 0, limitedFrom: null, revision: 0 }

export function useContentSearchState(search: ContentSearch | null): ContentSearchState {
  return useSyncExternalStore(
    (listener) => search?.subscribe(listener) ?? (() => undefined),
    () => search?.state ?? OFF,
  )
}

/**
 * A place's keyword search answered from body search, in the list's shape:
 * found, filtered, sorted and paged in the browser (only your own mailbox
 * is indexed).
 */
export function useContentSearchList(search: ContentSearch | null, folder: PlaceKey, view: ListView, enabled: boolean) {
  const { q = '', criteria, conversations, filter, sort, page = 0, pageSize = 50 } = view
  const { revision } = useContentSearchState(search)
  return useQuery({
    queryKey: ['mail', 'content-search', folder, q, JSON.stringify(criteria ?? {}), !!conversations, filter ?? null, sort ?? 'newest', page, pageSize, revision],
    enabled: enabled && !!search && !!q.trim(),
    placeholderData: (previous) => previous,
    queryFn: async (): Promise<{ pages: Page[]; pageParams: number[] }> => {
      const rows = await search!.search(q)
      return { pages: [contentPage(rows, folder, view, search!.address)], pageParams: [page] }
    },
  })
}
