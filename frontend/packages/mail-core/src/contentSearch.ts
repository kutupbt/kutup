import { useQuery } from '@tanstack/react-query'
import { useEffect, useState, useSyncExternalStore } from 'react'
import api from '@kutup/session/client'
import { getSession, subscribe as subscribeSession, useRequiredSession } from '@kutup/session/store'
import { openMessageText, useMailAccount, type ListView, type MailAccount, type MailMessage, type Page, type PlaceKey } from './api'
import { contentPage } from './contentFilter'
import { createMailSearch, mailSearchMatcher, mailSearchStoreName, type DocRef, type IndexDoc, type MailSearchIndex, type SealedRecord, type SearchHit } from './searchWasm'

// Body search in the browser (docs/plans/mail-body-search.md), as Proton's
// "Search message content": turned on by the reader, it downloads and opens
// each message once and keeps an index of its words and its list row in
// IndexedDB, every record sealed by the WASM module (no word, name or id
// readable) under a store key the database keeps wrapped; deleting the
// database destroys the key. Drafts, which change and move in time, are kept
// beside it by their rows alone. A keyword search is answered, filtered and
// paged here, so the server never learns what matched; the server's change
// feed (Proton's event loop) keeps the rows current.
//
// Every change, in any tab, holds one exclusive Web Lock and reads the
// stored state again inside it; the other tabs hear of it on a
// BroadcastChannel. Messages are downloaded outside the lock: the rows to
// index wait (`pending`: their ids in the progress, each row a record of its
// own) and the feed keeps them current under the lock; a downloaded message
// is stored only if it still waits, with its row as it is then.

/** The wrapped store key's record (not a secret: it opens only with the master key). */
const KEY_ID = 'store-key'
const PROGRESS = 'progress'
const DRAFTS = 'drafts'
const BATCH = 50
const OPEN_AT_ONCE = 4
/** Periods read per step of a search (each 30 days). */
const PERIODS_AT_ONCE = 12
/** Rows that may wait at once; past it the build reads the newest mail again later. */
const MAX_PENDING = 5000
/** Out of room: how long before indexing is tried again. */
const ROOM_RETRY_MS = 60 * 60 * 1000

export type ContentSearchStatus = 'off' | 'building' | 'paused' | 'ready' | 'limited' | 'unsupported'

export interface ContentSearchState {
  status: ContentSearchStatus
  /** Whether keyword searches are answered here now (built, current, and of this page's version). */
  searchable: boolean
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
  /** The search-index cursor to go on from; null once the oldest is read. */
  cursor: string | null
  started: boolean
  paused: boolean
  total: number
  /** The change feed's cursor, taken before the first page was read. */
  feed: string | null
  limitedFrom: number | null
  /** Out of room: not before this time is indexing tried again. */
  roomRetryAt: number | null
  /** Ids of rows waiting to be downloaded and indexed (each row in `pending/<id>`). */
  pending: string[]
  /** Rows that did not fit in `pending`: the newest mail is read again, from the top down to `until`. */
  rescan: { cursor: string | null; until: number } | null
}

interface IndexPage {
  messages: MailMessage[]
  next: string | null
  total?: number
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

const FRESH: Progress = { enabled: false, cursor: null, started: false, paused: false, total: 0, feed: null, limitedFrom: null, roomRetryAt: null, pending: [], rescan: null }

function quotaExceeded(error: unknown): boolean {
  return error instanceof DOMException && (error.name === 'QuotaExceededError' || error.code === 22)
}

/** A record of the index past what one may hold: as out of room for it. */
function tooLarge(error: unknown): boolean {
  return error instanceof Error && /too large/.test(error.message)
}

/** A message's list row as the index keeps it (what the list shows; not its thread's references). */
function rowOf(message: MailMessage): string {
  const row: Partial<MailMessage> = { ...message }
  delete row.conversation
  delete row.references
  return JSON.stringify(row)
}

const timeOf = (message: Pick<MailMessage, 'receivedAt'>) => Date.parse(message.receivedAt)
const pendingName = (id: string) => `pending/${id}`

/** A build cursor's time (`<nanoseconds>_<id>`), in ms. */
function cursorTime(cursor: string): number {
  const nanos = cursor.split('_')[0] ?? ''
  return /^-?\d+$/.test(nanos) ? Number(BigInt(nanos) / 1_000_000n) : Number.NEGATIVE_INFINITY
}

/** Who a message is from and to, as words to find it by. */
function people(message: MailMessage): string {
  return [message.from, ...message.to, ...message.cc, ...message.bcc]
    .filter((m) => !!m)
    .map((m) => `${m.name} ${m.address}`)
    .join(' ')
}

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

  /** Stores records and deletes others in one transaction: all of it or none. */
  put(records: SealedRecord[], deletes: string[] = []): Promise<void> {
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction('records', 'readwrite')
      const store = tx.objectStore('records')
      for (const id of deletes) store.delete(id)
      for (const record of records) store.put(record.sealed, record.id)
      tx.oncomplete = () => resolve()
      tx.onerror = () => reject(tx.error ?? new Error('search store write'))
      tx.onabort = () => reject(tx.error ?? new Error('search store write'))
    })
  }

  async load(needed: { name: string; id: string }[]): Promise<{ name: string; sealed: Uint8Array }[]> {
    const found = await this.get(needed.map((n) => n.id))
    return needed.filter((n) => found.has(n.id)).map((n) => ({ name: n.name, sealed: found.get(n.id)! }))
  }

  close() {
    this.db.close()
  }
}

/** What one run under the lock asked for once it ends. */
interface Run {
  /** The index was made again: building starts after. */
  rebuild: boolean
  /** The database was deleted in this run (not twice). */
  reset: boolean
}

/** One account's body search in this browser. */
export class ContentSearch {
  private progress: Progress = FRESH
  /** Drafts by id, by their rows alone. */
  private drafts = new Map<string, MailMessage>()
  private store: SealedStore | null = null
  private index: MailSearchIndex | null = null
  private building = false
  private catching: Promise<void> | null = null
  private closed = false
  /** Set when the work under the lock changed what searches find. */
  private dirty = false
  /** The run holding the lock now. */
  private run: Run = { rebuild: false, reset: false }
  /** The last change feed step failed: until one succeeds, searches go to the server. */
  private stale = false
  /** The index was written by a newer version: this page neither writes nor searches it. */
  private outdated = false
  /** The database cannot be written at all. */
  private broken = false
  private revision = 0
  private listeners = new Set<() => void>()
  private snapshot: ContentSearchState = { status: 'off', searchable: false, indexed: 0, total: 0, limitedFrom: null, revision: 0 }
  private readonly channel: BroadcastChannel | null

  private constructor(
    private readonly masterKey: Uint8Array,
    private account: MailAccount,
    private readonly dbName: string,
    private readonly matches: (query: string, text: string) => boolean,
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
    const search = new ContentSearch(masterKey, account, dbName, await mailSearchMatcher())
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
   * Runs `work` holding the index's lock (in every tab), on the state as
   * stored now; when `work` changed what searches find, lists refresh and
   * the other tabs are told. An index found damaged is made again (one of a
   * newer version is left alone).
   */
  private async exclusive<T>(work: () => Promise<T>): Promise<T> {
    const run: Run = { rebuild: false, reset: false }
    const locked = async () => {
      if (this.closed) throw new Error('body search is closed')
      this.run = run
      await this.attach()
      this.dirty = false
      try {
        await this.load()
        return await work()
      } catch (error) {
        if (!this.index?.damaged() || this.index.newer() || run.reset) throw error
        // A record that does not open: nothing more is written over it.
        await this.startAgain()
        throw error
      } finally {
        if (this.dirty) {
          this.revision += 1
          this.publish()
        }
      }
    }
    try {
      if (typeof navigator !== 'undefined' && 'locks' in navigator) {
        return (await navigator.locks.request(`${this.dbName}:write`, locked))
      }
      return await locked()
    } finally {
      if (run.rebuild && !this.closed) void this.build().catch(() => undefined)
    }
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

  /**
   * The stored state. A directory, progress or drafts record that does not
   * open (or an older version) makes the index again; one of a newer version
   * leaves this page out of it until reloaded.
   */
  private async load() {
    const index = this.index!
    const directoryId = index.directoryId()
    const progressId = index.recordId(PROGRESS)
    const draftsId = index.recordId(DRAFTS)
    const found = await this.store!.get([directoryId, progressId, draftsId])
    index.openDirectory(found.get(directoryId))
    if (index.newer()) {
      this.outdated = true
      this.publish()
      return
    }
    this.outdated = false
    const open = <T>(name: string, id: string): T | null | 'damaged' => {
      const sealed = found.get(id)
      if (!sealed) return null
      const plain = index.openRecord(name, sealed)
      return plain ? (JSON.parse(new TextDecoder().decode(plain)) as T) : 'damaged'
    }
    const progress = open<Partial<Progress>>(PROGRESS, progressId)
    const drafts = open<MailMessage[]>(DRAFTS, draftsId)
    if (index.damaged() || progress === 'damaged' || drafts === 'damaged') {
      const enabled = progress !== null && progress !== 'damaged' && !!progress.enabled
      await this.startAgain(enabled)
      return
    }
    this.progress = progress ? { ...FRESH, ...progress } : FRESH
    this.drafts = new Map((drafts ?? []).map((row) => [row.id, row]))
    this.publish()
  }

  /**
   * Deletes the database (and its key) and starts again, on if it was; once
   * per run. Under the lock. A database that cannot be written is told.
   */
  private async startAgain(enabled = this.progress.enabled) {
    if (this.run.reset) return
    await this.reset()
    if (!enabled) return
    this.progress = { ...FRESH, enabled: true }
    try {
      await this.save()
    } catch {
      this.broken = true
      this.publish()
      return
    }
    this.run.rebuild = true
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
    const status: ContentSearchStatus = this.broken
      ? 'unsupported'
      : !p.enabled
        ? 'off'
        : p.paused
          ? 'paused'
          : p.cursor !== null || !p.started
            ? 'building'
            : p.limitedFrom !== null
              ? 'limited'
              : 'ready'
    const searchable = (status === 'ready' || status === 'limited') && !this.stale && !this.outdated
    const indexed = (this.index?.size() ?? 0) + this.drafts.size
    this.snapshot = { status, searchable, indexed, total: Math.max(p.total, indexed), limitedFrom: p.limitedFrom, revision: this.revision }
    this.listeners.forEach((listener) => listener())
  }

  /**
   * Stores the progress and the drafts with `extra` records (and deletes
   * `deletes`), in one transaction; `changes`: what searches find changed.
   */
  private async save(extra: SealedRecord[] = [], changes = true, deletes: string[] = []) {
    const index = this.index!
    const encode = (value: unknown) => new TextEncoder().encode(JSON.stringify(value))
    await this.store!.put([...extra, index.sealRecord(DRAFTS, encode([...this.drafts.values()])), index.sealRecord(PROGRESS, encode(this.progress))], deletes)
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
      await this.save()
    })
    void this.build()
  }

  /** Turned off: searches go back to the server; the index stays. */
  async disable(): Promise<void> {
    await this.exclusive(async () => {
      this.progress = { ...this.progress, enabled: false }
      await this.save()
    })
  }

  async pause(): Promise<void> {
    await this.exclusive(async () => {
      this.progress = { ...this.progress, paused: true }
      await this.save()
    })
  }

  async resume(): Promise<void> {
    await this.exclusive(async () => {
      this.progress = { ...this.progress, paused: false }
      await this.save()
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
    this.run.reset = true
    this.broken = false
    this.progress = FRESH
    this.drafts = new Map()
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
      if (this.progress.enabled) await this.startAgain(true)
    })
  }

  /** Whether keyword searches go to this index now. */
  get active(): boolean {
    return this.snapshot.searchable
  }

  /** Rows waiting, by id, as stored now. Under the lock (or for reading ahead of it). */
  private async pendingRows(ids: string[]): Promise<Map<string, MailMessage>> {
    const index = this.index!
    const found = await this.store!.get(ids.map((id) => index.recordId(pendingName(id))))
    const rows = new Map<string, MailMessage>()
    for (const id of ids) {
      const sealed = found.get(index.recordId(pendingName(id)))
      const plain = sealed ? index.openRecord(pendingName(id), sealed) : undefined
      if (plain) rows.set(id, JSON.parse(new TextDecoder().decode(plain)) as MailMessage)
    }
    return rows
  }

  /**
   * Rows to wait (Drafts kept by their rows instead): their records, and
   * the progress's ids. What does not fit is read again later, from the top
   * down to the oldest of it. Returns the records to store.
   */
  private wait(rows: MailMessage[]): SealedRecord[] {
    const index = this.index!
    const ids = new Set(this.progress.pending)
    const records: SealedRecord[] = []
    let over: number | null = null
    for (const row of rows) {
      if (row.folder === 'drafts') {
        this.drafts.set(row.id, row)
        continue
      }
      if (!ids.has(row.id) && ids.size >= MAX_PENDING) {
        over = Math.min(over ?? Number.POSITIVE_INFINITY, timeOf(row))
        continue
      }
      ids.add(row.id)
      records.push(index.sealRecord(pendingName(row.id), new TextEncoder().encode(JSON.stringify(row))))
    }
    const rescan = over === null ? this.progress.rescan : { cursor: null, until: Math.min(over, this.progress.rescan?.until ?? over) }
    this.progress = { ...this.progress, pending: [...ids], rescan }
    return records
  }

  /**
   * Indexes `docs` and stores them with the progress (`next` applied) in one
   * transaction, deleting `deletes`. Out of room (the browser's, or a record
   * of the index past its limit): what is indexed stays, older mail is not
   * read, and indexing is tried again later; false then. Under the lock.
   */
  private async addDocs(docs: IndexDoc[], next: Partial<Progress> = {}, deletes: string[] = []): Promise<boolean> {
    const index = this.index!
    const room = async (): Promise<false> => {
      await this.load()
      this.progress = { ...this.progress, cursor: null, started: true, limitedFrom: index.oldestTime() ?? Date.now(), roomRetryAt: Date.now() + ROOM_RETRY_MS }
      await this.save([], true)
      return false
    }
    let changed: SealedRecord[] = []
    try {
      if (docs.length) changed = index.add(docs, await this.store!.load(index.planAdd(docs)))
    } catch (error) {
      if (!tooLarge(error)) throw error
      return room()
    }
    this.progress = { ...this.progress, ...next, roomRetryAt: null }
    try {
      await this.save(changed, docs.length > 0, deletes)
      return true
    } catch (error) {
      if (!quotaExceeded(error)) throw error
      return room()
    }
  }

  /** The messages' words: subject, people and text, with their list rows. */
  private async texts(messages: MailMessage[]): Promise<IndexDoc[]> {
    const docs: IndexDoc[] = []
    const queue = [...messages]
    const next = async (): Promise<void> => {
      const message = queue.shift()
      if (!message) return
      // A message that does not open (a key gone) is found by its subject and people.
      const text = await openMessageText(this.account, message).catch(() => message.subject)
      docs.push({ id: message.id, timeMs: timeOf(message), text: `${people(message)}\n${text}`, meta: rowOf(message) })
      return next()
    }
    await Promise.all(Array.from({ length: OPEN_AT_ONCE }, next))
    return docs
  }

  /**
   * Builds from where it stopped, in one tab at a time: a page of rows is
   * read under the lock (and waits), its messages downloaded outside it, and
   * stored under it again as they wait then. Rows that did not fit are read
   * again from the top (`rescan`), only those not held waiting.
   */
  private async build(): Promise<void> {
    if (this.building) return
    const work = async () => {
      this.building = true
      try {
        for (;;) {
          const step = await this.exclusive(async () => {
            const p = this.progress
            if (!p.enabled || p.paused || this.outdated) return 'stop'
            if (p.roomRetryAt !== null && Date.now() < p.roomRetryAt) return 'stop'
            if (p.feed === null) {
              // The feed starts before the first page, so no change is missed.
              this.progress = { ...p, feed: (await changesPage(null)).next }
              await this.save([], false)
            }
            if (this.progress.pending.length) return 'index'
            if (this.progress.rescan) return this.rescanPage()
            if (this.progress.started && this.progress.cursor === null) return 'stop'
            const data = await indexPage(this.progress.cursor)
            const records = this.wait(data.messages)
            this.progress = { ...this.progress, started: true, total: data.total ?? this.progress.total, cursor: data.next }
            await this.save(records)
            return 'index'
          })
          if (step === 'stop') break
          if (step === 'index') await this.indexPending()
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

  /** One page of the newest mail read again: rows held get their rows, the rest wait. Under the lock. */
  private async rescanPage(): Promise<'index' | 'more'> {
    const index = this.index!
    const rescan = this.progress.rescan!
    const data = await indexPage(rescan.cursor)
    const rows = data.messages.filter((m) => timeOf(m) >= rescan.until)
    const others = rows.filter((m) => m.folder !== 'drafts')
    const hits: SearchHit[] = others.map((m) => ({ id: m.id, timeMs: timeOf(m), meta: rowOf(m) }))
    let records: SealedRecord[] = []
    let missing: MailMessage[] = []
    if (hits.length) {
      const updated = index.updateMeta(hits, await this.store!.load(index.planUpdateMeta(hits)))
      records = updated.stored
      const notHeld = new Set(updated.missing)
      missing = others.filter((m) => notHeld.has(m.id))
    }
    // Only as much as fits; the rest on a later pass, from this page.
    const room = MAX_PENDING - this.progress.pending.length
    if (missing.length > room) {
      await this.save(records)
      return 'index'
    }
    records.push(...this.wait([...rows.filter((m) => m.folder === 'drafts'), ...missing]))
    const done = data.next === null || rows.length < data.messages.length
    this.progress = { ...this.progress, rescan: done ? null : { ...rescan, cursor: data.next } }
    await this.save(records)
    return 'index'
  }

  /** Downloads a batch of the rows waiting outside the lock, then indexes those still waiting, with their rows as now. */
  private async indexPending(): Promise<void> {
    const ids = this.progress.pending.slice(0, BATCH)
    if (!ids.length) return
    const rows = await this.pendingRows(ids)
    const docs = await this.texts(ids.flatMap((id) => (rows.has(id) ? [rows.get(id)!] : [])))
    await this.exclusive(async () => {
      const waiting = new Set(this.progress.pending)
      const now = await this.pendingRows(ids.filter((id) => waiting.has(id)))
      const kept = docs.flatMap((doc) => {
        const row = now.get(doc.id)
        return row ? [{ ...doc, timeMs: timeOf(row), meta: rowOf(row) }] : []
      })
      // Done: indexed, or a row that no longer reads (left to a rebuild).
      const done = new Set(ids)
      const deletes = ids.map((id) => this.index!.recordId(pendingName(id)))
      await this.addDocs(kept, { pending: this.progress.pending.filter((id) => !done.has(id)) }, deletes)
    })
  }

  /** One page of the change feed, applied (no download). Under the lock. */
  private async followFeed(): Promise<'more' | 'done' | 'resync'> {
    const p = this.progress
    if (!p.enabled || p.paused || p.feed === null || this.outdated) return 'done'
    const index = this.index!
    const data = await changesPage(p.feed)
    if (data.resync) return 'resync'
    if (!data.changed.length && !data.gone.length) {
      if (data.next !== p.feed) {
        this.progress = { ...p, feed: data.next }
        await this.save([], false)
      }
      return data.more ? 'more' : 'done'
    }
    const goneIds = new Set(data.gone.map((g) => g.id))
    const drafts = data.changed.filter((m) => m.folder === 'drafts')
    const rows = data.changed.filter((m) => m.folder !== 'drafts')
    // Drafts: kept by their rows; one sent or deleted leaves them.
    for (const id of goneIds) this.drafts.delete(id)
    for (const row of rows) this.drafts.delete(row.id)
    for (const row of drafts) this.drafts.set(row.id, row)
    // Waiting rows follow their messages, or go with them.
    const waiting = new Set(p.pending)
    const leaving = new Set([...goneIds, ...drafts.map((d) => d.id)].filter((id) => waiting.has(id)))
    const records: SealedRecord[] = rows
      .filter((row) => waiting.has(row.id))
      .map((row) => index.sealRecord(pendingName(row.id), new TextEncoder().encode(JSON.stringify(row))))
    const deletes = [...leaving].map((id) => index.recordId(pendingName(id)))
    this.progress = { ...p, pending: p.pending.filter((id) => !leaving.has(id)) }
    // The index: gone ones removed, changed ones given their rows.
    const removed: DocRef[] = [...data.gone.map((g) => ({ id: g.id, timeMs: timeOf(g) })), ...drafts.map((m) => ({ id: m.id, timeMs: timeOf(m) }))]
    if (removed.length) records.push(...index.remove(removed, await this.store!.load(index.planRemove(removed))))
    const held: SearchHit[] = rows.filter((m) => !waiting.has(m.id)).map((m) => ({ id: m.id, timeMs: timeOf(m), meta: rowOf(m) }))
    let missing: MailMessage[] = []
    if (held.length) {
      // Tables `remove` changed are read as just written.
      const loaded = await this.store!.load(index.planUpdateMeta(held))
      const written = new Map(records.map((r) => [r.id, r.sealed]))
      const updated = index.updateMeta(
        held,
        loaded.map((l) => ({ ...l, sealed: written.get(index.recordId(l.name)) ?? l.sealed })),
      )
      const replaced = new Set(updated.stored.map((r) => r.id))
      records.splice(0, records.length, ...records.filter((r) => !replaced.has(r.id)), ...updated.stored)
      const notHeld = new Set(updated.missing)
      missing = rows.filter((m) => notHeld.has(m.id))
    }
    // Not held: new mail waits to be indexed; one the build has yet to reach
    // is left to it (it reads the row as it is then).
    const building = !p.started || p.cursor !== null
    const reach = p.cursor === null ? Number.POSITIVE_INFINITY : cursorTime(p.cursor)
    const fresh = missing.filter((m) => !(building && (!p.started || timeOf(m) <= reach)))
    records.push(...this.wait(fresh))
    this.progress = { ...this.progress, feed: data.next }
    await this.save(records, true, deletes)
    return data.more ? 'more' : 'done'
  }

  /**
   * Follows the change feed (Mail's poll, and before every search); new mail
   * and a build that stopped go on. One at a time per tab. While a step
   * fails, searches go to the server (no row may be out of date).
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
    try {
      for (let page = 0; page < 20; page++) {
        const step = await this.exclusive(() => this.followFeed())
        if (step === 'resync') {
          await this.rebuild()
          return
        }
        if (step === 'done') break
      }
      if (this.stale) {
        this.stale = false
        this.publish()
      }
    } catch (error) {
      if (!this.stale) {
        this.stale = true
        this.publish()
      }
      throw error
    }
    const p = this.progress
    if (!p.paused && (p.cursor !== null || !p.started || p.pending.length || p.rescan)) void this.build()
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
        const { found, needed } = index.search(query, periods, await this.store!.load(index.planSearch(query, periods)))
        for (const hit of found.length ? index.hits(found, await this.store!.load(needed)) : []) {
          try {
            out.push(JSON.parse(hit.meta) as MailMessage)
          } catch {
            // A row that does not read is left out, and the index made again below.
            unreadable = true
          }
        }
        before = periods[periods.length - 1]
      }
      for (const draft of this.drafts.values()) {
        if (this.matches(query, `${draft.subject}\n${people(draft)}`)) out.push(draft)
      }
      return { out, damaged: !index.newer() && (unreadable || index.damaged()) }
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

const OFF: ContentSearchState = { status: 'off', searchable: false, indexed: 0, total: 0, limitedFrom: null, revision: 0 }

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
