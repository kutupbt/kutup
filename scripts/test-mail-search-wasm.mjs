// Mail's search index WASM module end to end (docs/plans/mail-body-search.md):
// index messages over sealed records kept in a plain Map (as IndexedDB keeps
// them), search them with their list rows, reopen from the directory and the
// wrapped store key, update a row, remove one; nothing stored shows a word or
// a record's name, and a new store key opens nothing of the old one.
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('..', import.meta.url))
const wasm = await import(new URL('../frontend/wasm/mail-search-wasm/kutup_mail_search_wasm.js', import.meta.url))
await wasm.default({ module_or_path: await readFile(`${root}/frontend/wasm/mail-search-wasm/kutup_mail_search_wasm_bg.wasm`) })

const masterKey = new Uint8Array(32).fill(0x5a)
const store = new Map()
const load = (needed) => needed.filter(({ id }) => store.has(id)).map(({ name, id }) => ({ name, sealed: store.get(id) }))
const keep = (sealed) => sealed.forEach(({ id, sealed }) => store.set(id, sealed))

const day = 24 * 60 * 60 * 1000
const t0 = Date.UTC(2026, 9, 1)
const index = new wasm.MailSearch(masterKey, undefined)
const wrapped = index.wrappedStoreKey()
assert.equal(wrapped.length, 82)
assert.equal(index.openDirectory(undefined), false)
// Each list row carries a long marker: the check below looks for it in the
// sealed bytes (a word of two or three letters turns up in random bytes by
// chance; one of twenty does not).
const ROW_MARKER = 'rowmarker7f3a9c1e5b2d'
const row = (id, folder) => JSON.stringify({ id, folder, marker: `${ROW_MARKER}-${id}` })
const docs = [
  { id: 'm1', timeMs: t0, text: 'Ekim faturası ektedir', meta: row('m1', 'inbox') },
  { id: 'm2', timeMs: t0 + 40 * day, text: 'Fatura ödendi, teşekkürler', meta: row('m2', 'inbox') },
  { id: 'm3', timeMs: t0 + 80 * day, text: 'İstanbul toplantısı', meta: row('m3', 'archive') },
]
keep(index.add(docs, load(index.planAdd(docs))))
assert.equal(index.size(), 3)

const hits = (target, query) => {
  const periods = target.nextPeriods(undefined, 100)
  const { found, needed } = target.search(query, periods, load(target.planSearch(query, periods)))
  return target.hits(found, load(needed))
}
const search = (target, query) => hits(target, query).map((hit) => hit.id)
assert.deepEqual(search(index, 'fatura'), ['m2', 'm1'])
assert.deepEqual(search(index, 'istanbul'), ['m3'])
assert.deepEqual(search(index, 'TESEKKUR'), ['m2'])
assert.deepEqual(search(index, 'yok'), [])

assert.deepEqual(hits(index, 'istanbul')[0].meta, row('m3', 'archive'))

// Reopened from the wrapped store key and the stored directory alone.
const again = new wasm.MailSearch(masterKey, wrapped)
assert.equal(again.openDirectory(store.get(again.directoryId())), true)
assert.deepEqual(search(again, 'fatura ekim'), ['m1'])

// A row changes (moved to the trash) without indexing the text again.
const changes = [
  { id: 'm2', timeMs: t0 + 40 * day, meta: row('m2', 'trash') },
  { id: 'm9', timeMs: t0 + 40 * day, meta: row('m9', 'inbox') },
]
const updated = again.updateMeta(changes, load(again.planUpdateMeta(changes)))
keep(updated.stored)
assert.deepEqual(updated.missing, ['m9'])
assert.deepEqual(hits(again, 'odendi')[0].meta, row('m2', 'trash'))

// Removed: never found again.
const gone = [{ id: 'm1', timeMs: t0 }]
keep(again.remove(gone, load(again.planRemove(gone))))
assert.deepEqual(search(again, 'fatura'), ['m2'])

// Another account (another master key) cannot unwrap the store key, and its database has another name.
const otherKey = new Uint8Array(32).fill(0x5b)
assert.notEqual(wasm.MailSearch.storeName(otherKey), wasm.MailSearch.storeName(masterKey))
assert.match(wasm.MailSearch.storeName(masterKey), /^[0-9a-f]{32}$/)
assert.throws(() => new wasm.MailSearch(otherKey, wrapped))

// A new store key (the index deleted and made again) opens nothing of the old
// one: the directory reads as empty, and records that do not open mark it damaged.
// one: its directory does not open, so the index is damaged and writes nothing.
const fresh = new wasm.MailSearch(masterKey, undefined)
assert.equal(fresh.openDirectory(undefined), false)
assert.equal(fresh.damaged(), false)
assert.equal(fresh.openDirectory(store.get(index.directoryId())), false)
assert.equal(fresh.damaged(), true)
assert.throws(() => fresh.add(docs, []), /damaged/)
// A record that does not open marks it too.
const other2 = new wasm.MailSearch(masterKey, undefined)
const stale = [...store].map(([, sealed]) => ({ name: 'shard/0/fat', sealed }))
other2.search('fatura', [0], stale.slice(0, 1))
assert.equal(other2.damaged(), true)

// A directory of a newer version: this page writes nothing, and it is not damage to wipe.
const enc = new TextEncoder()
const cbor = new Uint8Array([0xa2, 0x67, ...enc.encode('version'), 0x04, 0x67, ...enc.encode('periods'), 0xa0])
const ahead = new wasm.MailSearch(masterKey, wrapped)
assert.equal(ahead.openDirectory(ahead.sealRecord('dir', cbor).sealed), false)
assert.equal(ahead.newer(), true)
assert.throws(() => ahead.add(docs, []), /damaged/)
assert.equal(again.newer(), false)

// Drafts are matched outside the index, by the same rule.
assert.equal(wasm.MailSearch.matches('ofis istanbul', 'İstanbul ofisi taslak'), true)
assert.equal(wasm.MailSearch.matches('ofis ankara', 'İstanbul ofisi'), false)

// Nothing stored shows a word or a name.
const decoder = new TextDecoder('utf-8', { fatal: false })
for (const [id, sealed] of store) {
  assert.match(id, /^[0-9a-f]{64}$/)
  const text = decoder.decode(sealed)
  for (const word of ['fatura', 'istanbul', 'toplant', ROW_MARKER]) assert.ok(!text.includes(word), `${word} in a sealed record`)
}

// A larger mailbox stays quick.
const many = Array.from({ length: 5000 }, (_, i) => ({ id: `n${i}`, timeMs: t0 + Math.floor(i / 10) * day, text: `ileti ${i} toplantı rapor kelime${i % 50}`, meta: row(`n${i}`, 'inbox') }))
const started = performance.now()
for (let i = 0; i < many.length; i += 50) {
  const batch = many.slice(i, i + 50)
  keep(index.add(batch, load(index.planAdd(batch))))
}
const built = performance.now() - started
const found = search(index, 'kelime7')
const searched = performance.now() - started - built
console.log(`5,000 messages indexed in ${Math.round(built)} ms; a search over them in ${Math.round(searched)} ms; ${store.size} sealed records`)
assert.equal(found.length, 100)
console.log('mail search wasm: ok')
