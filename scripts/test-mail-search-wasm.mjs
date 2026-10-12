// Mail's search index WASM module end to end (docs/plans/mail-body-search.md):
// index messages over sealed records kept in a plain Map (as IndexedDB keeps
// them), search them, reopen from the directory, remove one; nothing stored
// shows a word or a record's name.
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
const index = new wasm.MailSearch(masterKey)
assert.equal(index.openDirectory(undefined), false)
const docs = [
  { id: 'm1', timeMs: t0, text: 'Ekim faturası ektedir' },
  { id: 'm2', timeMs: t0 + 40 * day, text: 'Fatura ödendi, teşekkürler' },
  { id: 'm3', timeMs: t0 + 80 * day, text: 'İstanbul toplantısı' },
]
keep(index.add(docs, load(index.planAdd(docs))))
assert.equal(index.size(), 3)

const search = (target, query) => {
  const periods = target.nextPeriods(undefined, 100)
  return target.search(query, periods, load(target.planSearch(query, periods))).map((hit) => hit.id)
}
assert.deepEqual(search(index, 'fatura'), ['m2', 'm1'])
assert.deepEqual(search(index, 'istanbul'), ['m3'])
assert.deepEqual(search(index, 'TESEKKUR'), ['m2'])
assert.deepEqual(search(index, 'yok'), [])

// Reopened from the stored directory alone.
const again = new wasm.MailSearch(masterKey)
assert.equal(again.openDirectory(store.get(again.directoryId())), true)
assert.deepEqual(search(again, 'fatura ekim'), ['m1'])

// Removed: never found again.
const gone = [{ id: 'm1', timeMs: t0 }]
keep(again.remove(gone, load(again.planRemove([t0]))))
assert.deepEqual(search(again, 'fatura'), ['m2'])

// Another account (another master key) opens nothing, and its database has another name.
assert.notEqual(new wasm.MailSearch(new Uint8Array(32).fill(0x5b)).storeName(), index.storeName())
const other = new wasm.MailSearch(new Uint8Array(32).fill(0x5b))
assert.equal(other.openDirectory(store.get(index.directoryId())), false)

// Nothing stored shows a word or a name.
const decoder = new TextDecoder('utf-8', { fatal: false })
for (const [id, sealed] of store) {
  assert.match(id, /^[0-9a-f]{64}$/)
  const text = decoder.decode(sealed)
  for (const word of ['fatura', 'ekim', 'istanbul', 'shard', 'docs', 'm1']) assert.ok(!text.includes(word), `${word} in a sealed record`)
}

// A larger mailbox stays quick.
const many = Array.from({ length: 5000 }, (_, i) => ({ id: `n${i}`, timeMs: t0 + Math.floor(i / 10) * day, text: `ileti ${i} toplantı rapor kelime${i % 50}` }))
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
