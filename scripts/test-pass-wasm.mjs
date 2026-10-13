// The Kutup Pass WASM module end to end (docs/plans/pass.md, K2b): create a
// vault, edit it with the website's operations, save and reopen it, merge two
// edited copies, read one-time codes and attachments.
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('..', import.meta.url))
const pass = await import(new URL('../frontend/wasm/pass-wasm/kutup_pass_wasm.js', import.meta.url))
await pass.default({ module_or_path: await readFile(`${root}/frontend/wasm/pass-wasm/kutup_pass_wasm_bg.wasm`) })

const t0 = Date.UTC(2026, 9, 12, 9, 0, 0)
const minute = (n) => t0 + n * 60_000
const fields = (pairs) => pairs.map(([key, value]) => ({ key, value, protected: false }))

const started = performance.now()
const vault = pass.Vault.create('Kişisel', 'parola-çğ', null, minute(0))
const root0 = vault.view().rootGroupId
const bank = vault.apply({ op: 'createEntry', groupId: root0, entry: { fields: fields([['Title', 'Banka'], ['UserName', 'ayse'], ['Password', 'p0']]) } }, minute(1)).id
const saved = vault.save()
const reopened = pass.Vault.open(saved, 'parola-çğ', null, null)
console.log(`create + save + open (Argon2id 64 MiB, 10 iterations): ${Math.round(performance.now() - started)} ms`)
assert.equal(reopened.view().entries[0].fields.find((f) => f.key === 'Password').value, 'p0')
assert.equal(reopened.view().entries[0].fields.find((f) => f.key === 'Password').protected, true)
assert.throws(() => pass.Vault.open(saved, 'wrong', null, null))
assert.throws(() => reopened.apply({ op: 'deleteEntry', id: 'not-an-id' }, minute(2)))
// What Kutup Pass keeps: the password's SHA-256 opens it, and saves it so the
// password still opens it.
const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode('parola-çğ')))
const byHash = pass.Vault.open(saved, null, hash, null)
assert.equal(byHash.view().entries.length, 1)
assert.ok(pass.Vault.open(byHash.save(), 'parola-çğ', null, null))
assert.throws(() => pass.Vault.open(saved, null, new Uint8Array(32), null))
assert.throws(() => pass.Vault.open(saved, null, new Uint8Array(31), null))
assert.throws(() => pass.Vault.open(saved, 'parola-çğ', hash, null))

// Two copies edited apart, then merged.
const ours = pass.Vault.open(saved, 'parola-çğ', null, null)
const theirs = pass.Vault.open(saved, 'parola-çğ', null, null)
ours.apply({ op: 'updateEntry', id: bank, entry: { fields: fields([['Title', 'Banka'], ['UserName', 'ayse'], ['Password', 'ours']]) } }, minute(2))
theirs.apply({ op: 'updateEntry', id: bank, entry: { fields: fields([['Title', 'Banka'], ['UserName', 'ayse-t'], ['Password', 'p0']]) } }, minute(3))
const mail = theirs.apply({ op: 'createEntry', groupId: root0, entry: { fields: fields([['Title', 'Posta']]) } }, minute(4)).id
const outcome = ours.mergeWith(saved, theirs.save(), null, null)
assert.equal(outcome.report.conflicts.length, 0)
assert.equal(outcome.differsFromTheirs, true)
const merged = ours.view()
const entry = merged.entries.find((e) => e.id === bank)
assert.equal(entry.fields.find((f) => f.key === 'Password').value, 'ours')
assert.equal(entry.fields.find((f) => f.key === 'UserName').value, 'ayse-t')
assert.ok(merged.entries.some((e) => e.id === mail))

// Recycle bin, history, attachments, one-time codes.
ours.apply({ op: 'deleteEntry', id: mail }, minute(5))
assert.ok(ours.view().recycleBinId)
assert.equal(ours.history(bank).length >= 1, true)
ours.apply({ op: 'addAttachment', entryId: bank, name: 'not.txt', data: Buffer.from('merhaba').toString('base64') }, minute(6))
assert.equal(Buffer.from(ours.attachment(bank, 'not.txt')).toString(), 'merhaba')
const twoFa = ours.apply({ op: 'createEntry', groupId: root0, entry: { fields: fields([['Title', '2FA'], ['otp', 'otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&period=30']]) } }, minute(7)).id
assert.deepEqual(ours.otp(twoFa, 59_000), { code: '94287082', period: 30, remaining: 1 })
assert.equal(ours.otp(bank, 59_000), null)

// A key changed: the new one opens the saved vault, the old one does not.
ours.changeKey('yeni', null, minute(8))
const rekeyed = ours.save()
assert.ok(pass.Vault.open(rekeyed, 'yeni', null, null))
assert.throws(() => pass.Vault.open(rekeyed, 'parola-çğ', null, null))

assert.equal(pass.keyFileSecret(new Uint8Array(10_000)).length, 32)
console.log('pass WASM checks passed')
