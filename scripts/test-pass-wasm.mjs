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
// (password, keepPassword, keyFile, keepKeyFile, now)
assert.deepEqual(ours.keyParts(), { password: true, keyFile: false })
assert.throws(() => ours.changeKey(null, false, null, false, minute(8)), /password or a key file/)
assert.throws(() => ours.changeKey('yeni', true, null, false, minute(8)))
// Undone: back to the key Drive's copy opens with.
ours.changeKey('geçici', false, null, false, minute(8))
ours.abandonKeyChange()
assert.ok(pass.Vault.open(ours.save(), 'parola-çğ', null, null))
ours.changeKey('yeni', false, null, false, minute(8))
// Not kept before Drive holds it: Drive's copy still opens with the old key.
const keepArgs = [new Uint8Array(32), '6f1d2c3b-4a59-4e8f-9a0b-1c2d3e4f5a6b', '3f1c9a52-6b7e-4f0e-9d1a-2c3b4d5e6f70', 1, false]
assert.throws(() => ours.keepKey(...keepArgs))
const rekeyed = ours.save()
assert.throws(() => ours.keepKey(...keepArgs), /save the vault/)
ours.keyChangeSaved()
assert.ok(ours.keepKey(...keepArgs))
assert.ok(pass.Vault.open(rekeyed, 'yeni', null, null))
assert.throws(() => pass.Vault.open(rekeyed, 'parola-çğ', null, null))

// A generated key file (KeePassXC's XML v2) added, the password kept.
const keyFile = pass.generateKeyFile()
assert.match(Buffer.from(keyFile).toString(), /<Version>2\.0<\/Version>[\s\S]*<Data Hash="[0-9A-F]{8}">/)
const withFile = pass.Vault.open(rekeyed, 'yeni', null, null)
withFile.changeKey(null, true, keyFile, false, minute(9))
assert.deepEqual(withFile.keyParts(), { password: true, keyFile: true })
const filed = withFile.save()
assert.ok(pass.Vault.open(filed, 'yeni', null, keyFile))
assert.throws(() => pass.Vault.open(filed, 'yeni', null, null))

// Kept vault keys (kutup_pass::kept): the checked-in vectors open, and a key
// kept from an open vault opens it again, for this account and vault only.
const vectors = JSON.parse(await readFile(`${root}/crates/kutup-crypto/tests/vectors/pass-vault-secret-v2.json`, 'utf8'))
const masterKey = Buffer.from(vectors.masterKey, 'base64')
assert.deepEqual(pass.openKept(vectors.sealedChosen, masterKey, vectors.binding, vectors.fileId), {
  passwordHash: vectors.chosenPasswordHash,
  keyFile: vectors.keyFile,
  generatedPassword: null,
  revision: vectors.revision,
})
const shown = pass.openKept(vectors.sealedGenerated, masterKey, vectors.binding, vectors.fileId)
assert.equal(shown.generatedPassword, vectors.generatedPassword)
assert.equal(shown.keyFile, null)
assert.throws(() => pass.openKept(vectors.sealedChosen, masterKey, vectors.binding, '00000000-0000-4000-8000-000000000000'))
assert.throws(() => pass.openKept(vectors.sealedChosen, masterKey, 'another-binding', vectors.fileId))
assert.throws(() => pass.openKept(vectors.sealedChosen, new Uint8Array(32), vectors.binding, vectors.fileId))
const kept = pass.Vault.open(rekeyed, 'yeni', null, null).keepKey(masterKey, vectors.binding, vectors.fileId, vectors.revision + 5, true)
const keptKey = pass.openKept(kept, masterKey, vectors.binding, vectors.fileId)
assert.equal(keptKey.generatedPassword, 'yeni')
assert.equal(keptKey.revision, vectors.revision + 5)
// Every kind of key is one length (the envelope's fixed padding).
assert.equal(Buffer.from(kept, 'base64').length, Buffer.from(vectors.sealedChosen, 'base64').length)
// A revision that is not a positive safe integer is refused.
for (const bad of [0, -1, 1.5]) {
  assert.throws(() => pass.Vault.open(rekeyed, 'yeni', null, null).keepKey(masterKey, vectors.binding, vectors.fileId, bad, true))
}
// The revision is authenticated: the checked-in key opens at its revision,
// and the same envelope with the revision changed in its header does not.
const chosenEnvelope = Buffer.from(vectors.sealedChosen, 'base64')
assert.equal(pass.openKept(vectors.sealedChosen, masterKey, vectors.binding, vectors.fileId).revision, vectors.revision)
// Header: ... revision (8 bytes) | nonce (24) | ciphertext length (4) | ciphertext (3121 + 16).
const lastRevisionByte = chosenEnvelope.length - (3121 + 16) - 4 - 24 - 1
assert.equal(chosenEnvelope.readBigUInt64BE(lastRevisionByte - 7), BigInt(vectors.revision))
const relabelled = Buffer.from(chosenEnvelope)
relabelled[lastRevisionByte] ^= 2
assert.throws(() => pass.openKept(relabelled.toString('base64'), masterKey, vectors.binding, vectors.fileId))
assert.ok(pass.Vault.open(rekeyed, null, Buffer.from(keptKey.passwordHash, 'base64'), null))
// Opened with a kept key, only the password's hash is known: kept as that
// hash when chosen; a generated one needs the password itself.
assert.ok(byHash.keepKey(masterKey, vectors.binding, vectors.fileId, 1, false))
assert.throws(() => byHash.keepKey(masterKey, vectors.binding, vectors.fileId, 1, true))
console.log('pass WASM checks passed')
