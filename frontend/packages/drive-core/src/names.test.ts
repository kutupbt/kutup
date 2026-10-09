// @vitest-environment node
import { describe, expect, it, vi } from 'vitest'
vi.mock('@kutup/crypto/rustWasm', async () => {
  const [{ readFile }, module] = await Promise.all([
    import('node:fs/promises'),
    import('../../../wasm/crypto-wasm/kutup_crypto_wasm.js'),
  ])
  const wasm = await readFile(new URL('../../../wasm/crypto-wasm/kutup_crypto_wasm_bg.wasm', import.meta.url))
  await module.default({ module_or_path: wasm })
  return { getCryptoWasm: () => Promise.resolve(module) }
})

import vectors from '../../../../crates/kutup-crypto/tests/vectors/crypto.json'
import { hashBlob } from '@kutup/crypto/contentHash'
import { canonicalName as rustCanonicalName } from '@kutup/crypto/driveNames'
import { UploadNameTaken } from '@kutup/files/upload/streamUpload'
import type { DriveFile, Folder } from './model'
import {
  asNameTaken,
  canonicalName,
  contentHashIn,
  freeName,
  inFolder,
  nameHashIn,
  nameTakenFromBody,
  namesIn,
  planUpload,
  unnumberedName,
} from './names'

describe('canonical names', () => {
  it('fold on this device as Rust folds them', async () => {
    const names = [
      ...vectors.driveNames.names.map((c) => c.name),
      'İstanbul.md',
      'ıIiİ',
      'ŞEKER',
      'ΟΔΟΣ.txt',
      'Σ',
      'STRASSE straße',
      'ﬃ',
      'ǅ',
      'Ⅻ',
      'K', // Kelvin sign
      'Å', // Ångström sign
      'ȩ́',
      '📄 Notes',
      'ＦＵＬＬ',
    ]
    for (const name of names) expect(canonicalName(name), name).toBe(await rustCanonicalName(name))
  })
})

describe('free names', () => {
  const taken = (...names: string[]) => new Set(names.map(canonicalName))

  it('number before the extension, counting on', () => {
    expect(freeName('a.txt', taken())).toBe('a.txt')
    expect(freeName('a.txt', taken('A.TXT'))).toBe('a (2).txt')
    expect(freeName('a.txt', taken('a.txt', 'a (2).txt'))).toBe('a (3).txt')
    expect(freeName('a (5).txt', taken('a (5).txt'))).toBe('a (6).txt')
    expect(freeName('Photos', taken('photos'))).toBe('Photos (2)')
    expect(freeName('.env', taken('.env'))).toBe('.env (2)')
    expect(freeName('archive.tar.gz', taken('archive.tar.gz'))).toBe('archive.tar (2).gz')
  })

  it('come back to what they were numbered from', () => {
    expect(unnumberedName('IMG_0001 (2).jpg')).toBe('IMG_0001.jpg')
    expect(unnumberedName('Photos (3)')).toBe('Photos')
    expect(unnumberedName('a(2).txt')).toBe('a(2).txt')
    expect(unnumberedName('.env (2)')).toBe('.env')
  })

  it('collect a folder’s files and subfolders together', () => {
    const names = namesIn([{ name: 'Report.pdf' }, { name: null }], [{ name: 'Docs' }])
    expect([...names].sort()).toEqual(['docs', 'report.pdf'])
  })
})

describe('a taken name', () => {
  it('is read from the server’s 409', () => {
    const taken = nameTakenFromBody(409, { error: 'x', code: 'name_taken', holder: { kind: 'file', id: 'f1', contentHash: 'c' } })
    expect(taken?.holder).toEqual({ kind: 'file', id: 'f1', contentHash: 'c' })
    expect(nameTakenFromBody(409, { error: 'x', code: 'name_taken' })?.holder).toBeNull()
    expect(nameTakenFromBody(409, { error: 'folder key changed' })).toBeNull()
    expect(nameTakenFromBody(400, { code: 'name_taken' })).toBeNull()
  })

  it('is recognised from an upload too', () => {
    const taken = asNameTaken(new UploadNameTaken({ kind: 'folder', id: 'd1', contentHash: null }))
    expect(taken?.holder).toEqual({ kind: 'folder', id: 'd1', contentHash: null })
    expect(asNameTaken(new Error('other'))).toBeNull()
  })
})

describe('planning an upload', () => {
  const folder = {
    id: '11111111-1111-4111-8111-111111111111',
    source: 'owned',
    key: new Uint8Array(32).fill(7),
    keyEpoch: 1,
  } as Folder
  const file = (name: string, size: number, contentHash: string | null = null) =>
    ({ id: `id-${name}`, name, size, contentHash }) as DriveFile
  const local = (name: string, text: string) => new File([text], name)

  it('uploads under a free name', async () => {
    expect(await planUpload(folder, local('a.txt', 'hi'), { files: [file('b.txt', 2)], subfolders: [] })).toEqual({ kind: 'free' })
  })

  it('skips the same file under the same name, case aside', async () => {
    const digest = await hashBlob(new Blob(['hello']))
    const holder = file('Notes.TXT', 5, await contentHashIn(folder, digest))
    const plan = await planUpload(folder, local('notes.txt', 'hello'), { files: [holder], subfolders: [] })
    expect(plan).toEqual({ kind: 'same', holder })
  })

  it('asks when the content differs, is unknown, or a folder holds the name', async () => {
    const digest = await hashBlob(new Blob(['hello']))
    const known = file('notes.txt', 5, await contentHashIn(folder, digest))
    expect((await planUpload(folder, local('notes.txt', 'HELLO'), { files: [known], subfolders: [] })).kind).toBe('taken')
    expect((await planUpload(folder, local('notes.txt', 'hello!'), { files: [known], subfolders: [] })).kind).toBe('taken')
    expect((await planUpload(folder, local('notes.txt', 'hello'), { files: [file('notes.txt', 5)], subfolders: [] })).kind).toBe('taken')
    const sub = { name: 'Notes.txt' } as Folder
    expect(await planUpload(folder, local('notes.txt', 'x'), { files: [], subfolders: [sub] })).toEqual({
      kind: 'taken',
      holder: { kind: 'folder', folder: sub },
    })
  })

  it('hashes names under the folder’s hash key: case aside, per folder', async () => {
    const hash = await nameHashIn(inFolder(folder), 'Report.pdf')
    expect(hash).toMatch(/^[0-9a-f]{64}$/)
    expect(await nameHashIn(inFolder(folder), 'report.PDF')).toBe(hash)
    const other = { ...folder, id: '22222222-2222-4222-8222-222222222222' }
    expect(await nameHashIn(inFolder(other), 'Report.pdf')).not.toBe(hash)
  })
})
