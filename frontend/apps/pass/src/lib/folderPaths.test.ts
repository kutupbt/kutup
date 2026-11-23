import { describe, expect, it } from 'vitest'
import type { Folder } from '@kutup/drive-core/model'
import { canMakeSubfolder, vaultFolderChoices } from './folderPaths'

const folder = (id: string, over: Partial<Folder> = {}): Folder =>
  ({
    source: 'owned',
    id,
    parentId: 'root',
    name: id,
    key: new Uint8Array(32),
    canUpload: true,
    canDelete: true,
    canManage: true,
    isRoot: false,
    ...over,
  }) as Folder

const names = { myFiles: 'My files', unnamed: 'Folder' }

describe('where a new vault can go', () => {
  it('names folders by their path, My files first, subfolders at any depth', () => {
    const folders = [
      folder('Inner', { parentId: 'Outer' }),
      folder('root', { parentId: null, isRoot: true, name: null }),
      folder('Outer'),
      folder('Deep', { parentId: 'Inner' }),
      folder('Banks', { parentId: 'Outer2' }),
      folder('Outer2', { name: 'Other' }),
    ]
    expect(vaultFolderChoices(folders, names).map((c) => c.path)).toEqual([
      'My files',
      'My files / Other',
      'My files / Other / Banks',
      'My files / Outer',
      'My files / Outer / Inner',
      'My files / Outer / Inner / Deep',
    ])
  })

  it('leaves out what a vault cannot be saved in, and starts a shared folder at itself', () => {
    const folders = [
      folder('root', { parentId: null, isRoot: true }),
      folder('closed', { key: null }),
      folder('readOnly', { canUpload: false }),
      folder('remote', { source: 'remote' }),
      folder('theirs', { source: 'shared', parentId: 'notListed', canManage: false }),
      folder('unnamed', { name: null }),
    ]
    expect(vaultFolderChoices(folders, names).map((c) => c.path)).toEqual(['My files', 'My files / Folder', 'theirs'])
  })

  it('survives a parent loop', () => {
    const folders = [folder('a', { parentId: 'b' }), folder('b', { parentId: 'a' })]
    expect(vaultFolderChoices(folders, names).map((c) => c.path)).toEqual(['a / b', 'b / a'])
  })

  it('makes subfolders only where Drive does: in folders the account manages', () => {
    expect(canMakeSubfolder(folder('a'))).toBe(true)
    expect(canMakeSubfolder(folder('a', { source: 'shared', canManage: false }))).toBe(false)
    expect(canMakeSubfolder(folder('a', { key: null }))).toBe(false)
    expect(canMakeSubfolder(folder('a', { canUpload: false }))).toBe(false)
    expect(canMakeSubfolder(undefined)).toBe(false)
  })
})
