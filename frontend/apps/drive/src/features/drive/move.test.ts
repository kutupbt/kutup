import { describe, expect, it } from 'vitest'
import type { FolderIndex } from './folders'
import type { DriveFile, Folder } from './model'
import { moveRefusal } from './move'

const key = new Uint8Array(32)

function folder(id: string, parentId: string | null, over: Partial<Folder> = {}): Folder {
  return {
    source: 'owned',
    id,
    parentId,
    name: id,
    key,
    keyEpoch: 1,
    ownerUserId: 'me',
    ownerAuthorityPublicKey: '',
    epochStatementHash: '',
    nameRevision: 1,
    color: null,
    createdAt: '',
    updatedAt: '',
    ownerAccount: null,
    canUpload: true,
    canDelete: true,
    canManage: true,
    isRoot: false,
    ...over,
  }
}

const root = folder('root', null, { isRoot: true })
const a = folder('a', 'root')
const b = folder('b', 'a')
const c = folder('c', 'root')
const theirs = folder('theirs', null, { source: 'shared', ownerUserId: 'them', canManage: false })
const theirsViewOnly = folder('view', null, { source: 'shared', ownerUserId: 'them', canManage: false, canUpload: false })
const theirsOther = folder('theirs2', null, { source: 'shared', ownerUserId: 'them', canManage: false })
const remote = folder('remote', null, { source: 'remote', remoteShareId: 's1', ownerUserId: 'far', canManage: false })
const locked = folder('locked', 'root', { key: null })
const all = [root, a, b, c, theirs, theirsViewOnly, theirsOther, remote, locked]
const index = { byId: new Map(all.map((f) => [f.id, f])), root } as FolderIndex

const file = { id: 'f1', fileKey: key } as DriveFile

describe('moveRefusal — files', () => {
  it('moves between folders of one owner that the user can edit', () => {
    expect(moveRefusal(index, { folder: a, file }, c)).toBeNull()
    expect(moveRefusal(index, { folder: theirs, file }, theirsOther)).toBeNull()
  })

  it('refuses the same folder, a view-only end, another owner, another server, a locked folder', () => {
    expect(moveRefusal(index, { folder: a, file }, a)).toBe('alreadyThere')
    expect(moveRefusal(index, { folder: a, file }, theirsViewOnly)).toBe('readOnly')
    expect(moveRefusal(index, { folder: theirsViewOnly, file }, theirs)).toBe('readOnly')
    expect(moveRefusal(index, { folder: a, file }, theirs)).toBe('otherOwner')
    expect(moveRefusal(index, { folder: a, file }, remote)).toBe('remote')
    expect(moveRefusal(index, { folder: remote, file }, a)).toBe('remote')
    expect(moveRefusal(index, { folder: a, file }, locked)).toBe('locked')
  })
})

describe('moveRefusal — folders', () => {
  it('moves an owned folder under another owned folder', () => {
    expect(moveRefusal(index, { folder: b }, c)).toBeNull()
    expect(moveRefusal(index, { folder: b }, root)).toBeNull()
  })

  it('never into itself or anything inside it', () => {
    expect(moveRefusal(index, { folder: a }, a)).toBe('intoItself')
    expect(moveRefusal(index, { folder: a }, b)).toBe('intoItself')
  })

  it('refuses where it already is, folders the user does not own, and other owners', () => {
    expect(moveRefusal(index, { folder: b }, a)).toBe('alreadyThere')
    expect(moveRefusal(index, { folder: theirs }, theirsOther)).toBe('notOwner')
    expect(moveRefusal(index, { folder: c }, theirs)).toBe('otherOwner')
  })
})
