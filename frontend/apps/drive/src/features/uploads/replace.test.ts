import { beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  streamVersionUpload: vi.fn(),
  resumeUpload: vi.fn(),
  list: vi.fn(),
  remove: vi.fn(),
  del: vi.fn(),
}))

vi.mock('@kutup/files/upload/streamUpload', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@kutup/files/upload/streamUpload')>()
  return { ...actual, streamVersionUpload: mocks.streamVersionUpload, resumeUpload: mocks.resumeUpload }
})
vi.mock('@kutup/files/upload/pendingUploads', () => ({ pendingUploads: { list: mocks.list, remove: mocks.remove } }))
vi.mock('@kutup/drive-core/rekey', () => ({ rekeyFile: (_folder: unknown, file: unknown) => Promise.resolve(file) }))
vi.mock('@kutup/drive-core/names', () => ({ contentHashIn: () => Promise.resolve('cd'.repeat(32)) }))
vi.mock('@kutup/crypto/contentHash', () => ({ hashBlob: () => Promise.resolve('BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=') }))
vi.mock('@kutup/files/media', () => ({ readMedia: () => Promise.resolve(undefined) }))
vi.mock('@kutup/session/store', () => ({ getSession: () => ({ userId: 'me' }) }))
vi.mock('@kutup/session/client', () => ({ default: { delete: mocks.del }, freshAccessToken: () => Promise.resolve('t') }))

import type { DriveFile, Folder } from '@kutup/drive-core/model'
import { NotTheSameFile, VersionConflict, VersionUploading } from '@kutup/files/upload/streamUpload'
import { ABANDONED_VERSION_UPLOAD_SECONDS, cancelVersionUpload, canReplace, replaceContent } from './replace'

const folder = { id: 'c1', source: 'owned', key: new Uint8Array(32), keyEpoch: 2, canUpload: true } as Folder
const holder = {
  id: 'f1',
  collectionId: 'c1',
  name: 'report.bin',
  mimeType: 'application/octet-stream',
  size: 3,
  sha256: null,
  media: null,
  fileKey: new Uint8Array(32).fill(1),
  fileKeyEnvelope: 'wrap',
  keyEpoch: 2,
  keyGeneration: 3,
  metadataRevision: 7,
} as unknown as DriveFile
const file = new File(['new content'], 'report.bin', { lastModified: 5 })
const signal = new AbortController().signal
const pending = (uploadId: string, version = true) => ({
  fileId: 'f1',
  uploadUrl: `https://drive.localhost/api/uploads/${uploadId}`,
  version: version ? { keyGeneration: 3, metadataRevision: 8 } : undefined,
})

beforeEach(() => {
  for (const mock of Object.values(mocks)) mock.mockReset()
  mocks.list.mockResolvedValue([])
})

describe('Replace', () => {
  it('is offered for files on this server, office documents and whiteboards too, but not notes', () => {
    expect(canReplace(folder, holder)).toBe(true)
    for (const name of ['plan.docx', 'sheet.xlsx', 'deck.pptx', 'scan.pdf', 'board.excalidraw', 'photo.jpg']) {
      expect(canReplace(folder, { ...holder, name }), name).toBe(true)
    }
    for (const name of ['notes.md', 'todo.txt', 'main.rs']) {
      expect(canReplace(folder, { ...holder, name }), name).toBe(false)
    }
    expect(canReplace({ ...folder, canUpload: false }, holder)).toBe(false)
    expect(canReplace({ ...folder, source: 'remote', remoteShareId: 's1' }, holder)).toBe(false)
  })

  it('sends the new content as the next revision of the file, sealed at its key generation', async () => {
    mocks.streamVersionUpload.mockResolvedValue({ fileId: 'f1', version: true })
    expect(await replaceContent(folder, holder, file, { signal })).toEqual({ done: { fileId: 'f1', version: true } })
    const sent = mocks.streamVersionUpload.mock.calls[0][0]
    expect(sent.target).toMatchObject({ fileId: 'f1', keyGeneration: 3, metadataRevision: 7, fileKeyEnvelope: 'wrap', keyEpoch: 2 })
    expect(sent.metadata).toEqual({
      name: 'report.bin',
      mimeType: 'application/octet-stream',
      size: file.size,
      sha256: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=',
    })
    expect(sent.contentHash).toBe('cd'.repeat(32))
    expect(sent.resumable).toEqual({ owner: 'me' })
  })

  it('asks instead of retrying when the file changed meanwhile', async () => {
    for (const kind of ['version', 'revision', 'key'] as const) {
      mocks.streamVersionUpload.mockRejectedValueOnce(new VersionConflict(kind))
      expect(await replaceContent(folder, holder, file, { signal })).toEqual({ problem: 'changed' })
    }
    expect(mocks.streamVersionUpload).toHaveBeenCalledTimes(3)
  })

  it('says when someone else is replacing the file', async () => {
    mocks.streamVersionUpload.mockRejectedValue(new VersionUploading(null))
    expect(await replaceContent(folder, holder, file, { signal })).toEqual({ problem: 'othersUpload' })
    expect(mocks.resumeUpload).not.toHaveBeenCalled()
  })

  it('goes on with its own open replacement when this browser remembers it', async () => {
    mocks.streamVersionUpload.mockRejectedValue(new VersionUploading('u1'))
    mocks.list.mockResolvedValue([pending('u0'), pending('u1')])
    mocks.resumeUpload.mockResolvedValue({ fileId: 'f1', version: true })
    expect(await replaceContent(folder, holder, file, { signal })).toEqual({ done: { fileId: 'f1', version: true } })
    expect(mocks.resumeUpload.mock.calls[0][0].upload.uploadUrl).toMatch(/u1$/)
  })

  it('offers to start again only when its own open replacement stopped an hour ago', async () => {
    mocks.streamVersionUpload.mockRejectedValue(new VersionUploading('u1', ABANDONED_VERSION_UPLOAD_SECONDS))
    expect(await replaceContent(folder, holder, file, { signal })).toEqual({ problem: 'ownUpload', uploadId: 'u1' })
    mocks.list.mockResolvedValue([pending('u1')])
    mocks.resumeUpload.mockRejectedValue(new NotTheSameFile())
    expect(await replaceContent(folder, holder, file, { signal })).toEqual({ problem: 'ownUpload', uploadId: 'u1' })
  })

  it('never cancels its own replacement that may be running elsewhere (a slow link idles for minutes)', async () => {
    for (const idle of [0, 300, ABANDONED_VERSION_UPLOAD_SECONDS - 1]) {
      mocks.streamVersionUpload.mockRejectedValueOnce(new VersionUploading('u1', idle))
      expect(await replaceContent(folder, holder, file, { signal })).toEqual({ problem: 'othersUpload' })
    }
    mocks.streamVersionUpload.mockRejectedValueOnce(new VersionUploading('u1'))
    expect(await replaceContent(folder, holder, file, { signal })).toEqual({ problem: 'othersUpload' })
  })

  it('cancels its own open replacement and forgets it', async () => {
    mocks.del.mockResolvedValue({})
    mocks.list.mockResolvedValue([pending('u1')])
    await cancelVersionUpload('f1', 'u1')
    expect(mocks.del).toHaveBeenCalledWith('/uploads/u1', { headers: { 'Tus-Resumable': '1.0.0' } })
    expect(mocks.remove).toHaveBeenCalledWith('f1')
  })
})
