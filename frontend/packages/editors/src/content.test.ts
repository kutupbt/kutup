import { beforeEach, describe, expect, it, vi } from 'vitest'
import * as Y from 'yjs'

const mocks = vi.hoisted(() => ({ listVersions: vi.fn(), get: vi.fn() }))
vi.mock('@kutup/collab/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@kutup/collab/api')>()),
  listVersions: mocks.listVersions,
}))
vi.mock('@kutup/session/client', () => ({ default: { get: mocks.get }, freshAccessToken: () => Promise.resolve('t') }))
vi.mock('@kutup/drive-core/keyring', () => ({ sealedAt: () => Promise.resolve({ fileKey: new Uint8Array(32), context: {} }) }))
// The "sealed" blob is the plaintext itself here.
vi.mock('@kutup/crypto/fileBlob', () => ({ decryptFileBlobV1: (bytes: Uint8Array) => Promise.resolve(bytes) }))

import type { DriveFile, Folder } from '@kutup/drive-core/model'
import { currentContent } from './content'

const folder = { id: 'c1', source: 'owned' } as Folder
const file = (name: string) => ({ id: 'f1', name, fileKey: new Uint8Array(32) }) as unknown as DriveFile
const version = (id: string, kind: 'file' | 'yjs') => ({ id, kind, sizeBytes: 10, keyGeneration: 1, seqAtSnapshot: 4 })

function noteState(text: string): Uint8Array {
  const doc = new Y.Doc()
  doc.getText('content').insert(0, text)
  return Y.encodeStateAsUpdateV2(doc)
}

beforeEach(() => {
  mocks.listVersions.mockReset()
  mocks.get.mockReset()
})

describe('what a note holds now', () => {
  it('is its newest Yjs state, a stray whole-file version passed over', async () => {
    mocks.listVersions.mockResolvedValue([version('stray', 'file'), version('y1', 'yjs')])
    mocks.get.mockImplementation((path: string) => {
      expect(path).toBe('/files/f1/versions/y1/download')
      return Promise.resolve({ data: noteState('hello').buffer })
    })
    const content = await currentContent(folder, file('notes.md'))
    expect(content).toEqual({ kind: 'plain', bytes: new TextEncoder().encode('hello'), versionId: 'y1' })
  })

  it('is the original upload when it has only whole-file versions', async () => {
    mocks.listVersions.mockResolvedValue([version('stray', 'file')])
    expect(await currentContent(folder, file('notes.md'))).toEqual({ kind: 'original' })
    expect(await currentContent(folder, file('Trip.kutupmap'))).toEqual({ kind: 'original' })
    expect(mocks.get).not.toHaveBeenCalled()
  })

  it('leaves office documents on their newest version of any kind', async () => {
    mocks.listVersions.mockResolvedValue([version('f2', 'file'), version('f1', 'file')])
    expect(await currentContent(folder, file('plan.docx'))).toMatchObject({ kind: 'version', versionId: 'f2' })
  })
})
