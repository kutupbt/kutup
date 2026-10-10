import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { DriveFile, Folder } from '@kutup/drive-core/model'

const stored = new Map<string, Uint8Array>()
const uploads: { fileId: string; assetId: string; base?: string }[] = []
vi.mock('@kutup/collab/whiteboardAssets', () => ({
  fetchAsset: (ctx: { fileId: string; assetId: string }) => {
    const bytes = stored.get(`${ctx.fileId}/${ctx.assetId}`)
    return bytes ? Promise.resolve(bytes) : Promise.reject(new Error('not found'))
  },
  uploadAsset: (ctx: { fileId: string; assetId: string }, _bytes: Uint8Array, _key: Uint8Array, base?: string) => {
    uploads.push({ fileId: ctx.fileId, assetId: ctx.assetId, base })
    return Promise.resolve()
  },
}))
vi.mock('@kutup/drive-core/keyring', () => ({ fileKeyAt: () => Promise.resolve(new Uint8Array(32)) }))
const { copyEmbedded, embeddedAssetIds, embeddingKind, exportEmbedded } = await import('./embedded')

const PNG = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 1, 2, 3])
const folder = { id: 'f', source: 'owned' } as unknown as Folder
const note = { id: 'n', name: 'Trip.md', fileKey: new Uint8Array(32), keyGeneration: 1 } as unknown as DriveFile
const board = { id: 'w', name: 'Plan.excalidraw', fileKey: new Uint8Array(32), keyGeneration: 1 } as unknown as DriveFile

beforeEach(() => {
  stored.clear()
  uploads.length = 0
})

describe('embedded pictures', () => {
  it('knows which files hold pictures and which ones they use', () => {
    expect(embeddingKind('a.md')).toBe('note')
    expect(embeddingKind('a.excalidraw')).toBe('whiteboard')
    expect(embeddingKind('a.pdf')).toBeNull()
    expect(embeddedAssetIds('note', '![a](kutup:asset/img-1) and ![b](kutup:asset/img-2) ![a](kutup:asset/img-1)')).toEqual(['img-1', 'img-2'])
    const scene = JSON.stringify({ elements: [{ type: 'image', fileId: 'x' }, { type: 'image', fileId: 'y', isDeleted: true }, { type: 'rectangle' }] })
    expect(embeddedAssetIds('whiteboard', scene)).toEqual(['x'])
  })

  it('seals a copy’s pictures for the copy, on its server', async () => {
    stored.set('n/img-1', PNG)
    const remote = { id: 'd', source: 'remote', remoteShareId: 's1' } as unknown as Folder
    const n = await copyEmbedded({ folder, file: note }, '![a](kutup:asset/img-1) ![gone](kutup:asset/img-9)', remote, {
      fileId: 'copy',
      fileKey: new Uint8Array(32),
      keyGeneration: 1,
    })
    expect(n).toBe(1)
    expect(uploads).toEqual([{ fileId: 'copy', assetId: 'img-1', base: '/drive/federation/shares/s1/files/copy' }])
  })

  it('exports a note with its pictures in assets/, links pointing there', async () => {
    stored.set('n/img-abcdef0123456789ffff', PNG)
    const out = await exportEmbedded(folder, note, 'See ![map](kutup:asset/img-abcdef0123456789ffff) and ![x](kutup:asset/img-missing)')
    expect(out?.map((e) => e.path)).toEqual(['Trip.md', 'assets/abcdef0123456789.png'])
    expect(new TextDecoder().decode(out![0].bytes)).toBe('See ![map](assets/abcdef0123456789.png) and ![x](kutup:asset/img-missing)')
  })

  it('exports a whiteboard with its pictures inline, as Excalidraw keeps them', async () => {
    stored.set('w/x', new TextEncoder().encode('data:image/png;base64,AAAA'))
    const scene = JSON.stringify({ type: 'excalidraw', elements: [{ type: 'image', fileId: 'x' }], files: {} })
    const out = await exportEmbedded(folder, board, scene)
    expect(out).toHaveLength(1)
    const saved = JSON.parse(new TextDecoder().decode(out![0].bytes)) as { files: Record<string, { mimeType: string; dataURL: string }> }
    expect(saved.files.x).toMatchObject({ mimeType: 'image/png', dataURL: 'data:image/png;base64,AAAA' })
  })

  it('leaves files without pictures as they are', async () => {
    expect(await exportEmbedded(folder, note, 'just text')).toBeNull()
  })
})
