// Pictures kept inside a file (a Markdown note's pasted pictures, a
// whiteboard's images): per-file assets, sealed under the file's key and
// bound to its id (docs/plans/drive-thumbnails.md, notes). A copy is a new
// file, so its pictures are sealed anew for it; a download carries them
// along: a whiteboard as Excalidraw's own format (pictures inline), a note
// as a ZIP of the note and an assets/ folder.

import { fetchAsset, uploadAsset } from '@kutup/collab/whiteboardAssets'
import { fileKeyAt } from '@kutup/drive-core/keyring'
import { collabBase, fileLocation, type DriveFile, type Folder } from '@kutup/drive-core/model'
import { imageTypeOf } from '../text/noteImages'

const NOTE_ASSET = /kutup:asset\/([A-Za-z0-9-]{1,100})/g

export type EmbeddingKind = 'note' | 'whiteboard'

/** Whether a file of this name can hold pictures of its own. */
export function embeddingKind(name: string | null | undefined): EmbeddingKind | null {
  const lower = (name ?? '').toLowerCase()
  if (lower.endsWith('.md') || lower.endsWith('.markdown')) return 'note'
  if (lower.endsWith('.excalidraw')) return 'whiteboard'
  return null
}

/** The asset ids a note or whiteboard uses, from its content. */
export function embeddedAssetIds(kind: EmbeddingKind, text: string): string[] {
  if (kind === 'note') return [...new Set([...text.matchAll(NOTE_ASSET)].map((m) => m[1]))]
  try {
    const scene = JSON.parse(text) as { elements?: { type?: string; fileId?: string | null; isDeleted?: boolean }[] }
    const ids = (scene.elements ?? [])
      .filter((e) => e.type === 'image' && e.fileId && !e.isDeleted)
      .map((e) => e.fileId!)
    return [...new Set(ids)]
  } catch {
    return []
  }
}

/** Where a file's asset calls go: here, or its relay for a file on another server. */
function baseOf(folder: Folder, fileId: string): string {
  return collabBase(fileLocation(folder), fileId)
}

/** The file's assets that open, by id (one that is gone or does not open is left out). */
async function readAssets(folder: Folder, file: DriveFile, ids: string[]): Promise<Map<string, Uint8Array>> {
  const out = new Map<string, Uint8Array>()
  if (!file.fileKey) return out
  const fileKey = file.fileKey
  for (const assetId of ids) {
    try {
      out.set(
        assetId,
        await fetchAsset(
          { fileId: file.id, assetId, generation: file.keyGeneration },
          fileKey,
          (generation) => fileKeyAt(file, generation),
          baseOf(folder, file.id),
        ),
      )
    } catch {
      // Gone, or unreadable: the copy or download goes on without it.
    }
  }
  return out
}

/** A new file, as an upload made it: where its assets are sealed. */
export interface CreatedFile {
  fileId: string
  fileKey: Uint8Array
  keyGeneration: number
}

/**
 * A copy's pictures: each of the source's, sealed for the copy (its id and
 * key) and stored with it, on its server. Returns how many were copied.
 */
export async function copyEmbedded(
  source: { folder: Folder; file: DriveFile },
  text: string,
  dest: Folder,
  created: CreatedFile,
): Promise<number> {
  const kind = embeddingKind(source.file.name)
  if (!kind) return 0
  const assets = await readAssets(source.folder, source.file, embeddedAssetIds(kind, text))
  for (const [assetId, bytes] of assets) {
    await uploadAsset(
      { fileId: created.fileId, assetId, generation: created.keyGeneration },
      bytes,
      created.fileKey,
      baseOf(dest, created.fileId),
    )
  }
  return assets.size
}

const EXTENSION: Record<string, string> = {
  'image/png': 'png',
  'image/jpeg': 'jpg',
  'image/gif': 'gif',
  'image/webp': 'webp',
  'image/avif': 'avif',
}

/** A picture's name in an exported note's assets/ folder. */
function assetFileName(assetId: string, bytes: Uint8Array): string {
  return `${assetId.replace(/^img-/, '').slice(0, 16)}.${EXTENSION[imageTypeOf(bytes) ?? ''] ?? 'bin'}`
}

export interface ExportedFile {
  /** Path inside the download (relative to where the file goes). */
  path: string
  bytes: Uint8Array
}

/**
 * A file as it should leave Kutup, with its pictures: a note with pictures
 * becomes the note (its links pointing at assets/…) and the pictures; a
 * whiteboard gets its pictures back inline (Excalidraw's own format). Null
 * when there is nothing to carry (the file as it is will do).
 */
export async function exportEmbedded(folder: Folder, file: DriveFile, text: string): Promise<ExportedFile[] | null> {
  const kind = embeddingKind(file.name)
  if (!kind || !file.name) return null
  const ids = embeddedAssetIds(kind, text)
  if (ids.length === 0) return null
  const assets = await readAssets(folder, file, ids)
  if (kind === 'whiteboard') {
    try {
      const scene = JSON.parse(text) as { files?: Record<string, unknown> }
      const files: Record<string, unknown> = { ...(scene.files ?? {}) }
      for (const [id, bytes] of assets) {
        const dataURL = new TextDecoder().decode(bytes)
        const mimeType = /^data:([^;,]+)[;,]/.exec(dataURL)?.[1] ?? 'image/png'
        files[id] = { id, mimeType, dataURL, created: Date.now() }
      }
      return [{ path: file.name, bytes: new TextEncoder().encode(JSON.stringify({ ...scene, files })) }]
    } catch {
      return null
    }
  }
  const out: ExportedFile[] = []
  const names = new Map<string, string>()
  for (const [id, bytes] of assets) {
    const name = assetFileName(id, bytes)
    names.set(id, name)
    out.push({ path: `assets/${name}`, bytes })
  }
  // Pictures that did not open keep their kutup: link (nothing to point at).
  const markdown = text.replace(NOTE_ASSET, (whole, id: string) => (names.has(id) ? `assets/${names.get(id)}` : whole))
  return [{ path: file.name, bytes: new TextEncoder().encode(markdown) }, ...out]
}
