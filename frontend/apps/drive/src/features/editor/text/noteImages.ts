// Images in Markdown notes, stored inside the note: each is sealed under the
// note's file key as one of its assets (the per-file asset store whiteboards
// use, bound to the file, the asset id and the key's generation), named by
// its content hash, and written into the note as
//
//   ![name](kutup:asset/<id>)
//
// The preview opens it in the browser and shows it from a blob: URL. Anyone
// the note is shared with can see its images; the server sees neither.

import { fetchAsset, uploadAsset } from '@kutup/collab/whiteboardAssets'

/** Pictures every browser shows. SVG is left out (it is a document, not a picture). */
export const NOTE_IMAGE_TYPES = new Set(['image/png', 'image/jpeg', 'image/gif', 'image/webp', 'image/avif'])

/** The server's per-asset cap (MAX_WHITEBOARD_ASSET_PLAINTEXT_BYTES). */
export const MAX_NOTE_IMAGE_BYTES = 25 * 1024 * 1024

const ASSET_SRC = /^kutup:asset\/([A-Za-z0-9-]{1,100})$/

export class NoteImageTooLargeError extends Error {}
export class NoteImageTypeError extends Error {}

/** The note's asset id in an image's `src`, or null for anything else. */
export function assetIdFromSrc(src: string | undefined): string | null {
  const m = ASSET_SRC.exec(src ?? '')
  return m ? m[1] : null
}

/** An image's Markdown: its file name (without the extension) as the alt text. */
export function imageMarkdown(name: string, assetId: string): string {
  const alt = name.replace(/\.[^.]+$/, '').replace(/[[\]\\]/g, '').trim() || 'image'
  return `![${alt}](kutup:asset/${assetId})`
}

/** Content-addressed: the same image pasted twice is stored once. */
export async function assetIdOf(bytes: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as BufferSource))
  return 'img-' + Array.from(digest, (b) => b.toString(16).padStart(2, '0')).join('')
}

/** What a picture's bytes are, by their signature (the stored bytes carry no type). */
export function imageTypeOf(bytes: Uint8Array): string | null {
  const at = (i: number, ...sig: number[]) => sig.every((b, j) => bytes[i + j] === b)
  if (at(0, 0x89, 0x50, 0x4e, 0x47)) return 'image/png'
  if (at(0, 0xff, 0xd8, 0xff)) return 'image/jpeg'
  if (at(0, 0x47, 0x49, 0x46, 0x38)) return 'image/gif'
  if (at(0, 0x52, 0x49, 0x46, 0x46) && at(8, 0x57, 0x45, 0x42, 0x50)) return 'image/webp'
  if (at(4, 0x66, 0x74, 0x79, 0x70) && (at(8, 0x61, 0x76, 0x69, 0x66) || at(8, 0x61, 0x76, 0x69, 0x73))) return 'image/avif'
  return null
}

export interface NoteAssetTarget {
  fileId: string
  fileKey: Uint8Array
  generation: number
  /** Keys of older generations: an image stored before the note was re-keyed. */
  keyAt?: (generation: number) => Promise<Uint8Array>
}

/** Seals and stores one pasted or dropped image; resolves to its asset id. */
export async function storeNoteImage(target: NoteAssetTarget, file: File): Promise<string> {
  if (!NOTE_IMAGE_TYPES.has(file.type)) throw new NoteImageTypeError(file.type)
  if (file.size > MAX_NOTE_IMAGE_BYTES) throw new NoteImageTooLargeError(String(file.size))
  const bytes = new Uint8Array(await file.arrayBuffer())
  // The bytes must be the picture they say they are.
  if (imageTypeOf(bytes) === null) throw new NoteImageTypeError(file.type)
  const assetId = await assetIdOf(bytes)
  await uploadAsset({ fileId: target.fileId, assetId, generation: target.generation }, bytes, target.fileKey)
  return assetId
}

/**
 * Opens a note's images once each, as blob: URLs, for this note's session;
 * `dispose` releases them.
 */
export function noteImageResolver(target: NoteAssetTarget) {
  const cache = new Map<string, Promise<string | null>>()
  return {
    resolve(assetId: string): Promise<string | null> {
      let hit = cache.get(assetId)
      if (!hit) {
        hit = fetchAsset({ fileId: target.fileId, assetId, generation: target.generation }, target.fileKey, target.keyAt)
          .then((bytes) => {
            const type = imageTypeOf(bytes)
            return type ? URL.createObjectURL(new Blob([bytes as BlobPart], { type })) : null
          })
          .catch(() => null)
        cache.set(assetId, hit)
      }
      return hit
    },
    dispose() {
      for (const url of cache.values()) void url.then((u) => u && URL.revokeObjectURL(u))
      cache.clear()
    },
  }
}

export type NoteImageResolver = ReturnType<typeof noteImageResolver>
