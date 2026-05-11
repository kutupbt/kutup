// uploadFolder — orchestrate a recursive folder upload over the tus
// endpoint. Mirrors what the CLI's `kutup upload --recursive` does:
//
//   1. Build the set of unique directory paths from the dropped /
//      picked entries.
//   2. Create kutup subcollections top-down, encrypting each new
//      collection key with the user's master key. Parents before
//      children (sort by string-length / segment count works).
//   3. Stream-upload each file via the existing streamUpload(), keyed
//      to the subcollection that matches its relativePath.
//
// Input shape (FolderEntry) is intentionally minimal: a File +
// the directory segments (NOT including the file name). The caller
// (Drive.tsx) builds these from `webkitRelativePath` for picker-
// triggered uploads, or from a `DataTransferItem.webkitGetAsEntry()`
// walker for drag-dropped folders. Either source produces the same
// shape so the orchestrator doesn't care.
//
// Concurrency is sequential for v1. Speeding up to 3-parallel is a
// small refactor once we have user signal on bottleneck — probably
// the per-file streamUpload's own server round-trips dominate
// already on LAN speeds.

import api from '@/api/client'
import { generateKey, encrypt, toBase64 } from '@/crypto'
import { streamUpload } from './streamUpload'

/** One file + the directory path it lives in, relative to the drop root. */
export interface FolderEntry {
  file: File
  /** Directory segments, NOT including the file name.
   *  e.g. for `photos/2024/wedding/a.jpg` dropped as `photos/`,
   *  relativePath is `['photos', '2024', 'wedding']`. */
  relativePath: string[]
}

export interface UploadFolderOptions {
  entries: FolderEntry[]
  /** The collection the user dropped the folder into (current Drive view). */
  parentCollection: { id: string; collectionKey: Uint8Array }
  /** User's master key — needed to wrap new collection keys. */
  masterKey: Uint8Array
  /** Bearer JWT for the tus calls. */
  accessToken: string
  onProgress?: (filesDone: number, filesTotal: number, currentName: string) => void
  signal?: AbortSignal
}

/** Internal: create one subcollection under `parentCollectionId`,
 *  returning the new id + the freshly-generated collectionKey so the
 *  caller can hand it to streamUpload for files in that folder. */
async function createSubcollection(
  name: string,
  parentCollectionId: string,
  masterKey: Uint8Array,
): Promise<{ id: string; collectionKey: Uint8Array }> {
  const collectionKey = await generateKey()
  const encKey = await encrypt(collectionKey, masterKey)
  const encName = await encrypt(new TextEncoder().encode(name), collectionKey)
  const res = await api.post('/collections/', {
    encryptedName: toBase64(encName.ciphertext),
    nameNonce: toBase64(encName.nonce),
    encryptedKey: toBase64(encKey.ciphertext),
    encryptedKeyNonce: toBase64(encKey.nonce),
    parentCollectionId,
  })
  return { id: res.data.id, collectionKey }
}

export async function uploadFolder(opts: UploadFolderOptions): Promise<void> {
  if (opts.entries.length === 0) return

  // 1. Enumerate unique directory paths across all entries.
  //    "" key represents the drop-root (= opts.parentCollection).
  const dirSet = new Set<string>()
  for (const e of opts.entries) {
    let acc = ''
    for (const seg of e.relativePath) {
      acc = acc === '' ? seg : `${acc}/${seg}`
      dirSet.add(acc)
    }
  }

  // 2. Sort by segment count so parents always exist before children.
  const orderedDirs = [...dirSet].sort((a, b) => {
    const sa = a.split('/').length
    const sb = b.split('/').length
    if (sa !== sb) return sa - sb
    return a.localeCompare(b)
  })

  // 3. Build the path → collection map, starting with the drop root.
  const collMap = new Map<string, { id: string; collectionKey: Uint8Array }>()
  collMap.set('', opts.parentCollection)

  for (const dir of orderedDirs) {
    if (opts.signal?.aborted) throw new DOMException('Aborted', 'AbortError')
    const segments = dir.split('/')
    const childName = segments[segments.length - 1]
    const parentKey = segments.slice(0, -1).join('/')
    const parent = collMap.get(parentKey)
    if (!parent) {
      throw new Error(`uploadFolder: missing parent ${parentKey || '<root>'} for ${dir}`)
    }
    const created = await createSubcollection(childName, parent.id, opts.masterKey)
    collMap.set(dir, created)
  }

  // 4. Stream-upload each file into its target collection.
  const total = opts.entries.length
  let done = 0
  for (const entry of opts.entries) {
    if (opts.signal?.aborted) throw new DOMException('Aborted', 'AbortError')
    const dirKey = entry.relativePath.join('/')
    const target = collMap.get(dirKey) ?? opts.parentCollection
    opts.onProgress?.(done, total, entry.file.name)
    try {
      await streamUpload({
        file: entry.file,
        collection: target,
        accessToken: opts.accessToken,
        signal: opts.signal,
      })
    } catch (err) {
      console.error('[uploadFolder] streamUpload failed for', entry.file.name, 'in', dirKey, err)
      throw err
    }
    done++
  }
  opts.onProgress?.(total, total, '')
}

/** Convert a picker-flat FileList (each item carrying
 *  `webkitRelativePath` like `root/sub/file.jpg`) into FolderEntry[].
 *  The first path segment is the dropped root folder name. */
export function filesToFolderEntries(files: FileList | File[]): FolderEntry[] {
  const out: FolderEntry[] = []
  for (const f of Array.from(files)) {
    const path = (f as File & { webkitRelativePath?: string }).webkitRelativePath ?? ''
    if (!path) {
      out.push({ file: f, relativePath: [] })
      continue
    }
    const segments = path.split('/')
    const dirs = segments.slice(0, -1)
    out.push({ file: f, relativePath: dirs })
  }
  return out
}

/** Recursively walk a `DataTransferItemList` from a folder drop,
 *  producing the same FolderEntry[] shape as the picker path.
 *
 *  Returns an empty list if no entry is a directory (in which case
 *  the caller should fall back to its existing flat-file path). */
export async function dataTransferToFolderEntries(items: DataTransferItemList): Promise<FolderEntry[]> {
  const out: FolderEntry[] = []
  const promises: Promise<void>[] = []
  for (let i = 0; i < items.length; i++) {
    const it = items[i]
    if (it.kind !== 'file') continue
    const entry = (it as DataTransferItem & {
      webkitGetAsEntry?: () => FileSystemEntry | null
    }).webkitGetAsEntry?.()
    if (!entry) continue
    promises.push(walkEntry(entry, [], out))
  }
  await Promise.all(promises)
  return out
}

interface FSEntry {
  isFile: boolean
  isDirectory: boolean
  name: string
  file?: (cb: (f: File) => void, err?: (e: unknown) => void) => void
  createReader?: () => {
    readEntries: (cb: (entries: FSEntry[]) => void, err?: (e: unknown) => void) => void
  }
}

async function walkEntry(
  entry: FileSystemEntry,
  parents: string[],
  out: FolderEntry[],
): Promise<void> {
  const e = entry as unknown as FSEntry
  if (e.isFile && e.file) {
    const file = await new Promise<File>((resolve, reject) => e.file!(resolve, reject))
    out.push({ file, relativePath: parents })
    return
  }
  if (e.isDirectory && e.createReader) {
    const reader = e.createReader()
    // readEntries returns paginated lists — loop until empty.
    const children: FSEntry[] = []
    while (true) {
      const batch = await new Promise<FSEntry[]>((resolve, reject) =>
        reader.readEntries(resolve, reject),
      )
      if (batch.length === 0) break
      children.push(...batch)
    }
    const childPath = [...parents, e.name]
    for (const child of children) {
      await walkEntry(child as unknown as FileSystemEntry, childPath, out)
    }
  }
}
