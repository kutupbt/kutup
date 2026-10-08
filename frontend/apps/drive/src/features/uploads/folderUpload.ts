import { createOwnedCollectionV1 } from '@kutup/crypto'
import type { FolderEntry } from '@kutup/files/upload/uploadFolder'
import api from '@kutup/session/client'
import type { DriveIdentity } from '@kutup/drive-core/identity'
import type { Folder } from '@kutup/drive-core/model'
import { asNameTaken, canonicalName, freeName, inFolder, nameHashIn, namesIn } from '@kutup/drive-core/names'
import { loadFolderFiles } from '@kutup/drive-core/files'
import { openRow, type CollectionRowWithTimes } from '@kutup/drive-core/folders'
import { ConflictPolicy } from '@kutup/drive-ui/nameConflicts'
import { createdFolder } from '../drive/copy'
import { BatchListing, placeFile } from './upload'

/**
 * A dropped or picked directory into `parent`, as on a disk
 * (docs/plans/drive-unique-names.md): a folder of the same name already
 * there is gone into rather than made twice, so dropping a folder again
 * uploads only what is new or changed — a file already there with the same
 * content is skipped, one that differs is the person's choice (with "apply
 * to all" across the whole drop). Parents are made before their children;
 * files go one at a time.
 */
export async function uploadDirectoryInto(opts: {
  me: DriveIdentity
  parent: Folder
  entries: FolderEntry[]
  folderName: string
  /** The subfolders of a folder that existed before this upload. */
  subfoldersOf: (folder: Folder) => Folder[]
  signal: AbortSignal
  waiting?: (waiting: boolean) => void
  onProgress?: (filesDone: number, filesTotal: number) => void
}): Promise<void> {
  const { me, entries, signal } = opts
  if (entries.length === 0) return
  const policy = new ConflictPolicy(entries.length)

  // Folders made by this upload: nothing is in them but what it puts there.
  const made = new Set<string>()
  const children = new Map<string, Folder[]>()
  const subfolders = (folder: Folder) => [...(made.has(folder.id) ? [] : opts.subfoldersOf(folder)), ...(children.get(folder.id) ?? [])]

  /** The subfolder `name` of `parent`: the one there, or a new one. */
  async function folderIn(parent: Folder, name: string): Promise<Folder> {
    for (let attempt = 0; ; attempt++) {
      const wanted = canonicalName(name)
      const existing = subfolders(parent).find((f) => f.name !== null && canonicalName(f.name) === wanted)
      if (existing?.key && existing.source === 'owned') return existing
      // A file (or a folder that cannot be opened) holds the name: a new
      // folder beside it, under the next free name.
      const files = made.has(parent.id) ? [] : await loadFolderFiles(parent)
      const free = freeName(name, namesIn(files, subfolders(parent)))
      const created = await createOwnedCollectionV1(me.masterKey, me.userId, free, parent.id)
      try {
        await api.post('/collections', { ...created.payload, nameHash: await nameHashIn(inFolder(parent), free) })
      } catch (error) {
        // Made meanwhile (another tab, or a listing not yet reloaded): look again.
        const taken = asNameTaken(error)
        if (!taken || attempt > 0) throw error
        if (taken.holder?.kind === 'folder') {
          const { data } = await api.get<CollectionRowWithTimes>(`/collections/${taken.holder.id}`)
          const holder = await openRow(data, me)
          if (holder.key && holder.source === 'owned') {
            children.set(parent.id, [...(children.get(parent.id) ?? []), holder])
            return holder
          }
        }
        continue
      }
      const folder = createdFolder(me, parent, created, free)
      made.add(folder.id)
      children.set(parent.id, [...(children.get(parent.id) ?? []), folder])
      return folder
    }
  }

  // Each directory once, parents first.
  const targets = new Map<string, Folder>([['', opts.parent]])
  const directories = new Set<string>()
  for (const entry of entries) {
    for (let depth = 1; depth <= entry.relativePath.length; depth++) directories.add(entry.relativePath.slice(0, depth).join('/'))
  }
  const ordered = [...directories].sort((a, b) => a.split('/').length - b.split('/').length || a.localeCompare(b))
  for (const path of ordered) {
    signal.throwIfAborted()
    const segments = path.split('/')
    const parent = targets.get(segments.slice(0, -1).join('/'))
    if (!parent) throw new Error('a folder upload lost a parent folder')
    targets.set(path, await folderIn(parent, segments[segments.length - 1]))
  }

  const listings = new Map<string, BatchListing>()
  const listingOf = (folder: Folder) => {
    let listing = listings.get(folder.id)
    if (!listing) {
      listing = new BatchListing(folder, () => subfolders(folder))
      listings.set(folder.id, listing)
    }
    return listing
  }
  const total = entries.length
  let done = 0
  opts.onProgress?.(0, total)
  for (const entry of entries) {
    signal.throwIfAborted()
    const target = targets.get(entry.relativePath.join('/')) ?? opts.parent
    await placeFile({
      folder: target,
      file: entry.file,
      folderName: target.id === opts.parent.id ? opts.folderName : (target.name ?? opts.folderName),
      listing: listingOf(target),
      policy,
      signal,
      waiting: opts.waiting,
    })
    opts.onProgress?.(++done, total)
  }
}
