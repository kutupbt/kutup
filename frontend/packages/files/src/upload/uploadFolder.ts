// The files of a dropped or picked directory, each with the directory path
// it lives in, from the picker (`webkitRelativePath`) or a drag-and-drop
// (`webkitGetAsEntry`): one shape whatever the source. Drive puts them into
// folders (apps/drive/src/features/uploads/folderUpload.ts).

/** One file + the directory path it lives in, relative to the drop root. */
export interface FolderEntry {
  file: File
  /** Directory segments, NOT including the file name.
   *  e.g. for `photos/2024/wedding/a.jpg` dropped as `photos/`,
   *  relativePath is `['photos', '2024', 'wedding']`. */
  relativePath: string[]
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
