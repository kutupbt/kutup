// Where a new vault can go (docs/plans/pass.md): every Drive folder it may
// be saved in, named by its path so subfolders with the same name are told
// apart, and whether a subfolder can be made there.

import type { Folder } from '@kutup/drive-core/model'

export interface FolderChoice {
  folder: Folder
  /** "My files / Work / Banks"; a folder shared with the account starts at itself. */
  path: string
}

/**
 * The folders a vault can be saved in (open, writable, the account's own or
 * shared with it), each with its path, My files first, then by path.
 */
export function vaultFolderChoices(folders: readonly Folder[], names: { myFiles: string; unnamed: string }): FolderChoice[] {
  const byId = new Map(folders.map((f) => [f.id, f]))
  const nameOf = (f: Folder) => (f.isRoot ? names.myFiles : (f.name ?? names.unnamed))
  const pathOf = (folder: Folder) => {
    const parts = [nameOf(folder)]
    const seen = new Set([folder.id])
    let parent = folder.parentId ? byId.get(folder.parentId) : undefined
    // Up to a folder whose parent is not listed (a shared folder's), or a loop.
    while (parent && !seen.has(parent.id)) {
      seen.add(parent.id)
      parts.unshift(nameOf(parent))
      parent = parent.parentId ? byId.get(parent.parentId) : undefined
    }
    return parts.join(' / ')
  }
  return folders
    .filter((f) => f.key && f.canUpload && (f.source === 'owned' || f.source === 'shared'))
    .map((folder) => ({ folder, path: pathOf(folder) }))
    .sort(
      (a, b) =>
        Number(b.folder.isRoot) - Number(a.folder.isRoot) ||
        a.path.localeCompare(b.path, undefined, { numeric: true, sensitivity: 'base' }),
    )
}

/** Whether a subfolder can be made in `folder`: Drive's New folder rule (owner-only actions). */
export function canMakeSubfolder(folder: Folder | undefined): boolean {
  return Boolean(folder?.key && folder.canUpload && folder.canManage)
}
