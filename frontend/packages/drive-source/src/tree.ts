// What the screens need to know about the folder tree, whatever the source.

import type { FolderTree, FolderView } from './source'

/** Whether `candidate` is `folder` or somewhere inside it (nothing goes into itself). */
export function isWithin(tree: Pick<FolderTree, 'byId'>, candidate: FolderView, folder: FolderView): boolean {
  let at: FolderView | undefined = candidate
  while (at) {
    if (at.id === folder.id && at.source === folder.source) return true
    at = at.parentId ? tree.byId.get(at.parentId) : undefined
  }
  return false
}
