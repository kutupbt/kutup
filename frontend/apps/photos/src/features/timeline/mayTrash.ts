import type { Photo } from '../library/library'

/** Whether this account may move the photo to its folder's trash. */
export function mayTrash(photo: Photo, userId: string): boolean {
  const { folder, file } = photo
  if (folder.source === 'file') return false
  return folder.source === 'owned' || folder.canDelete || file.uploaderUserId === userId
}
