import type { UploadedFile } from '@kutup/files/upload/streamUpload'
import { thumbnailsOfFile, thumbnailSourceFor } from '@kutup/editors/thumbnails/make'
import { enqueueThumbnail } from '@kutup/drive-core/thumbnailQueue'
import { storeThumbnails } from '@kutup/drive-core/thumbnails'

/** After an upload: draw its thumbnail from the plaintext still in hand. */
export function thumbnailAfterUpload(uploaded: UploadedFile, file: File): void {
  if (!thumbnailSourceFor(file.name, file.type)) return
  enqueueThumbnail(uploaded.fileId, async () =>
    storeThumbnails(
      { fileId: uploaded.fileId, fileKey: uploaded.fileKey, keyGeneration: uploaded.keyGeneration },
      await thumbnailsOfFile(file),
      'original',
    ),
  )
}
