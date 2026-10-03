import { sealedAt } from '@kutup/drive-core/keyring'
import { contentPath, fileLocation, folderLocation } from '@kutup/drive-core/model'
import { fetchDecryptedChunks } from '@kutup/files/download/fetchDecrypt'
import { openDownloadSink } from '@kutup/files/download/streamDownload'
import { downloadAsZip, type ZipFile } from '@kutup/files/zipDownload'
import { resolveApiBase } from '@kutup/session/apiBase'
import { freshAccessToken } from '@kutup/session/client'
import type { Photo } from '../library/library'

export { FsaRequiredError } from '@kutup/files/zipDownload'

/**
 * Save one photo as it was uploaded: decrypted as it streams, straight to
 * disk where the browser allows it. Cancelling the save picker rejects with
 * an AbortError, which callers ignore.
 */
export async function downloadPhoto(photo: Photo): Promise<void> {
  const { folder, file } = photo
  if (!file.fileKey || !file.name) throw new Error('file is not open')
  // The save picker needs the click's user activation: ask for it first.
  const sink = await openDownloadSink({ filename: file.name, mimeType: file.mimeType })
  try {
    const url = `${await resolveApiBase()}${contentPath(fileLocation(folder), file.id)}`
    const sealed = await sealedAt(file, file.contentKeyGeneration)
    for await (const { plain } of fetchDecryptedChunks(url, sealed.fileKey, sealed.context, await freshAccessToken())) {
      await sink.write(plain)
    }
    await sink.finalize()
  } catch (error) {
    await sink.abort().catch(() => {})
    throw error
  }
}

/** `name`, or `name (1)`… when the archive already has it (photos from different folders share names). */
export function uniqueName(name: string, used: Set<string>): string {
  let candidate = name
  const dot = name.lastIndexOf('.')
  for (let n = 1; used.has(candidate.toLocaleLowerCase()); n++) {
    candidate = dot > 0 ? `${name.slice(0, dot)} (${n})${name.slice(dot)}` : `${name} (${n})`
  }
  used.add(candidate.toLocaleLowerCase())
  return candidate
}

/** Several photos as one ZIP (split at 2 GiB, as Drive's). */
export async function downloadPhotosZip(
  photos: readonly Photo[],
  archive: string,
  onProgress: (done: number, total: number) => void,
): Promise<void> {
  const used = new Set<string>()
  const entries: ZipFile[] = []
  for (const { folder, file } of photos) {
    if (!file.fileKey || !file.name) continue
    const sealed = await sealedAt(file, file.contentKeyGeneration)
    const location = folderLocation(folder)
    entries.push({
      id: file.id,
      keyGeneration: sealed.context.generation,
      name: uniqueName(file.name, used),
      size: file.size,
      fileKey: sealed.fileKey,
      ...(location.kind === 'remote' ? { isRemote: true, remoteShareId: location.shareId } : {}),
    })
  }
  if (entries.length === 0) return
  await downloadAsZip(entries, archive, await freshAccessToken(), (done, total) => onProgress(done, total))
}
