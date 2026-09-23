import { Zip, ZipPassThrough } from 'fflate'
import { fetchDecryptedChunks } from './download/fetchDecrypt'
import { resolveApiBase } from '@kutup/session/apiBase'

// 2 GB — ZIP32 max; Windows Explorer and most real-world readers cap here.
const SPLIT_BYTES = 2 * 1024 * 1024 * 1024
// On browsers without the File System Access API (Firefox / Safari) the ZIP
// must be assembled fully in memory before `<a download>` can save it — so
// it's capped. The FSA path streams to disk and have no cap.
const BLOB_FALLBACK_LIMIT = 1 * 1024 * 1024 * 1024 // 1 GB

export class FsaRequiredError extends Error {
  code = 'NO_FSA'
  constructor() { super('File System Access API required for large downloads') }
}

export interface ZipFile {
  id: string
  collectionId: string
  keyEpoch: number
  name: string
  size: number
  fileKey: Uint8Array
  isRemote?: boolean
  remoteShareId?: string
  /** Where the encrypted blob is, under the API base, when it is not the
   *  file's own upload (an editor's latest saved version). */
  contentPath?: string
  /** Content already decrypted by the caller; nothing is fetched. */
  plain?: Uint8Array
}

export type ProgressCallback = (done: number, total: number, part: number, parts: number) => void

const hasFSA = () => typeof (window as any).showSaveFilePicker === 'function'

function partition(files: ZipFile[]): ZipFile[][] {
  const parts: ZipFile[][] = [[]]
  let current = 0
  for (const f of files) {
    if (current + f.size > SPLIT_BYTES && current > 0) {
      parts.push([])
      current = 0
    }
    parts[parts.length - 1].push(f)
    current += f.size
  }
  return parts
}

function toBuffer(chunk: Uint8Array): ArrayBuffer {
  return chunk.buffer.slice(chunk.byteOffset, chunk.byteOffset + chunk.byteLength) as ArrayBuffer
}

// pumpFileIntoZip — fetch + decrypt one member file chunk-by-chunk and feed
// each plaintext chunk into a fresh ZipPassThrough entry incrementally, so
// neither the encrypted blob nor the plaintext is ever fully buffered. After
// each pushed chunk it calls `flush()` — the caller's sink-specific drain of
// the ZIP-format chunks fflate has emitted (write to disk, or accumulate for
// the blob path). RAM stays ~constant regardless of file size.
async function pumpFileIntoZip(
  zip: Zip,
  f: ZipFile,
  base: string,
  accessToken: string,
  flush: () => Promise<void>,
  signal?: AbortSignal,
): Promise<void> {
  const entry = new ZipPassThrough(f.name)
  zip.add(entry)
  if (f.plain) {
    entry.push(f.plain, true)
    await flush()
    return
  }
  const url = f.contentPath
    ? `${base}${f.contentPath}`
    : f.isRemote
      ? `${base}/drive/federation/shares/${f.remoteShareId}/files/${f.id}/content`
      : `${base}/files/${f.id}/download`
  let pushed = false
  for await (const { plain, isFinal } of fetchDecryptedChunks(
    url,
    f.fileKey,
    { fileId: f.id, collectionId: f.collectionId, epoch: f.keyEpoch },
    accessToken,
    signal,
  )) {
    signal?.throwIfAborted()
    entry.push(plain, isFinal)
    pushed = true
    await flush()
  }
  if (!pushed) entry.push(new Uint8Array(0), true) // 0-byte file → finalise the entry
  await flush()
}

// Blob path (no FSA): accumulate the whole archive in memory.
async function buildPart(
  files: ZipFile[],
  partDone: number,
  total: number,
  onProgress: ProgressCallback,
  partIdx: number,
  parts: number,
  base: string,
  accessToken: string,
  signal?: AbortSignal,
): Promise<Uint8Array[]> {
  const chunks: Uint8Array[] = []
  const zip = new Zip((err, chunk) => {
    if (err) throw err
    chunks.push(chunk)
  })
  const flush = async () => {} // no streaming-to-disk here; chunks just accumulate
  for (let i = 0; i < files.length; i++) {
    signal?.throwIfAborted()
    await pumpFileIntoZip(zip, files[i], base, accessToken, flush, signal)
    onProgress(partDone + i + 1, total, partIdx + 1, parts)
  }
  zip.end()
  return chunks
}

// FSA path (Chrome / Edge): stream the ZIP straight to a FileSystemWritableFileStream.
async function streamPartToWritable(
  files: ZipFile[],
  writable: FileSystemWritableFileStream,
  partDone: number,
  total: number,
  onProgress: ProgressCallback,
  partIdx: number,
  parts: number,
  base: string,
  accessToken: string,
  signal?: AbortSignal,
): Promise<void> {
  const pending: Uint8Array[] = []
  const zip = new Zip((err, chunk) => {
    if (err) throw err
    pending.push(chunk)
  })
  const flush = async () => {
    for (const c of pending) await writable.write(toBuffer(c))
    pending.length = 0
  }
  try {
    for (let i = 0; i < files.length; i++) {
      signal?.throwIfAborted()
      await pumpFileIntoZip(zip, files[i], base, accessToken, flush, signal)
      onProgress(partDone + i + 1, total, partIdx + 1, parts)
    }
    zip.end()
    await flush()
    await writable.close()
  } catch (e) {
    await writable.close().catch(() => {})
    throw e
  }
}

function triggerBlobDownload(chunks: Uint8Array[], filename: string): void {
  const blob = new Blob(chunks as BlobPart[], { type: 'application/zip' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
  chunks.length = 0
}

export async function downloadAsZip(
  files: ZipFile[],
  folderName: string,
  accessToken: string,
  onProgress: ProgressCallback,
  signal?: AbortSignal,
): Promise<void> {
  if (files.length === 0) return

  const base = await resolveApiBase()
  const totalSize = files.reduce((n, f) => n + f.size, 0)
  const groups = partition(files)
  const total = files.length

  if (!hasFSA()) {
    if (totalSize > BLOB_FALLBACK_LIMIT) throw new FsaRequiredError()
    // Small download — collect in memory and trigger a blob download.
    const chunks = await buildPart(files, 0, total, onProgress, 0, 1, base, accessToken, signal)
    triggerBlobDownload(chunks, `${folderName}.zip`)
    return
  }

  let partDone = 0

  if (groups.length === 1) {
    const handle = await (window as any).showSaveFilePicker({
      suggestedName: `${folderName}.zip`,
      types: [{ description: 'ZIP archive', accept: { 'application/zip': ['.zip'] } }],
    })
    const writable = await handle.createWritable()
    await streamPartToWritable(groups[0], writable, 0, total, onProgress, 0, 1, base, accessToken, signal)
  } else {
    const dir = await (window as any).showDirectoryPicker({ mode: 'readwrite' })
    for (let i = 0; i < groups.length; i++) {
      signal?.throwIfAborted()
      const name = `${folderName}_part${i + 1}.zip`
      const handle = await dir.getFileHandle(name, { create: true })
      const writable = await handle.createWritable()
      await streamPartToWritable(groups[i], writable, partDone, total, onProgress, i, groups.length, base, accessToken, signal)
      partDone += groups[i].length
    }
  }
}
