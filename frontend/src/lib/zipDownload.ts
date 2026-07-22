import { Zip, ZipPassThrough } from 'fflate'
import { fetchDecryptedChunks } from '@/download/fetchDecrypt'
import { resolveApiBase } from '@/lib/apiBase'
import { isTauri } from '@/lib/isTauri'

// 2 GB — ZIP32 max; Windows Explorer and most real-world readers cap here.
const SPLIT_BYTES = 2 * 1024 * 1024 * 1024
// On browsers without the File System Access API (Firefox / Safari) the ZIP
// must be assembled fully in memory before `<a download>` can save it — so
// it's capped. The FSA / Tauri paths stream to disk and have no cap.
const BLOB_FALLBACK_LIMIT = 1 * 1024 * 1024 * 1024 // 1 GB

export class FsaRequiredError extends Error {
  code = 'NO_FSA'
  constructor() { super('File System Access API required for large downloads') }
}

export interface ZipFile {
  id: string
  name: string
  size: number
  fileKey: Uint8Array
  isRemote?: boolean
  remoteShareId?: string
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
  const url = f.isRemote
    ? `${base}/drive/federation/shares/${f.remoteShareId}/files/${f.id}/content`
    : `${base}/files/${f.id}/download`
  const entry = new ZipPassThrough(f.name)
  zip.add(entry)
  let pushed = false
  for await (const { plain, isFinal } of fetchDecryptedChunks(url, f.fileKey, accessToken, signal)) {
    signal?.throwIfAborted()
    entry.push(plain, isFinal)
    pushed = true
    await flush()
  }
  if (!pushed) entry.push(new Uint8Array(0), true) // 0-byte file → finalise the entry
  await flush()
}

// Blob path (no FSA, not Tauri): accumulate the whole archive in memory.
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

// ---------------------------------------------------------------------------
// Tauri path — WebKitGTK / WKWebView have no File System Access API, so use
// the native save dialog (single ZIP) or directory picker (multi-part) plus
// @tauri-apps/plugin-fs streaming writes. Mirrors streamPartToWritable.
// ---------------------------------------------------------------------------

interface TauriFileHandle {
  write(data: Uint8Array): Promise<number>
  close(): Promise<void>
}

async function streamPartToTauriFile(
  files: ZipFile[],
  file: TauriFileHandle,
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
    for (const c of pending) await file.write(c)
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
    await file.close()
  } catch (e) {
    await file.close().catch(() => {})
    throw e
  }
}

async function downloadAsZipTauri(
  groups: ZipFile[][],
  folderName: string,
  total: number,
  base: string,
  accessToken: string,
  onProgress: ProgressCallback,
  signal?: AbortSignal,
): Promise<void> {
  const [{ save, open: openDialog }, fs] = await Promise.all([
    import('@tauri-apps/plugin-dialog'),
    import('@tauri-apps/plugin-fs'),
  ])

  if (groups.length === 1) {
    const path = await save({
      defaultPath: `${folderName}.zip`,
      title: 'Save ZIP',
    })
    if (!path) throw new DOMException('save cancelled', 'AbortError')
    const file = (await fs.open(path, {
      write: true,
      create: true,
      truncate: true,
    })) as unknown as TauriFileHandle
    await streamPartToTauriFile(groups[0], file, 0, total, onProgress, 0, 1, base, accessToken, signal)
    return
  }

  // >2 GB total → split into parts → pick a directory to drop them in.
  const dir = await openDialog({
    directory: true,
    multiple: false,
    title: `Choose a folder for the ${groups.length} ZIP parts`,
  })
  if (!dir || typeof dir !== 'string') {
    throw new DOMException('directory pick cancelled', 'AbortError')
  }
  let partDone = 0
  for (let i = 0; i < groups.length; i++) {
    signal?.throwIfAborted()
    const file = (await fs.open(`${dir}/${folderName}_part${i + 1}.zip`, {
      write: true,
      create: true,
      truncate: true,
    })) as unknown as TauriFileHandle
    await streamPartToTauriFile(groups[i], file, partDone, total, onProgress, i, groups.length, base, accessToken, signal)
    partDone += groups[i].length
  }
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

  if (isTauri) {
    await downloadAsZipTauri(groups, folderName, total, base, accessToken, onProgress, signal)
    return
  }

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
