import { Zip, ZipPassThrough } from 'fflate'
import api from '@/api/client'
import { decryptStream } from '@/crypto'
import { isTauri } from '@/lib/isTauri'

// 2 GB — ZIP32 max; Windows Explorer and most real-world readers cap here.
const SPLIT_BYTES = 2 * 1024 * 1024 * 1024
// Below this threshold, non-FSA browsers get an in-memory blob fallback.
const BLOB_FALLBACK_LIMIT = 500 * 1024 * 1024

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

async function buildPart(
  files: ZipFile[],
  partDone: number,
  total: number,
  onProgress: ProgressCallback,
  partIdx: number,
  parts: number,
  signal?: AbortSignal,
): Promise<Uint8Array[]> {
  const chunks: Uint8Array[] = []
  const zip = new Zip((err, chunk) => {
    if (err) throw err
    chunks.push(chunk)
  })

  for (let i = 0; i < files.length; i++) {
    signal?.throwIfAborted()
    const f = files[i]
    const path = f.isRemote
      ? `/fed-proxy/${f.remoteShareId}/files/${f.id}/download`
      : `/files/${f.id}/download`

    const res = await api.get(path, { responseType: 'arraybuffer', signal })
    const plain = await decryptStream(new Uint8Array(res.data), f.fileKey)

    const entry = new ZipPassThrough(f.name)
    zip.add(entry)
    entry.push(plain, true)

    onProgress(partDone + i + 1, total, partIdx + 1, parts)
  }

  zip.end()
  return chunks
}

async function streamPartToWritable(
  files: ZipFile[],
  writable: FileSystemWritableFileStream,
  partDone: number,
  total: number,
  onProgress: ProgressCallback,
  partIdx: number,
  parts: number,
  signal?: AbortSignal,
): Promise<void> {
  const pending: Uint8Array[] = []
  const zip = new Zip((err, chunk) => {
    if (err) throw err
    pending.push(chunk)
  })

  try {
    for (let i = 0; i < files.length; i++) {
      signal?.throwIfAborted()
      const f = files[i]
      const path = f.isRemote
        ? `/fed-proxy/${f.remoteShareId}/files/${f.id}/download`
        : `/files/${f.id}/download`

      const res = await api.get(path, { responseType: 'arraybuffer', signal })
      const plain = await decryptStream(new Uint8Array(res.data), f.fileKey)

      const entry = new ZipPassThrough(f.name)
      zip.add(entry)
      entry.push(plain, true)

      for (const chunk of pending) await writable.write(toBuffer(chunk))
      pending.length = 0

      onProgress(partDone + i + 1, total, partIdx + 1, parts)
    }

    zip.end()
    for (const chunk of pending) await writable.write(toBuffer(chunk))
    await writable.close()
  } catch (e) {
    await writable.close().catch(() => {})
    throw e
  }
}

function triggerBlobDownload(chunks: Uint8Array[], filename: string): void {
  const total = chunks.reduce((n, c) => n + c.byteLength, 0)
  const merged = new Uint8Array(total)
  let offset = 0
  for (const c of chunks) { merged.set(c, offset); offset += c.byteLength }
  const blob = new Blob([merged.buffer], { type: 'application/zip' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
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
  signal?: AbortSignal,
): Promise<void> {
  const pending: Uint8Array[] = []
  const zip = new Zip((err, chunk) => {
    if (err) throw err
    pending.push(chunk)
  })
  try {
    for (let i = 0; i < files.length; i++) {
      signal?.throwIfAborted()
      const f = files[i]
      const path = f.isRemote
        ? `/fed-proxy/${f.remoteShareId}/files/${f.id}/download`
        : `/files/${f.id}/download`
      const res = await api.get(path, { responseType: 'arraybuffer', signal })
      const plain = await decryptStream(new Uint8Array(res.data), f.fileKey)
      const entry = new ZipPassThrough(f.name)
      zip.add(entry)
      entry.push(plain, true)
      for (const chunk of pending) await file.write(chunk)
      pending.length = 0
      onProgress(partDone + i + 1, total, partIdx + 1, parts)
    }
    zip.end()
    for (const chunk of pending) await file.write(chunk)
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
      filters: [{ name: 'ZIP archive', extensions: ['zip'] }],
      title: 'Save ZIP',
    })
    if (!path) throw new DOMException('save cancelled', 'AbortError')
    const file = (await fs.open(path, {
      write: true,
      create: true,
      truncate: true,
    })) as unknown as TauriFileHandle
    await streamPartToTauriFile(groups[0], file, 0, total, onProgress, 0, 1, signal)
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
    await streamPartToTauriFile(groups[i], file, partDone, total, onProgress, i, groups.length, signal)
    partDone += groups[i].length
  }
}

export async function downloadAsZip(
  files: ZipFile[],
  folderName: string,
  onProgress: ProgressCallback,
  signal?: AbortSignal,
): Promise<void> {
  if (files.length === 0) return

  const totalSize = files.reduce((n, f) => n + f.size, 0)
  const groups = partition(files)
  const total = files.length

  if (isTauri) {
    await downloadAsZipTauri(groups, folderName, total, onProgress, signal)
    return
  }

  if (!hasFSA()) {
    if (totalSize > BLOB_FALLBACK_LIMIT) throw new FsaRequiredError()
    // Small download — collect in memory and trigger blob download
    const chunks = await buildPart(files, 0, total, onProgress, 0, 1, signal)
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
    await streamPartToWritable(groups[0], writable, 0, total, onProgress, 0, 1, signal)
  } else {
    const dir = await (window as any).showDirectoryPicker({ mode: 'readwrite' })
    for (let i = 0; i < groups.length; i++) {
      signal?.throwIfAborted()
      const name = `${folderName}_part${i + 1}.zip`
      const handle = await dir.getFileHandle(name, { create: true })
      const writable = await handle.createWritable()
      await streamPartToWritable(groups[i], writable, partDone, total, onProgress, i, groups.length, signal)
      partDone += groups[i].length
    }
  }
}
