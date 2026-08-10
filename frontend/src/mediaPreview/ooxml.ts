export type OoxmlContainerType = 'docx' | 'pptx' | 'xlsx'

export interface OoxmlInspectionLimitsV1 {
  maxEntries: number
  maxCentralDirectoryBytes: number
  maxEntryUncompressedBytes: number
  maxTotalUncompressedBytes: number
  maxCompressionRatio: number
}

export const OOXML_INSPECTION_LIMITS_V1: OoxmlInspectionLimitsV1 = Object.freeze({
  maxEntries: 4096,
  maxCentralDirectoryBytes: 4 * 1024 * 1024,
  maxEntryUncompressedBytes: 256 * 1024 * 1024,
  maxTotalUncompressedBytes: 512 * 1024 * 1024,
  maxCompressionRatio: 100,
})

const EOCD_SIGNATURE = 0x06054b50
const CENTRAL_SIGNATURE = 0x02014b50
const MAX_ZIP_COMMENT_BYTES = 0xffff
const EOCD_BYTES = 22

/**
 * Inspect only the bounded ZIP tail and central directory. No entry is
 * decompressed and no relationship or external resource is followed.
 */
export async function inspectOoxmlContainerV1(
  file: Blob,
  limits: OoxmlInspectionLimitsV1 = OOXML_INSPECTION_LIMITS_V1,
  signal?: AbortSignal,
): Promise<OoxmlContainerType | null> {
  validateLimits(limits)
  throwIfAborted(signal)
  const tailStart = Math.max(0, file.size - EOCD_BYTES - MAX_ZIP_COMMENT_BYTES)
  const tail = new Uint8Array(await readBlob(file.slice(tailStart)))
  throwIfAborted(signal)
  const eocdInTail = findEocd(tail)
  if (eocdInTail < 0) return null
  const eocd = new DataView(tail.buffer, tail.byteOffset + eocdInTail, tail.byteLength - eocdInTail)
  const commentBytes = eocd.getUint16(20, true)
  if (eocdInTail + EOCD_BYTES + commentBytes !== tail.length ||
      eocd.getUint16(4, true) !== 0 || eocd.getUint16(6, true) !== 0) return null
  const entriesOnDisk = eocd.getUint16(8, true)
  const totalEntries = eocd.getUint16(10, true)
  const centralBytes = eocd.getUint32(12, true)
  const centralOffset = eocd.getUint32(16, true)
  if (entriesOnDisk === 0xffff || totalEntries === 0xffff ||
      centralBytes === 0xffff_ffff || centralOffset === 0xffff_ffff ||
      entriesOnDisk !== totalEntries || totalEntries < 1 || totalEntries > limits.maxEntries ||
      centralBytes < 46 || centralBytes > limits.maxCentralDirectoryBytes ||
      centralOffset + centralBytes > file.size ||
      centralOffset + centralBytes > tailStart + eocdInTail) return null

  const central = new Uint8Array(await readBlob(file.slice(centralOffset, centralOffset + centralBytes)))
  throwIfAborted(signal)
  return inspectCentralDirectory(central, totalEntries, limits)
}

function inspectCentralDirectory(
  bytes: Uint8Array,
  expectedEntries: number,
  limits: OoxmlInspectionLimitsV1,
): OoxmlContainerType | null {
  const decoder = new TextDecoder('utf-8', { fatal: true })
  let offset = 0
  let entries = 0
  let compressedTotal = 0
  let uncompressedTotal = 0
  let hasContentTypes = false
  let hasDocx = false
  let hasPptx = false
  let hasXlsx = false
  while (offset < bytes.length) {
    if (offset + 46 > bytes.length) return null
    const view = new DataView(bytes.buffer, bytes.byteOffset + offset, bytes.byteLength - offset)
    if (view.getUint32(0, true) !== CENTRAL_SIGNATURE) return null
    const flags = view.getUint16(8, true)
    const method = view.getUint16(10, true)
    const compressedBytes = view.getUint32(20, true)
    const uncompressedBytes = view.getUint32(24, true)
    const nameBytes = view.getUint16(28, true)
    const extraBytes = view.getUint16(30, true)
    const commentBytes = view.getUint16(32, true)
    const diskStart = view.getUint16(34, true)
    const recordBytes = 46 + nameBytes + extraBytes + commentBytes
    if (nameBytes < 1 || offset + recordBytes > bytes.length || diskStart !== 0 ||
        (flags & 0x0001) !== 0 || (method !== 0 && method !== 8) ||
        compressedBytes === 0xffff_ffff || uncompressedBytes === 0xffff_ffff ||
        uncompressedBytes > limits.maxEntryUncompressedBytes) return null
    let name: string
    try {
      name = decoder.decode(bytes.subarray(offset + 46, offset + 46 + nameBytes))
    } catch {
      return null
    }
    if (!safeZipPath(name)) return null
    const lowerName = name.toLowerCase()
    if (lowerName === '[content_types].xml') hasContentTypes = true
    if (lowerName === 'word/document.xml') hasDocx = true
    if (lowerName === 'ppt/presentation.xml') hasPptx = true
    if (lowerName === 'xl/workbook.xml') hasXlsx = true
    if (lowerName.endsWith('/vbaproject.bin') || lowerName.includes('/activex/')) return null
    compressedTotal += compressedBytes
    uncompressedTotal += uncompressedBytes
    if (!Number.isSafeInteger(compressedTotal) || !Number.isSafeInteger(uncompressedTotal) ||
        uncompressedTotal > limits.maxTotalUncompressedBytes) return null
    entries += 1
    offset += recordBytes
  }
  if (offset !== bytes.length || entries !== expectedEntries || !hasContentTypes ||
      uncompressedTotal > Math.max(1024 * 1024, compressedTotal * limits.maxCompressionRatio)) {
    return null
  }
  const kinds = [hasDocx, hasPptx, hasXlsx].filter(Boolean).length
  if (kinds !== 1) return null
  if (hasDocx) return 'docx'
  if (hasPptx) return 'pptx'
  return 'xlsx'
}

function findEocd(bytes: Uint8Array): number {
  if (bytes.length < EOCD_BYTES) return -1
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  for (let offset = bytes.length - EOCD_BYTES; offset >= 0; offset -= 1) {
    if (view.getUint32(offset, true) === EOCD_SIGNATURE) return offset
  }
  return -1
}

function safeZipPath(name: string): boolean {
  if (!name || name.includes('\0') || name.includes('\\') || name.startsWith('/') ||
      /^[a-z]:/iu.test(name)) return false
  return !name.split('/').some(part => part === '..')
}

function validateLimits(limits: OoxmlInspectionLimitsV1): void {
  for (const value of [
    limits.maxEntries,
    limits.maxCentralDirectoryBytes,
    limits.maxEntryUncompressedBytes,
    limits.maxTotalUncompressedBytes,
    limits.maxCompressionRatio,
  ]) {
    if (!Number.isSafeInteger(value) || value < 1) throw new Error('invalid OOXML inspection limits')
  }
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw new DOMException('OOXML inspection aborted', 'AbortError')
}

function readBlob(blob: Blob): Promise<ArrayBuffer> {
  if (typeof blob.arrayBuffer === 'function') return blob.arrayBuffer()
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onerror = () => reject(reader.error ?? new Error('OOXML container could not be read'))
    reader.onload = () => reader.result instanceof ArrayBuffer
      ? resolve(reader.result)
      : reject(new Error('OOXML reader returned invalid bytes'))
    reader.readAsArrayBuffer(blob)
  })
}
