// A RAW photo's picture (docs/plans/photos.md): browsers cannot develop RAW
// files, but cameras embed a full-size or large JPEG preview in them. This
// finds the largest one without reading the whole file:
// - TIFF-based RAW (DNG, CR2, NEF, NRW, ARW, ORF, RW2, PEF, SRW): the image
//   directories (IFD0, its SubIFDs, the chain), whose JPEG entries are either
//   JPEGInterchangeFormat/Length or a single JPEG-compressed strip;
// - Fujifilm RAF: the JPEG its header points to;
// - Canon CR3 (ISO BMFF): a bounded scan of its start for JPEG streams.
// Lossless JPEG (the raw sensor data in some DNGs) is skipped: only
// baseline or progressive JPEG, which the preview worker can decode.

export interface RawPreview {
  jpeg: Blob
  /** The RAW's EXIF orientation, which its preview does not carry. */
  orientation?: number
}

const MAX_PREVIEW_BYTES = 48 * 1024 * 1024
const MAX_IFDS = 64
const MAX_ENTRIES = 1024
const SCAN_BYTES = 16 * 1024 * 1024

interface Candidate {
  offset: number
  length: number
}

/** Reads at offsets of a Blob, a slice at a time. */
class Reader {
  private cache: { start: number; view: DataView } | null = null
  constructor(private readonly blob: Blob) {}

  get size(): number {
    return this.blob.size
  }

  async view(offset: number, length: number): Promise<DataView | null> {
    if (offset < 0 || length < 0 || offset + length > this.blob.size) return null
    const c = this.cache
    if (c && offset >= c.start && offset + length <= c.start + c.view.byteLength) {
      return new DataView(c.view.buffer, c.view.byteOffset + (offset - c.start), length)
    }
    // Read ahead: directories sit close together.
    const chunk = Math.min(this.blob.size - offset, Math.max(length, 256 * 1024))
    const view = new DataView(await this.blob.slice(offset, offset + chunk).arrayBuffer())
    this.cache = { start: offset, view }
    return new DataView(view.buffer, 0, length)
  }
}

/** Whether a JPEG stream (at `offset`) is one a browser decodes: SOF0, SOF1 or SOF2. */
async function decodableJpeg(reader: Reader, offset: number, length: number): Promise<boolean> {
  const head = await reader.view(offset, Math.min(length, 64 * 1024))
  if (!head || head.byteLength < 4 || head.getUint16(0) !== 0xffd8) return false
  let at = 2
  while (at + 4 <= head.byteLength) {
    if (head.getUint8(at) !== 0xff) return false
    const marker = head.getUint8(at + 1)
    if (marker === 0xd8 || (marker >= 0xd0 && marker <= 0xd7) || marker === 0x01) {
      at += 2
      continue
    }
    if (marker === 0xc0 || marker === 0xc1 || marker === 0xc2) return true
    // Lossless, arithmetic or hierarchical: not for a browser.
    if (marker >= 0xc3 && marker <= 0xcf && marker !== 0xc4 && marker !== 0xc8 && marker !== 0xcc) return false
    if (marker === 0xda) return false
    at += 2 + head.getUint16(at + 2)
  }
  return false
}

async function tiffCandidates(reader: Reader): Promise<{ candidates: Candidate[]; orientation?: number } | null> {
  const header = await reader.view(0, 8)
  if (!header) return null
  const order = header.getUint16(0)
  if (order !== 0x4949 && order !== 0x4d4d) return null
  const little = order === 0x4949
  const magic = header.getUint16(2, little)
  // 42: TIFF; 0x4f52 / 0x5352: Olympus ORF; 0x55: Panasonic RW2.
  if (magic !== 42 && magic !== 0x4f52 && magic !== 0x5352 && magic !== 0x55) return null
  const queue: number[] = [header.getUint32(4, little)]
  const seen = new Set<number>()
  const candidates: Candidate[] = []
  let orientation: number | undefined
  let first = true
  while (queue.length && seen.size < MAX_IFDS) {
    const offset = queue.shift()!
    if (!offset || seen.has(offset)) continue
    seen.add(offset)
    const countView = await reader.view(offset, 2)
    if (!countView) continue
    const count = countView.getUint16(0, little)
    if (count === 0 || count > MAX_ENTRIES) continue
    const table = await reader.view(offset + 2, count * 12 + 4)
    if (!table) continue
    let jpegOffset = 0
    let jpegLength = 0
    let compression = 0
    let stripOffset = 0
    let stripLength = 0
    let strips = 0
    for (let i = 0; i < count; i++) {
      const e = i * 12
      const tag = table.getUint16(e, little)
      const type = table.getUint16(e + 2, little)
      const n = table.getUint32(e + 4, little)
      // SHORT values sit in the first two bytes of the value field.
      const value = type === 3 ? table.getUint16(e + 8, little) : table.getUint32(e + 8, little)
      switch (tag) {
        case 0x0112:
          if (first && value >= 1 && value <= 8) orientation = value
          break
        case 0x0103:
          compression = value
          break
        case 0x0111:
          strips = n
          stripOffset = value
          break
        case 0x0117:
          stripLength = value
          break
        case 0x0201:
          jpegOffset = value
          break
        case 0x0202:
          jpegLength = value
          break
        case 0x014a: {
          // SubIFDs: one inline, or an array of offsets elsewhere.
          if (n === 1) queue.push(value)
          else if (n > 1 && n <= 16) {
            const list = await reader.view(value, n * 4)
            if (list) for (let k = 0; k < n; k++) queue.push(list.getUint32(k * 4, little))
          }
          break
        }
      }
    }
    if (jpegOffset && jpegLength) candidates.push({ offset: jpegOffset, length: jpegLength })
    if ((compression === 6 || compression === 7) && strips === 1 && stripOffset && stripLength) {
      candidates.push({ offset: stripOffset, length: stripLength })
    }
    queue.push(table.getUint32(count * 12, little))
    first = false
  }
  return { candidates, orientation }
}

async function rafCandidates(reader: Reader): Promise<Candidate[] | null> {
  const head = await reader.view(0, 92)
  if (!head) return null
  const magic = new TextDecoder().decode(new Uint8Array(head.buffer, head.byteOffset, 15))
  if (magic !== 'FUJIFILMCCD-RAW') return null
  return [{ offset: head.getUint32(84), length: head.getUint32(88) }]
}

/** JPEG streams in the file's start: each SOI up to the EOI after its scan. */
async function scannedCandidates(reader: Reader): Promise<Candidate[]> {
  const view = await reader.view(0, Math.min(reader.size, SCAN_BYTES))
  if (!view) return []
  const bytes = new Uint8Array(view.buffer, view.byteOffset, view.byteLength)
  const found: Candidate[] = []
  for (let i = 0; i + 3 < bytes.length && found.length < 16; i++) {
    if (bytes[i] !== 0xff || bytes[i + 1] !== 0xd8 || bytes[i + 2] !== 0xff) continue
    // Walk the segments to the scan, then find the end marker.
    let at = i + 2
    let ok = false
    while (at + 4 <= bytes.length) {
      if (bytes[at] !== 0xff) break
      const marker = bytes[at + 1]!
      const length = (bytes[at + 2]! << 8) | bytes[at + 3]!
      if (marker === 0xda) {
        ok = true
        at += 2 + length
        break
      }
      at += 2 + length
    }
    if (!ok) continue
    let end = at
    while (end + 1 < bytes.length && !(bytes[end] === 0xff && bytes[end + 1] === 0xd9)) end++
    if (end + 1 >= bytes.length) continue
    found.push({ offset: i, length: end + 2 - i })
    i = end + 1
  }
  return found
}

/** A RAW file's largest decodable embedded JPEG, or null when there is none. */
export async function extractRawPreview(file: Blob): Promise<RawPreview | null> {
  const reader = new Reader(file)
  let candidates: Candidate[] = []
  let orientation: number | undefined
  const tiff = await tiffCandidates(reader)
  if (tiff) {
    candidates = tiff.candidates
    orientation = tiff.orientation
  } else {
    candidates = (await rafCandidates(reader)) ?? (await scannedCandidates(reader))
  }
  const usable: Candidate[] = []
  for (const c of candidates) {
    if (c.length < 4 || c.length > MAX_PREVIEW_BYTES || c.offset + c.length > file.size) continue
    if (await decodableJpeg(reader, c.offset, c.length)) usable.push(c)
  }
  const best = usable.sort((a, b) => b.length - a.length)[0]
  if (!best) return null
  return {
    jpeg: file.slice(best.offset, best.offset + best.length, 'image/jpeg'),
    ...(orientation && orientation !== 1 ? { orientation } : {}),
  }
}

const RAW_EXTENSIONS = new Set(['dng', 'cr2', 'cr3', 'nef', 'nrw', 'arw', 'orf', 'rw2', 'pef', 'srw', 'raf'])

export function isRawName(name: string): boolean {
  const dot = name.lastIndexOf('.')
  return dot > 0 && RAW_EXTENSIONS.has(name.slice(dot + 1).toLowerCase())
}
