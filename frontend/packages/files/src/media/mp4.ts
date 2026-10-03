// What a video says about itself (docs/plans/photos.md): its creation time,
// place, size on screen and length, from the MP4/QuickTime boxes. Bounded:
// only box headers are read until `moov`, and `moov` itself only up to
// MAX_MOOV_BYTES. No decoding, no ffmpeg (Proton reads `mvhd` the same way).

import { parseCameraDate, type TakenDate } from './dates'

export interface VideoFacts {
  taken?: TakenDate
  lat?: number
  lon?: number
  width?: number
  height?: number
  durationMs?: number
}

const MAX_MOOV_BYTES = 32 * 1024 * 1024
const MAX_TOP_BOXES = 4096
/** Seconds from 1904-01-01 (QuickTime's epoch) to 1970-01-01. */
const EPOCH_1904 = 2_082_844_800

interface Box {
  type: string
  /** Where its content starts and ends, in the buffer or file. */
  start: number
  end: number
}

function fourcc(view: DataView, at: number): string {
  return String.fromCharCode(view.getUint8(at), view.getUint8(at + 1), view.getUint8(at + 2), view.getUint8(at + 3))
}

/** The boxes in `view` between `from` and `to`. */
function boxes(view: DataView, from: number, to: number): Box[] {
  const out: Box[] = []
  let at = from
  while (at + 8 <= to && out.length < 1024) {
    let size = view.getUint32(at)
    const type = fourcc(view, at + 4)
    let header = 8
    if (size === 1) {
      if (at + 16 > to) break
      const big = view.getBigUint64(at + 8)
      if (big > BigInt(to - at)) break
      size = Number(big)
      header = 16
    } else if (size === 0) {
      size = to - at
    }
    if (size < header || at + size > to) break
    out.push({ type, start: at + header, end: at + size })
    at += size
  }
  return out
}

function child(view: DataView, parent: Box, type: string): Box | undefined {
  return boxes(view, parent.start, parent.end).find((b) => b.type === type)
}

/** Finds `moov` by reading only box headers, then reads it whole. */
async function readMoov(file: Blob): Promise<DataView | undefined> {
  let at = 0
  for (let n = 0; n < MAX_TOP_BOXES && at + 8 <= file.size; n++) {
    const head = new DataView(await file.slice(at, at + 16).arrayBuffer())
    if (head.byteLength < 8) return undefined
    let size = head.getUint32(0)
    const type = fourcc(head, 4)
    let header = 8
    if (size === 1) {
      if (head.byteLength < 16) return undefined
      size = Number(head.getBigUint64(8))
      header = 16
    } else if (size === 0) {
      size = file.size - at
    }
    if (size < header) return undefined
    if (type === 'moov') {
      if (size > MAX_MOOV_BYTES) return undefined
      return new DataView(await file.slice(at, at + size).arrayBuffer())
    }
    at += size
  }
  return undefined
}

/** ISO 6709 as Apple and Android write it: "+41.0082+028.9784+012.000/". */
export function parseIso6709(value: string): { lat: number; lon: number } | undefined {
  const m = /^([+-]\d{1,2}(?:\.\d+)?)([+-]\d{1,3}(?:\.\d+)?)/.exec(value.trim())
  if (!m) return undefined
  const lat = Number(m[1])
  const lon = Number(m[2])
  if (!Number.isFinite(lat) || !Number.isFinite(lon) || Math.abs(lat) > 90 || Math.abs(lon) > 180) return undefined
  if (lat === 0 && lon === 0) return undefined
  return { lat, lon }
}

function text(view: DataView, start: number, end: number): string {
  return new TextDecoder('utf-8', { fatal: false }).decode(new Uint8Array(view.buffer, view.byteOffset + start, Math.max(0, end - start)))
}

/**
 * 3GPP's location box: version and flags, language, a name ending in a zero
 * byte, a role, then longitude, latitude and altitude as signed 16.16.
 */
function parseLoci(view: DataView, loci: Box): { lat: number; lon: number } | undefined {
  let at = loci.start + 6
  while (at < loci.end && view.getUint8(at) !== 0) at++
  at += 2
  if (at + 8 > loci.end) return undefined
  const lon = view.getInt32(at) / 65536
  const lat = view.getInt32(at + 4) / 65536
  if (Math.abs(lat) > 90 || Math.abs(lon) > 180 || (lat === 0 && lon === 0)) return undefined
  return { lat, lon }
}

/** Apple's `moov/meta` (keys + ilst): the named string values. */
function appleKeys(view: DataView, meta: Box): Map<string, string> {
  const values = new Map<string, string>()
  // QuickTime's `meta` has no version and flags; MP4's has four bytes of them.
  let start = meta.start
  if (meta.end - start >= 8 && fourcc(view, start + 4) !== 'hdlr') start += 4
  const inner: Box = { type: 'meta', start, end: meta.end }
  const keysBox = child(view, inner, 'keys')
  const ilst = child(view, inner, 'ilst')
  if (!keysBox || !ilst || keysBox.end - keysBox.start < 8) return values
  const names: string[] = []
  const count = view.getUint32(keysBox.start + 4)
  let at = keysBox.start + 8
  for (let i = 0; i < count && at + 8 <= keysBox.end; i++) {
    const size = view.getUint32(at)
    if (size < 8 || at + size > keysBox.end) break
    names.push(text(view, at + 8, at + size))
    at += size
  }
  for (const item of boxes(view, ilst.start, ilst.end)) {
    // An item's type is its key's 1-based index, as a number.
    const index = view.getUint32(item.start - 4) - 1
    const name = names[index]
    const data = child(view, item, 'data')
    if (!name || !data || data.end - data.start < 8) continue
    // Type 1 is UTF-8 text.
    if (view.getUint32(data.start) !== 1) continue
    values.set(name, text(view, data.start + 8, data.end))
  }
  return values
}

/** A video's facts, from a File or Blob. Unknown fields are left out. */
export async function readVideoFacts(file: Blob): Promise<VideoFacts> {
  const view = await readMoov(file)
  if (!view) return {}
  return factsFromMoov(view)
}

/** Parsing `moov` (exported for tests). */
export function factsFromMoov(view: DataView): VideoFacts {
  const facts: VideoFacts = {}
  const [moov] = boxes(view, 0, view.byteLength)
  if (!moov || moov.type !== 'moov') return facts
  const top = boxes(view, moov.start, moov.end)

  const mvhd = top.find((b) => b.type === 'mvhd')
  if (mvhd && mvhd.end - mvhd.start >= 20) {
    const version = view.getUint8(mvhd.start)
    let created: number
    let timescale: number
    let duration: number
    if (version === 1 && mvhd.end - mvhd.start >= 32) {
      created = Number(view.getBigUint64(mvhd.start + 4))
      timescale = view.getUint32(mvhd.start + 20)
      duration = Number(view.getBigUint64(mvhd.start + 24))
    } else {
      created = view.getUint32(mvhd.start + 4)
      timescale = view.getUint32(mvhd.start + 12)
      duration = view.getUint32(mvhd.start + 16)
    }
    // Zero means unset; many cameras write UTC here.
    if (created > EPOCH_1904) {
      const takenAt = (created - EPOCH_1904) * 1000
      if (takenAt < Date.now() + 86_400_000) facts.taken = { takenAt }
    }
    if (timescale > 0 && duration > 0 && duration < 2 ** 53) {
      facts.durationMs = Math.round((duration / timescale) * 1000)
    }
  }

  // The first track with a picture: its size, turned as it is shown.
  for (const trak of top.filter((b) => b.type === 'trak')) {
    const tkhd = child(view, trak, 'tkhd')
    if (!tkhd) continue
    const version = view.getUint8(tkhd.start)
    const matrixAt = tkhd.start + (version === 1 ? 52 : 40)
    if (matrixAt + 44 > tkhd.end) continue
    const width = view.getUint32(matrixAt + 36) / 65536
    const height = view.getUint32(matrixAt + 40) / 65536
    if (width < 1 || height < 1) continue
    // The matrix's a and b (16.16): a quarter turn has a = 0.
    const a = view.getInt32(matrixAt)
    const b = view.getInt32(matrixAt + 4)
    const turned = a === 0 && b !== 0
    facts.width = Math.round(turned ? height : width)
    facts.height = Math.round(turned ? width : height)
    break
  }

  // Apple's keys: the creation date with its time zone, and the place. An
  // iPhone writes them in moov/meta; other tools in moov/udta/meta.
  const udta = top.find((b) => b.type === 'udta')
  const udtaBoxes = udta ? boxes(view, udta.start, udta.end) : []
  for (const meta of [top.find((b) => b.type === 'meta'), udtaBoxes.find((b) => b.type === 'meta')]) {
    if (!meta) continue
    const keys = appleKeys(view, meta)
    const created = keys.get('com.apple.quicktime.creationdate')
    const taken = created ? parseCameraDate(created) : undefined
    if (taken) facts.taken = taken
    const place = keys.get('com.apple.quicktime.location.ISO6709')
    const where = place ? parseIso6709(place) : undefined
    if (where) Object.assign(facts, where)
  }

  // Android and others: udta/©xyz (ISO 6709 text) or 3GPP's udta/loci.
  if (facts.lat === undefined) {
    const xyz = udtaBoxes.find((b) => b.type === '\u00a9xyz')
    if (xyz && xyz.end - xyz.start > 4) {
      const where = parseIso6709(text(view, xyz.start + 4, xyz.end))
      if (where) Object.assign(facts, where)
    }
  }
  if (facts.lat === undefined) {
    const loci = udtaBoxes.find((b) => b.type === 'loci')
    const where = loci ? parseLoci(view, loci) : undefined
    if (where) Object.assign(facts, where)
  }
  return facts
}
