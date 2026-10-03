// A HEIC/HEIF photo's size (docs/plans/photos.md): the largest `ispe`
// (image spatial extent) property among the first bytes, which is the full
// image rather than its tiles or thumbnail, turned by `irot` if it turns a
// quarter. Bounded: only the start of the file, where HEIF keeps its
// properties.

const HEAD_BYTES = 512 * 1024

export async function heifSize(file: Blob): Promise<{ width: number; height: number } | undefined> {
  const bytes = new Uint8Array(await file.slice(0, Math.min(file.size, HEAD_BYTES)).arrayBuffer())
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  let best: { width: number; height: number } | undefined
  let quarterTurn = false
  for (let i = 4; i + 16 <= bytes.length; i++) {
    // 'ispe': size, then version and flags, then width and height.
    if (bytes[i] === 0x69 && bytes[i + 1] === 0x73 && bytes[i + 2] === 0x70 && bytes[i + 3] === 0x65) {
      if (view.getUint32(i - 4) !== 20) continue
      const width = view.getUint32(i + 8)
      const height = view.getUint32(i + 12)
      if (width > 0 && height > 0 && width <= 1_000_000 && height <= 1_000_000 && (!best || width * height > best.width * best.height)) {
        best = { width, height }
      }
    }
    // 'irot': size 9, then the angle in quarter turns anticlockwise.
    if (bytes[i] === 0x69 && bytes[i + 1] === 0x72 && bytes[i + 2] === 0x6f && bytes[i + 3] === 0x74 && view.getUint32(i - 4) === 9) {
      const angle = bytes[i + 4]! & 3
      if (angle === 1 || angle === 3) quarterTurn = true
    }
  }
  if (!best) return undefined
  return quarterTurn ? { width: best.height, height: best.width } : best
}
