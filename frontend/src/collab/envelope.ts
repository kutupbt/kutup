// Wire envelope for collaborative-edit frames — TS mirror of backend/services/envelope.
// See docs/superpowers/specs/2026-05-04-collab-edit-design.md §5 for the canonical layout.

export const KIND = {
  YJS_UPDATE: 1,
  YJS_AWARENESS: 2,
  SNAPSHOT_ANNOUNCE: 3,
  OO_OP: 4,
  OO_LOCK: 5,
  OO_CHECKPOINT_META: 6,
} as const
export type Kind = typeof KIND[keyof typeof KIND]

export const HEADER_SIZE = 30

export interface Frame {
  version: number
  kind: number
  docKeyId: number
  senderDeviceId: bigint
  sequence: bigint
  nonce: Uint8Array        // 24 bytes
  ciphertext: Uint8Array
  signature: Uint8Array    // 64 bytes
}

function leU32(v: number, out: Uint8Array, off: number) {
  new DataView(out.buffer, out.byteOffset, out.byteLength).setUint32(off, v, true)
}
function leU64(v: bigint, out: Uint8Array, off: number) {
  new DataView(out.buffer, out.byteOffset, out.byteLength).setBigUint64(off, v, true)
}
function rdU32(bs: Uint8Array, off: number): number {
  return new DataView(bs.buffer, bs.byteOffset, bs.byteLength).getUint32(off, true)
}
function rdU64(bs: Uint8Array, off: number): bigint {
  return new DataView(bs.buffer, bs.byteOffset, bs.byteLength).getBigUint64(off, true)
}

export function header(f: Frame): Uint8Array {
  const out = new Uint8Array(HEADER_SIZE)
  out[0] = f.version
  out[1] = f.kind
  leU32(f.docKeyId, out, 2)
  leU64(f.senderDeviceId, out, 6)
  leU64(f.sequence, out, 14)
  out.set(f.nonce.subarray(0, 8), 22)
  return out
}

export function pack(f: Frame): Uint8Array {
  if (f.nonce.length !== 24) throw new Error('envelope: nonce must be 24 bytes')
  if (f.signature.length !== 64) throw new Error('envelope: signature must be 64 bytes')
  const total = HEADER_SIZE + 16 + 4 + f.ciphertext.length + 64
  const out = new Uint8Array(total)
  out.set(header(f), 0)
  out.set(f.nonce.subarray(8), HEADER_SIZE)
  leU32(f.ciphertext.length, out, HEADER_SIZE + 16)
  out.set(f.ciphertext, HEADER_SIZE + 20)
  out.set(f.signature, HEADER_SIZE + 20 + f.ciphertext.length)
  return out
}

export function unpack(bs: Uint8Array): Frame {
  const minLen = HEADER_SIZE + 16 + 4 + 64
  if (bs.length < minLen) throw new Error('envelope: too short')
  const nonce = new Uint8Array(24)
  nonce.set(bs.subarray(22, 30), 0)
  nonce.set(bs.subarray(30, 46), 8)
  const clen = rdU32(bs, 46)
  if (bs.length !== 50 + clen + 64) throw new Error('envelope: bad ciphertext length')
  const ciphertext = bs.slice(50, 50 + clen)
  const signature = bs.slice(50 + clen, 50 + clen + 64)
  return {
    version: bs[0],
    kind: bs[1],
    docKeyId: rdU32(bs, 2),
    senderDeviceId: rdU64(bs, 6),
    sequence: rdU64(bs, 14),
    nonce,
    ciphertext,
    signature,
  }
}
