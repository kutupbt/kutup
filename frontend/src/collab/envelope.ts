// Public collaboration-frame discriminants. The canonical wire parser,
// serializer, KDF and AEAD live in kutup-crypto and are consumed through WASM.

export const KIND = {
  YJS_UPDATE: 1,
  YJS_AWARENESS: 2,
  SNAPSHOT_ANNOUNCE: 3,
  OO_OP: 4,
  OO_LOCK: 5,
  OO_CHECKPOINT_META: 6,
  OO_CURSOR: 7,
  EXCALIDRAW_OP: 8,
  EXCALIDRAW_CURSOR: 9,
} as const

export type Kind = typeof KIND[keyof typeof KIND]

export interface OpenedCollabFrameV1 {
  kind: number
  keyEpoch: number
  docKeyId: number
  senderDeviceId: bigint
  sequence: bigint
  plaintext: Uint8Array
}
