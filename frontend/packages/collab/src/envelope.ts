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

/** A frame as opened: its sender, its public header and its plaintext. */
export interface OpenedCollabFrame {
  /**
   * The sender's account (`aci:<uuid>@<server>`), as the server delivered
   * it. The signature covers it; recipients check that against the
   * sender's manifest from slice 3 on.
   */
  sender: string
  kind: number
  keyGeneration: number
  docKeyId: number
  /** The sender's device, 1..127 within its account. */
  deviceId: number
  /** The sender's manifest when it sealed the frame. */
  manifestSequence: bigint
  sequence: bigint
  plaintext: Uint8Array
}

/**
 * One device in a room: device ids are per account, so a peer is its
 * account and device together. A delivered frame's sender and device id
 * give the same key as the server's peer list (`account`, `deviceId`).
 */
export function peerKey(account: string, deviceId: number): string {
  return `${account}#${deviceId}`
}
