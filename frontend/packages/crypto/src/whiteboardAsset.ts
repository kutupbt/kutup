import { fromBase64, toBase64 } from './base64'
import { getCryptoWasm } from './rustWasm'

/**
 * A whiteboard's embedded file, sealed under the file key and bound to the
 * file, the key's generation and the asset id — never the folder, so a
 * whiteboard moves with its assets untouched (docs/plans/drive-move.md).
 */
export interface WhiteboardAssetContextV1 {
  fileId: string
  assetId: string
  /** The generation of the file key it is sealed under. */
  generation: number
}

export async function sealWhiteboardAssetV1(
  plaintext: Uint8Array,
  fileKey: Uint8Array,
  context: WhiteboardAssetContextV1,
): Promise<Uint8Array> {
  const module = await getCryptoWasm()
  return fromBase64(module.sealWhiteboardAsset(
    toBase64(plaintext),
    toBase64(fileKey),
    context.fileId,
    context.assetId,
    context.generation,
  ))
}

export async function openWhiteboardAssetV1(
  envelope: Uint8Array,
  fileKey: Uint8Array,
  expected: WhiteboardAssetContextV1,
): Promise<Uint8Array> {
  const module = await getCryptoWasm()
  return fromBase64(module.openWhiteboardAsset(
    toBase64(envelope),
    toBase64(fileKey),
    expected.fileId,
    expected.assetId,
    expected.generation,
  ))
}
