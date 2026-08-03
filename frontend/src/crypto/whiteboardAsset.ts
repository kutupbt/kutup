import { fromBase64, toBase64 } from './base64'
import { getCryptoWasm } from './rustWasm'

export interface WhiteboardAssetContextV1 {
  fileId: string
  collectionId: string
  assetId: string
  epoch: number
}

export async function sealWhiteboardAssetV1(
  plaintext: Uint8Array,
  collectionKey: Uint8Array,
  context: WhiteboardAssetContextV1,
): Promise<Uint8Array> {
  const module = await getCryptoWasm()
  return fromBase64(module.sealWhiteboardAsset(
    toBase64(plaintext),
    toBase64(collectionKey),
    context.fileId,
    context.collectionId,
    context.assetId,
    context.epoch,
  ))
}

export async function openWhiteboardAssetV1(
  envelope: Uint8Array,
  collectionKey: Uint8Array,
  expected: WhiteboardAssetContextV1,
): Promise<Uint8Array> {
  const module = await getCryptoWasm()
  return fromBase64(module.openWhiteboardAsset(
    toBase64(envelope),
    toBase64(collectionKey),
    expected.fileId,
    expected.collectionId,
    expected.assetId,
    expected.epoch,
  ))
}
