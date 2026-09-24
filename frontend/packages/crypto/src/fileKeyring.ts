import { fromBase64, toBase64 } from './base64'
import { getCryptoWasm } from './rustWasm'

/**
 * A file's keys across its generations (docs/plans/drive-move.md). A re-key
 * gives the file a new key and seals the one it leaves under it, so the
 * current key reaches every older one — in whichever folder the file is.
 */

/** One entry of a file row's `keyHistory`: generation `g` seals `g − 1`. */
export interface FileKeyLinkV1 {
  generation: number
  previousKeyEnvelope: string
}

/** Seal the key of `generation − 1` under the key of `generation`. */
export async function sealPreviousFileKeyV1(
  previousKey: Uint8Array,
  key: Uint8Array,
  fileId: string,
  generation: number,
): Promise<string> {
  const module = await getCryptoWasm()
  return module.sealPreviousFileKey(toBase64(previousKey), toBase64(key), fileId, generation)
}

/**
 * The file key of generation `wanted`, from the current key (of
 * `generation`) and the complete chain (generations 2 to `generation`).
 * Throws unless every link opens under the one after it.
 */
export async function fileKeyAtV1(
  currentKey: Uint8Array,
  fileId: string,
  generation: number,
  chain: FileKeyLinkV1[],
  wanted: number,
): Promise<Uint8Array> {
  if (wanted === generation) return currentKey
  const module = await getCryptoWasm()
  return fromBase64(module.fileKeyAt(
    toBase64(currentKey),
    fileId,
    generation,
    chain.map((link) => ({
      generation: link.generation,
      previousKeyEnvelope: link.previousKeyEnvelope,
    })),
    wanted,
  ))
}
