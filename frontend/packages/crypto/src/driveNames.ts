// Names unique in a folder without the server reading them, and files it
// can recognise as already there (crates/kutup-crypto/src/drive_names.rs,
// which owns the format; this file only converts types).

import { fromBase64, toBase64 } from './base64'
import { getCryptoWasm } from './rustWasm'

/** A folder's hash key, from its first (epoch 1) folder key: the same through every rotation. */
export async function folderHashKey(firstFolderKey: Uint8Array, collectionId: string): Promise<Uint8Array> {
  const wasm = await getCryptoWasm()
  return fromBase64(wasm.driveFolderHashKey(toBase64(firstFolderKey), collectionId))
}

/** The hash a name is kept unique by in its folder (case and composition aside). */
export async function nameHash(hashKey: Uint8Array, name: string): Promise<string> {
  const wasm = await getCryptoWasm()
  return wasm.driveNameHash(toBase64(hashKey), name)
}

/** The hash a file's content is recognised by in its folder, from its SHA-256 (base64, `hashBlob`'s). */
export async function contentHash(hashKey: Uint8Array, contentSha256: string): Promise<string> {
  const wasm = await getCryptoWasm()
  return wasm.driveContentHash(toBase64(hashKey), contentSha256)
}

/** The form two names are compared in. */
export async function canonicalName(name: string): Promise<string> {
  const wasm = await getCryptoWasm()
  return wasm.driveCanonicalName(name)
}
