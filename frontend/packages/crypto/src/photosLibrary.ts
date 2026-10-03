// The Photos library record (docs/plans/photos.md): an account's own marks
// on photos, sealed under a subkey of its master key. Rust owns the format;
// this module only moves text and bytes.
import { toBase64 } from './base64'
import { getCryptoWasm } from './rustWasm'

export interface PhotosLibraryMarks {
  favourites: string[]
  archived: string[]
  hidden: string[]
}

export interface SealedPhotosLibrary {
  envelope: string
  digest: string
}

export interface PhotosLibraryHeader {
  accountIncarnationId: string
  revision: number
  previousDigest?: string
}

/** The record's key, from the master key. */
export async function photosLibraryKey(masterKey: Uint8Array): Promise<string> {
  return (await getCryptoWasm()).photosLibraryKey(toBase64(masterKey))
}

/** Seal `marks` (any order) as `revision`, after the record with `previousDigest`. */
export async function sealPhotosLibrary(
  marks: PhotosLibraryMarks,
  key: string,
  incarnationId: string,
  revision: number,
  previousDigest: string | undefined,
): Promise<SealedPhotosLibrary> {
  return (await getCryptoWasm()).sealPhotosLibrary(JSON.stringify(marks), key, incarnationId, revision, previousDigest)
}

export async function inspectPhotosLibrary(envelope: string): Promise<PhotosLibraryHeader> {
  return (await getCryptoWasm()).inspectPhotosLibrary(envelope)
}

/** Open a record as exactly what its header says it is, for this account. */
export async function openPhotosLibrary(envelope: string, key: string, incarnationId: string): Promise<{ marks: PhotosLibraryMarks; header: PhotosLibraryHeader }> {
  const module = await getCryptoWasm()
  const header = module.inspectPhotosLibrary(envelope)
  if (header.accountIncarnationId !== incarnationId) throw new Error('library record of another account')
  const text = module.openPhotosLibrary(envelope, key, incarnationId, header.revision, header.previousDigest)
  return { marks: JSON.parse(text) as PhotosLibraryMarks, header }
}
