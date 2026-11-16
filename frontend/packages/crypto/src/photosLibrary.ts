// The Photos library record (docs/plans/photos.md): an account's own marks
// on photos, an account record under its master key, bound to its key
// binding (docs/plans/w1-account-record.md). Rust owns the format; this
// module only moves text and bytes.
import type { MasterKeys } from './masterKeys'
import { getCryptoWasm } from './rustWasm'

/** Whose record: the account's master key and its key binding (`session.envelopeBinding`). */
export interface PhotosLibraryOwner {
  /** The account's master keys (`session.masterKeys`). */
  masterKeys: MasterKeys
  binding: string
}

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

/** Seal `marks` (any order) as `revision`, after the record with `previousDigest`. */
export async function sealPhotosLibrary(
  marks: PhotosLibraryMarks,
  owner: PhotosLibraryOwner,
  incarnationId: string,
  revision: number,
  previousDigest: string | undefined,
): Promise<SealedPhotosLibrary> {
  return (await getCryptoWasm()).sealPhotosLibrary(
    JSON.stringify(marks),
    owner.masterKeys,
    owner.binding,
    incarnationId,
    revision,
    previousDigest,
  )
}

/** A record's digest (lowercase hex SHA-256): what its successor names. */
export async function photosLibraryDigest(envelope: string): Promise<string> {
  return (await getCryptoWasm()).photosLibraryDigest(envelope)
}

export async function inspectPhotosLibrary(envelope: string): Promise<PhotosLibraryHeader> {
  return (await getCryptoWasm()).inspectPhotosLibrary(envelope)
}

/** Open a record as exactly what its header says it is, for this account. */
export async function openPhotosLibrary(
  envelope: string,
  owner: PhotosLibraryOwner,
  incarnationId: string,
): Promise<{ marks: PhotosLibraryMarks; header: PhotosLibraryHeader }> {
  const module = await getCryptoWasm()
  const header = module.inspectPhotosLibrary(envelope)
  if (header.accountIncarnationId !== incarnationId) throw new Error('library record of another account')
  const text = module.openPhotosLibrary(envelope, owner.masterKeys, owner.binding, incarnationId, header.revision, header.previousDigest)
  return { marks: JSON.parse(text) as PhotosLibraryMarks, header }
}
