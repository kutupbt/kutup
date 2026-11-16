// The Photos library record (docs/plans/photos.md): an account's own marks
// on photos, an account record under its master key, bound to its key
// binding (docs/plans/w1-account-record.md), kept in the account-records
// store's `photosLibrary` scope (docs/plans/account-records.md). Rust owns
// the format; this module only moves text and bytes.
import type { MasterKeys } from './masterKeys'
import { getCryptoWasm } from './rustWasm'

/** Whose record: the account's master key and its key binding (`session.envelopeBinding`). */
export interface PhotosLibraryOwner {
  /** The account's master keys (`session.masterKeys`). */
  masterKeys: MasterKeys
  binding: string
}

/**
 * The record's marks. `v` is the format version (written as 1 when absent);
 * an opened record also carries whatever a newer client added, which a
 * spread (`{ ...marks, favourites }`) keeps for the next seal
 * (docs/plans/format-evolution.md).
 */
export interface PhotosLibraryMarks {
  v?: number
  favourites: string[]
  archived: string[]
  hidden: string[]
}

/** Seal `marks` (any order) as revision `revision` of the record `recordId`. */
export async function sealPhotosLibrary(
  marks: PhotosLibraryMarks,
  owner: PhotosLibraryOwner,
  recordId: string,
  revision: number,
): Promise<string> {
  return (await getCryptoWasm()).sealPhotosLibrary(
    JSON.stringify({ v: 1, ...marks }),
    owner.masterKeys,
    owner.binding,
    recordId,
    revision,
  )
}

/** Open the record `recordId` of this account: its marks and the revision it was sealed at. */
export async function openPhotosLibrary(
  envelope: string,
  owner: PhotosLibraryOwner,
  recordId: string,
): Promise<{ marks: PhotosLibraryMarks; revision: number }> {
  const opened = (await getCryptoWasm()).openPhotosLibrary(envelope, owner.masterKeys, owner.binding, recordId)
  return { marks: JSON.parse(opened.plaintext) as PhotosLibraryMarks, revision: opened.revision }
}
