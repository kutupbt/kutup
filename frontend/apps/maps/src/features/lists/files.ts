import { MAX_IMPORT_BYTES, readPlaceFile, UnreadablePlaceFile, type ImportedList } from '@kutup/map/exchange'
import type { Place } from '@kutup/map/list'

/** Offer `content` as a file to save, made on the device. */
export function saveFile(filename: string, content: BlobPart, type: string): void {
  const url = URL.createObjectURL(new Blob([content], { type }))
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export class PlaceFileTooLarge extends Error {
  constructor() {
    super('place file too large')
  }
}

/** A KML, GPX or Kutup list file chosen by the person, read on the device. */
export async function readChosenFile(file: File, fallbackName: (n: number) => string): Promise<ImportedList> {
  if (file.size > MAX_IMPORT_BYTES) throw new PlaceFileTooLarge()
  return readPlaceFile(await file.text(), fallbackName)
}

/** Imported points as places added now by `addedBy`. */
export function asPlaces(imported: ImportedList, addedBy: string): Place[] {
  const now = Date.now()
  // A millisecond apart, so the list keeps the file's order.
  return imported.places.map((p, i) => ({ ...p, id: crypto.randomUUID(), addedBy, addedAt: new Date(now + i).toISOString() }))
}

/** The title a file suggests: its own name inside, else its file name. */
export function titleOf(imported: ImportedList, file: File): string {
  return (imported.title ?? file.name.replace(/\.(kml|gpx|kutupmap|json)$/i, '')).trim().slice(0, 240) || 'Map'
}

export { UnreadablePlaceFile }

export const IMPORT_ACCEPT = '.kml,.gpx,.kutupmap,application/vnd.google-earth.kml+xml,application/gpx+xml'
