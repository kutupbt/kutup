import { createContext, useContext } from 'react'
import type { useLibrary } from './library'
import type { Marks } from './marks'

export type Library = ReturnType<typeof useLibrary> & {
  /** Upload photos and videos into the upload folder. */
  upload: (files: File[]) => Promise<void>
  /** Your favourites, archived and hidden photos. */
  marks: Marks
}

export const LibraryContext = createContext<Library | null>(null)

export function useLibraryContext(): Library {
  const library = useContext(LibraryContext)
  if (!library) throw new Error('useLibraryContext outside LibraryProvider')
  return library
}
