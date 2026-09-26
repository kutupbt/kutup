import { createContext, useContext } from 'react'
import type { useLibrary } from './library'

export type Library = ReturnType<typeof useLibrary> & {
  /** Upload photos and videos into the upload folder. */
  upload: (files: File[]) => Promise<void>
}

export const LibraryContext = createContext<Library | null>(null)

export function useLibraryContext(): Library {
  const library = useContext(LibraryContext)
  if (!library) throw new Error('useLibraryContext outside LibraryProvider')
  return library
}
