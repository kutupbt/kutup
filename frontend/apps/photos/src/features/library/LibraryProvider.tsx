import { useMemo, type ReactNode } from 'react'
import { useRequiredSession } from '@kutup/session/store'
import { useUploadPhotos } from '../upload/useUploadPhotos'
import { useLibraryCatchUp } from './catchUp'
import { useLibrary } from './library'
import { LibraryContext } from './libraryContext'

/** The library, read once for the whole app, and kept up to date in the background. */
export function LibraryProvider({ children }: { children: ReactNode }) {
  const session = useRequiredSession()
  const library = useLibrary()
  const upload = useUploadPhotos(library.photos, library.preferences)
  useLibraryCatchUp(library.photos, session.userId, !library.loading)
  const value = useMemo(() => ({ ...library, upload }), [library, upload])
  return <LibraryContext.Provider value={value}>{children}</LibraryContext.Provider>
}
