import { useState, type ReactNode } from 'react'
import { CurrentFolder, SetCurrentFolder } from './currentFolderContext'
import type { FolderView } from '@kutup/drive-source/source'

/** Which folder the page shows (see useDeclareCurrentFolder). */
export function CurrentFolderProvider({ children }: { children: ReactNode }) {
  const [folder, setFolder] = useState<FolderView | null>(null)
  return (
    <SetCurrentFolder.Provider value={setFolder}>
      <CurrentFolder.Provider value={folder}>{children}</CurrentFolder.Provider>
    </SetCurrentFolder.Provider>
  )
}
