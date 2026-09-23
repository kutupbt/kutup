import { useState, type ReactNode } from 'react'
import { CurrentFolder, SetCurrentFolder } from './currentFolderContext'
import type { Folder } from './model'

/** Which folder the page shows (see useDeclareCurrentFolder). */
export function CurrentFolderProvider({ children }: { children: ReactNode }) {
  const [folder, setFolder] = useState<Folder | null>(null)
  return (
    <SetCurrentFolder.Provider value={setFolder}>
      <CurrentFolder.Provider value={folder}>{children}</CurrentFolder.Provider>
    </SetCurrentFolder.Provider>
  )
}
