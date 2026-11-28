import { createContext, useContext, useEffect } from 'react'
import type { FolderView } from '@kutup/drive-source/source'

export const CurrentFolder = createContext<FolderView | null>(null)
export const SetCurrentFolder = createContext<(folder: FolderView | null) => void>(() => {})

export function useCurrentFolder(): FolderView | null {
  return useContext(CurrentFolder)
}

/** A page declares its folder while mounted, so the sidebar's New menu puts things there. */
export function useDeclareCurrentFolder(folder: FolderView | null | undefined) {
  const set = useContext(SetCurrentFolder)
  useEffect(() => {
    set(folder ?? null)
    return () => set(null)
  }, [folder, set])
}
