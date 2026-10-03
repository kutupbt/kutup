import { createContext, useContext, useEffect } from 'react'
import type { Folder } from '@kutup/drive-core/model'

export const CurrentFolder = createContext<Folder | null>(null)
export const SetCurrentFolder = createContext<(folder: Folder | null) => void>(() => {})

export function useCurrentFolder(): Folder | null {
  return useContext(CurrentFolder)
}

/** A page declares its folder while mounted, so the sidebar's New menu puts things there. */
export function useDeclareCurrentFolder(folder: Folder | null | undefined) {
  const set = useContext(SetCurrentFolder)
  useEffect(() => {
    set(folder ?? null)
    return () => set(null)
  }, [folder, set])
}
