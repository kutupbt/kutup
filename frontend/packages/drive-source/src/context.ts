// The app passes its DriveSource once, at the top (DriveSourceProvider); the
// screens read it here.

import { createContext, useContext } from 'react'
import type { DriveSource } from './source'

export const DriveSourceContext = createContext<DriveSource | null>(null)

export function useDriveSource(): DriveSource {
  const source = useContext(DriveSourceContext)
  if (!source) throw new Error('useDriveSource outside DriveSourceProvider')
  return source
}
