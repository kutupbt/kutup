import type { ReactNode } from 'react'
import { DriveSourceContext } from './context'
import type { DriveSource } from './source'

export function DriveSourceProvider({ source, children }: { source: DriveSource; children: ReactNode }) {
  return <DriveSourceContext.Provider value={source}>{children}</DriveSourceContext.Provider>
}
