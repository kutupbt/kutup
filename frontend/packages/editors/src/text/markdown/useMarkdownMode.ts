// View-mode state for the notes markdown editor (Edit / Split / Read).
// Persisted per-file in localStorage so a user's preference for a given
// note survives reloads. Falls back to 'edit' for unknown files.

import { useEffect, useState } from 'react'

export type MarkdownMode = 'edit' | 'split' | 'read'

const VALID: MarkdownMode[] = ['edit', 'split', 'read']

function storageKey(fileId: string): string {
  return `kutup-md-mode-${fileId}`
}

function readStored(fileId: string): MarkdownMode {
  try {
    const v = localStorage.getItem(storageKey(fileId))
    if (v && (VALID as string[]).includes(v)) return v as MarkdownMode
  } catch { /* localStorage may be disabled in some contexts */ }
  return 'edit'
}

export function useMarkdownMode(fileId: string): [MarkdownMode, (m: MarkdownMode) => void] {
  const [mode, setMode] = useState<MarkdownMode>(() => readStored(fileId))

  // Re-read when the file changes (different note → its own preference).
  useEffect(() => {
    setMode(readStored(fileId))
  }, [fileId])

  function update(next: MarkdownMode) {
    setMode(next)
    try {
      localStorage.setItem(storageKey(fileId), next)
    } catch { /* persisted-best-effort */ }
  }

  return [mode, update]
}

/** Cycle to the next mode in the order Edit → Split → Read → Edit. */
export function nextMode(m: MarkdownMode): MarkdownMode {
  const i = VALID.indexOf(m)
  return VALID[(i + 1) % VALID.length]
}

/** Cycle to the previous mode (Read → Split → Edit → Read). */
export function prevMode(m: MarkdownMode): MarkdownMode {
  const i = VALID.indexOf(m)
  return VALID[(i - 1 + VALID.length) % VALID.length]
}
