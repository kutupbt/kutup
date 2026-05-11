import { useEffect, useState } from 'react'
import { type Theme, getTheme, subscribeTheme, applyTheme, toggleTheme } from '@/lib/theme'

// Reactive companion to lib/theme.ts. Components that read the current
// theme should use this hook so they re-render when the theme changes
// (toggled from any pane: Sidebar, FileEditorPage navbar, another tab).
export function useTheme(): [Theme, () => Theme, (t: Theme) => void] {
  const [theme, setTheme] = useState<Theme>(getTheme)
  useEffect(() => {
    const unsub = subscribeTheme(setTheme)
    function onStorage(e: StorageEvent) {
      if (e.key === 'kutup-theme' && (e.newValue === 'dark' || e.newValue === 'light')) {
        setTheme(e.newValue)
      }
    }
    window.addEventListener('storage', onStorage)
    return () => {
      unsub()
      window.removeEventListener('storage', onStorage)
    }
  }, [])
  return [theme, toggleTheme, applyTheme]
}
