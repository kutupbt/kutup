export type Theme = 'dark' | 'light'

const KEY = 'kutup-theme'

type Listener = (t: Theme) => void
const listeners = new Set<Listener>()

export function getTheme(): Theme {
  return (localStorage.getItem(KEY) as Theme) ?? 'dark'
}

export function applyTheme(theme: Theme) {
  document.documentElement.classList.toggle('dark', theme === 'dark')
  document.documentElement.classList.toggle('light', theme === 'light')
  localStorage.setItem(KEY, theme)
  listeners.forEach((l) => l(theme))
}

export function toggleTheme(): Theme {
  const next = getTheme() === 'dark' ? 'light' : 'dark'
  applyTheme(next)
  return next
}

// In-tab pub/sub. Cross-tab sync uses the native `storage` event — see
// hooks/useTheme.ts. Returns an unsubscribe function.
export function subscribeTheme(cb: Listener): () => void {
  listeners.add(cb)
  return () => { listeners.delete(cb) }
}
