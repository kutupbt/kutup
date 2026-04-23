export type Theme = 'dark' | 'light'

const KEY = 'kutup-theme'

export function getTheme(): Theme {
  return (localStorage.getItem(KEY) as Theme) ?? 'dark'
}

export function applyTheme(theme: Theme) {
  document.documentElement.classList.toggle('dark', theme === 'dark')
  document.documentElement.classList.toggle('light', theme === 'light')
  localStorage.setItem(KEY, theme)
}

export function toggleTheme(): Theme {
  const next = getTheme() === 'dark' ? 'light' : 'dark'
  applyTheme(next)
  return next
}
