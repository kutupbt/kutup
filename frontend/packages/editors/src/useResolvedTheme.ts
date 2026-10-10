import { useTheme } from 'next-themes'

/** 'dark' or 'light' as actually shown (the editors pick their own palettes). */
export function useResolvedTheme(): 'dark' | 'light' {
  const { resolvedTheme } = useTheme()
  return resolvedTheme === 'dark' ? 'dark' : 'light'
}
