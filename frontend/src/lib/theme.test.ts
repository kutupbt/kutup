import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import {
  getSystemTheme,
  getThemePreference,
  resolveTheme,
  getTheme,
  applyTheme,
  toggleTheme,
  isThemePreference,
} from './theme'

const KEY = 'kutup-theme'

// Make window.matchMedia('(prefers-color-scheme: dark)') report `dark`.
function mockOSDark(dark: boolean) {
  vi.spyOn(window, 'matchMedia').mockImplementation(
    (query: string) =>
      ({
        matches: query.includes('dark') ? dark : !dark,
        media: query,
        onchange: null,
        addListener: () => {},
        removeListener: () => {},
        addEventListener: () => {},
        removeEventListener: () => {},
        dispatchEvent: () => false,
      }) as unknown as MediaQueryList,
  )
}

describe('theme', () => {
  beforeEach(() => {
    localStorage.clear()
    document.documentElement.className = ''
    document.documentElement.style.colorScheme = ''
  })
  afterEach(() => {
    vi.restoreAllMocks()
  })

  describe('isThemePreference', () => {
    it('accepts light/dark/system, rejects everything else', () => {
      expect(isThemePreference('light')).toBe(true)
      expect(isThemePreference('dark')).toBe(true)
      expect(isThemePreference('system')).toBe(true)
      expect(isThemePreference('')).toBe(false)
      expect(isThemePreference(null)).toBe(false)
      expect(isThemePreference('Dark')).toBe(false)
      expect(isThemePreference(undefined)).toBe(false)
      expect(isThemePreference(0)).toBe(false)
    })
  })

  describe('getSystemTheme', () => {
    it('returns dark when the OS prefers dark', () => {
      mockOSDark(true)
      expect(getSystemTheme()).toBe('dark')
    })
    it('returns light when the OS prefers light / has no preference', () => {
      mockOSDark(false)
      expect(getSystemTheme()).toBe('light')
    })
  })

  describe('resolveTheme', () => {
    it('passes through light/dark', () => {
      expect(resolveTheme('light')).toBe('light')
      expect(resolveTheme('dark')).toBe('dark')
    })
    it('resolves system via getSystemTheme', () => {
      mockOSDark(true)
      expect(resolveTheme('system')).toBe('dark')
      mockOSDark(false)
      expect(resolveTheme('system')).toBe('light')
    })
  })

  describe('getThemePreference', () => {
    it('defaults to system when nothing is stored', () => {
      expect(getThemePreference()).toBe('system')
    })
    it('defaults to system when the stored value is garbage', () => {
      localStorage.setItem(KEY, 'banana')
      expect(getThemePreference()).toBe('system')
    })
    it('returns the stored preference when valid', () => {
      localStorage.setItem(KEY, 'dark')
      expect(getThemePreference()).toBe('dark')
      localStorage.setItem(KEY, 'light')
      expect(getThemePreference()).toBe('light')
      localStorage.setItem(KEY, 'system')
      expect(getThemePreference()).toBe('system')
    })
  })

  describe('getTheme (resolved)', () => {
    it('follows the OS when nothing is stored', () => {
      mockOSDark(true)
      expect(getTheme()).toBe('dark')
      mockOSDark(false)
      expect(getTheme()).toBe('light')
    })
    it('returns the pinned preference regardless of the OS', () => {
      mockOSDark(true)
      localStorage.setItem(KEY, 'light')
      expect(getTheme()).toBe('light')
    })
  })

  describe('applyTheme', () => {
    it("applies 'system': sets the resolved class + persists 'system'", () => {
      mockOSDark(true)
      applyTheme('system')
      expect(document.documentElement.classList.contains('dark')).toBe(true)
      expect(document.documentElement.classList.contains('light')).toBe(false)
      expect(document.documentElement.style.colorScheme).toBe('dark')
      expect(localStorage.getItem(KEY)).toBe('system') // still following the OS next launch
    })
    it("applies a concrete theme: pins it", () => {
      mockOSDark(true)
      applyTheme('light')
      expect(document.documentElement.classList.contains('light')).toBe(true)
      expect(document.documentElement.classList.contains('dark')).toBe(false)
      expect(document.documentElement.style.colorScheme).toBe('light')
      expect(localStorage.getItem(KEY)).toBe('light')
    })
  })

  describe('toggleTheme', () => {
    it('flips the resolved theme and pins a concrete value', () => {
      mockOSDark(false) // OS = light, no stored pref → resolved = light
      const next = toggleTheme()
      expect(next).toBe('dark')
      expect(getThemePreference()).toBe('dark') // pinned, no longer 'system'
      expect(document.documentElement.classList.contains('dark')).toBe(true)
      const back = toggleTheme()
      expect(back).toBe('light')
      expect(getThemePreference()).toBe('light')
    })
  })
})
