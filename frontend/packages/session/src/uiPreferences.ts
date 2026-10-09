import { useEffect, useRef } from 'react'
import { useTheme } from 'next-themes'
import { useTranslation } from 'react-i18next'
import api from './client'

/**
 * Theme and language follow the account (docs/roadmap.md, "Web · theme and
 * language follow the account"). Each app keeps its own copy for the first
 * paint, so a page never flashes the wrong theme; this takes the account's
 * values when the app opens and when its tab comes back into view, and saves
 * a change made here so every other app and device takes it too.
 *
 * Call once in each signed-in app's shell. Offline, or when the server
 * cannot be reached, the local choice stays and nothing is lost.
 */

export type ThemeChoice = 'light' | 'dark' | 'system'
export type LanguageChoice = 'en' | 'tr'

export interface UiPreferences {
  theme: ThemeChoice | null
  language: LanguageChoice | null
}

const PATH = '/account/ui-preferences'

function languageOf(language: string | undefined): LanguageChoice {
  // As the locale toggle does: anything not Turkish is English.
  return language?.startsWith('tr') ? 'tr' : 'en'
}

function themeOf(theme: string | undefined): ThemeChoice {
  return theme === 'light' || theme === 'dark' ? theme : 'system'
}

export function useAccountUiPreferences(): void {
  const { theme, setTheme } = useTheme()
  const { i18n } = useTranslation()
  const local = { theme: themeOf(theme), language: languageOf(i18n.language) }
  const localRef = useRef(local)
  localRef.current = local
  // What the account holds as far as this app knows: null until it has been
  // read, so nothing is saved over it before then.
  const account = useRef<UiPreferences | null>(null)
  // Values taken from the account that this app has not shown yet: the theme
  // and the language land in separate renders, and the one still on its way
  // is not a change made here.
  const arriving = useRef<Partial<UiPreferences>>({})

  useEffect(() => {
    let current = true
    const read = async () => {
      let stored: UiPreferences
      try {
        stored = (await api.get<UiPreferences>(PATH)).data
      } catch {
        return
      }
      if (!current) return
      account.current = stored
      if (stored.theme && stored.theme !== localRef.current.theme) {
        arriving.current.theme = stored.theme
        setTheme(stored.theme)
      }
      if (stored.language && stored.language !== localRef.current.language) {
        arriving.current.language = stored.language
        void i18n.changeLanguage(stored.language)
      }
      // Never chosen for the account: this app's choice becomes it.
      if (!stored.theme || !stored.language) void save()
    }
    const save = async () => {
      const next: UiPreferences = {
        theme: account.current?.theme ?? localRef.current.theme,
        language: account.current?.language ?? localRef.current.language,
      }
      account.current = next
      try {
        await api.put(PATH, next)
      } catch {
        // Kept locally; the next change or visit saves it.
      }
    }
    const onVisible = () => {
      if (document.visibilityState === 'visible') void read()
    }
    void read()
    document.addEventListener('visibilitychange', onVisible)
    return () => {
      current = false
      document.removeEventListener('visibilitychange', onVisible)
    }
    // Once per mount: the effect below saves later changes.
  }, [])

  // A change made here (the theme or language control) goes to the account;
  // one that came from the account matches it and is not sent back.
  useEffect(() => {
    const stored = account.current
    if (!stored) return
    const pending = arriving.current
    if (pending.theme === local.theme) delete pending.theme
    if (pending.language === local.language) delete pending.language
    // A value still arriving from the account stands for the account's.
    const theme = pending.theme ?? local.theme
    const language = pending.language ?? local.language
    if (stored.theme === theme && stored.language === language) return
    const next: UiPreferences = { theme, language }
    account.current = next
    void api.put(PATH, next).catch(() => undefined)
  }, [local.theme, local.language])
}
