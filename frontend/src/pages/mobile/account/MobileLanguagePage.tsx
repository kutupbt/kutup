import { useTranslation } from 'react-i18next'
import { Icon, ICONS } from '@/components/mobile/Icon'
import { MobileAccountSubPage } from '@/pages/mobile/account/MobileAccountSubPage'
import { Surface } from '@/components/ui/surface'
import { PressableRow } from '@/components/ui/pressable-row'

/**
 * MobileLanguagePage — `/drive/account/language`.
 *
 * Simple language picker for the i18n catalog (currently English + Turkish).
 * Persists via i18next's `changeLanguage` — the existing
 * `i18next-browser-languagedetector` writes to localStorage automatically.
 */

const LANGS: Array<{ code: 'en' | 'tr'; native: string; english: string }> = [
  { code: 'en', native: 'English', english: 'English' },
  { code: 'tr', native: 'Türkçe', english: 'Turkish' },
]

export default function MobileLanguagePage() {
  const { t, i18n } = useTranslation()
  const current = (i18n.resolvedLanguage ?? i18n.language ?? 'en').slice(0, 2)

  return (
    <MobileAccountSubPage title={t('mobile.account.language', 'Language')}>
      <Surface>
        {LANGS.map((lang, i) => {
          const active = lang.code === current
          return (
            <PressableRow
              key={lang.code}
              onClick={() => void i18n.changeLanguage(lang.code)}
              last={i === LANGS.length - 1}
              ariaLabel={lang.english}
            >
              <div className="flex-1 min-w-0">
                <div className="text-sm font-medium text-text-primary">{lang.native}</div>
                {lang.english !== lang.native && (
                  <div className="text-[12px] text-text-tertiary mt-0.5">{lang.english}</div>
                )}
              </div>
              {active && (
                <span
                  className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-primary-faint text-primary"
                  aria-label={t('mobile.account.language.selected', 'Selected')}
                >
                  <Icon d="M5 13l4 4L19 7" size={14} strokeWidth={2.5} />
                </span>
              )}
            </PressableRow>
          )
        })}
      </Surface>
    </MobileAccountSubPage>
  )
}
