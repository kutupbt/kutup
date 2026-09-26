import { useTranslation } from 'react-i18next'
import { Button } from './button'

/**
 * Switch between the two shipped locales.
 *
 * `onChrome` says which surface it is standing on: the rail (chrome tokens)
 * or the **auth screens**, which have no rail and sit on `bg-muted`, where
 * the content tokens fit.
 */
export function LocaleToggle({ onChrome = true }: { onChrome?: boolean } = {}) {
  const { t, i18n } = useTranslation()
  // Anything that is not Turkish is treated as English, matching i18next's
  // `fallbackLng` — a browser reporting `en-GB` must not land in a third state.
  const next = i18n.language.startsWith('tr') ? 'en' : 'tr'

  return (
    <Button
      variant={onChrome ? 'chrome' : 'outline'}
      size="sm"
      className={onChrome ? 'border border-chrome-border' : undefined}
      onClick={() => void i18n.changeLanguage(next)}
      aria-label={t('common.switchLanguage')}
    >
      {next.toUpperCase()}
    </Button>
  )
}
