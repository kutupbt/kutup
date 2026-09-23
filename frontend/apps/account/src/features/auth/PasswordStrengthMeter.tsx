import { useTranslation } from 'react-i18next'
import { cn } from '@kutup/ui/lib/cn'

const LABEL_KEYS = [
  'auth.strength.veryWeak',
  'auth.strength.weak',
  'auth.strength.fair',
  'auth.strength.strong',
  'auth.strength.veryStrong',
] as const

/** Four segments filling with the score; the label says it in words too. */
export function PasswordStrengthMeter({ score }: { score: number | null }) {
  const { t } = useTranslation()
  if (score === null) return null
  const tone = score < 2 ? 'bg-status-danger' : score < 3 ? 'bg-status-warn' : 'bg-status-ok'
  return (
    <div className="space-y-1" aria-live="polite">
      <div className="flex gap-1" aria-hidden>
        {[1, 2, 3, 4].map((segment) => (
          <span
            key={segment}
            className={cn('h-1 flex-1 rounded-full', score >= segment ? tone : 'bg-muted')}
          />
        ))}
      </div>
      <p className="text-xs text-muted-foreground">
        {t('auth.strength.label', { strength: t(LABEL_KEYS[score] ?? LABEL_KEYS[0]) })}
      </p>
    </div>
  )
}
