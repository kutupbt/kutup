import { useTranslation } from 'react-i18next'
import { KutupLogo } from '@kutup/ui/components/brand'

export function NotFoundPage() {
  const { t } = useTranslation()
  return (
    <main className="flex min-h-svh flex-col items-center justify-center gap-4 px-6 text-center">
      <KutupLogo size={40} />
      <h1 className="font-display text-2xl font-semibold tracking-tight">{t('notFound.title')}</h1>
      <p className="max-w-md text-sm text-muted-foreground">{t('notFound.description')}</p>
    </main>
  )
}
