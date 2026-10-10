import { lazy, Suspense } from 'react'
import { useTranslation } from 'react-i18next'
import { LoadingPanel } from '@kutup/ui/components/states'

// A public link's document page loads when one is opened, not with the app.
const PublicFilePage = lazy(() => import('./public/PublicFilePage').then((m) => ({ default: m.PublicFilePage })))

/** `/s/:token` and `/s/:token/:fid`: a document reached by a public link, without an account. */
export function PublicFileRoute() {
  const { t } = useTranslation()
  return (
    <Suspense
      fallback={
        <div className="flex min-h-svh items-center justify-center bg-background">
          <LoadingPanel label={t('publicFile.decrypting')} />
        </div>
      }
    >
      <PublicFilePage />
    </Suspense>
  )
}
