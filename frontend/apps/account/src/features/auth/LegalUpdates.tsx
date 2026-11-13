import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { AuthLayout } from './AuthLayout'
import { DocumentChecks } from './DocumentChecks'
import { acknowledgeDocuments, oneEach, type LegalDocument } from './legal'

/** Shown once after a sign-in when a required document has a new version. */
export function LegalUpdates({ documents, onDone }: { documents: LegalDocument[]; onDone: () => void }) {
  const { t, i18n } = useTranslation()
  const shown = oneEach(documents, i18n.language)
  const [confirmed, setConfirmed] = useState<string[]>([])
  const [error, setError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)

  async function confirm() {
    if (!shown.every((d) => confirmed.includes(d.id))) {
      setError(t('legal.confirmAll'))
      return
    }
    setPending(true)
    setError(null)
    try {
      await acknowledgeDocuments(shown.map((d) => d.id))
      onDone()
    } catch (err) {
      setError(apiErrorMessage(err, t('legal.confirmFailed')))
    } finally {
      setPending(false)
    }
  }

  return (
    <AuthLayout title={t('legal.updatedTitle')} description={t('legal.updatedDescription')}>
      <div className="space-y-4">
        <DocumentChecks documents={shown} checked={confirmed} onChange={setConfirmed} />
        {error ? <Alert variant="error">{error}</Alert> : null}
        <Button type="button" className="w-full" loading={pending} onClick={() => void confirm()}>
          {t('legal.continue')}
        </Button>
      </div>
    </AuthLayout>
  )
}
