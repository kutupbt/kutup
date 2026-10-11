import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { useMailIdentity, useUpdateMailIdentity } from '@kutup/mail-core/api'
import { sanitizeSignature } from '@kutup/mail-core/sanitize'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { PageBody, PageHeader } from '@kutup/ui/components/page'
import { LoadingPanel } from '@kutup/ui/components/states'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { SimpleEditor } from './SimpleEditor'

/** Settings → Identity (Proton's Identity and addresses): display name and signature. */
export function IdentitySettingsPage() {
  const { t } = useTranslation()
  const identity = useMailIdentity()
  const update = useUpdateMailIdentity()
  const [name, setName] = useState('')
  const [signature, setSignature] = useState('')
  const [error, setError] = useState<string | undefined>()
  const loaded = identity.data
  useEffect(() => {
    if (loaded) {
      setName(loaded.displayName)
      setSignature(loaded.signature)
    }
  }, [loaded])

  if (identity.isPending) return <LoadingPanel label={t('common.loading')} />
  if (identity.isError) return <Alert variant="error">{apiErrorMessage(identity.error, t('common.tryAgain'))}</Alert>

  function save() {
    const trimmed = name.trim()
    if (trimmed.length > 100) {
      setError(t('identity.nameTooLong'))
      return
    }
    const clean = sanitizeSignature(signature)
    if (new TextEncoder().encode(clean).length > 10_000) {
      toast.error(t('identity.signatureTooLong'))
      return
    }
    update.mutate(
      { displayName: trimmed, signature: clean },
      {
        onSuccess: () => toast.success(t('general.saved')),
        onError: (e) => toast.error(apiErrorMessage(e, t('common.tryAgain'))),
      },
    )
  }

  return (
    <PageBody>
      <PageHeader title={t('identity.title')} description={t('identity.description', { address: identity.data.address })} />
      <form
        className="max-w-2xl space-y-5"
        onSubmit={(e) => {
          e.preventDefault()
          save()
        }}
      >
        <Field label={t('identity.displayName')} description={t('identity.displayNameHint')} error={error}>
          {(props) => (
            <Input
              {...props}
              value={name}
              maxLength={100}
              onChange={(e) => {
                setName(e.target.value)
                setError(undefined)
              }}
            />
          )}
        </Field>
        <div className="space-y-2">
          <p className="text-sm font-medium">{t('identity.signature')}</p>
          <p className="text-sm text-muted-foreground">{t('identity.signatureHint')}</p>
          {loaded ? <SimpleEditor key={loaded.address} value={loaded.signature} label={t('identity.signature')} onChange={(html) => setSignature(html)} /> : null}
        </div>
        <Button type="submit" disabled={update.isPending}>
          {t('common.save')}
        </Button>
      </form>
    </PageBody>
  )
}
