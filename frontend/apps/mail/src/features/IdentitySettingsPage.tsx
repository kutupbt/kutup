import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { defaultAddressId, useOwnAddresses } from '@kutup/mail-core/addresses'
import { useMailIdentity, useUpdateMailIdentity } from '@kutup/mail-core/api'
import { sanitizeSignature } from '@kutup/mail-core/sanitize'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { PageBody, PageHeader } from '@kutup/ui/components/page'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@kutup/ui/components/select'
import { LoadingPanel } from '@kutup/ui/components/states'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { AddressesSection } from './AddressesSection'
import { SimpleEditor } from './SimpleEditor'

/**
 * Settings → Identity and addresses (Proton's): the account's addresses, and
 * the display name and signature of each enabled one.
 */
export function IdentitySettingsPage() {
  const { t } = useTranslation()
  const addresses = useOwnAddresses()
  const enabled = (addresses.data ?? []).filter((row) => !row.disabled)
  const [picked, setPicked] = useState<string | undefined>()
  // The picked address while it stays enabled, else the default.
  const addressId = enabled.some((row) => row.id === picked) ? picked : defaultAddressId(addresses.data ?? [])
  return (
    <PageBody>
      <PageHeader title={t('identity.title')} description={t('identity.description')} />
      <div className="space-y-10">
        <AddressesSection />
        <section className="max-w-2xl space-y-5" aria-labelledby="identity-heading">
          <h2 id="identity-heading" className="text-base font-semibold">
            {t('identity.nameAndSignature')}
          </h2>
          {enabled.length > 1 && addressId ? (
            <Select value={addressId} onValueChange={setPicked}>
              <SelectTrigger className="w-72" aria-label={t('identity.address')}>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {enabled.map((row) => (
                  <SelectItem key={row.id} value={row.id}>
                    {row.address}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          ) : null}
          {addresses.isPending ? null : <IdentityForm key={addressId ?? 'default'} addressId={addressId} />}
        </section>
      </div>
    </PageBody>
  )
}

/** One address's display name and signature. */
function IdentityForm({ addressId }: { addressId: string | undefined }) {
  const { t } = useTranslation()
  const identity = useMailIdentity(addressId)
  const update = useUpdateMailIdentity(addressId)
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
    <form
        className="space-y-5"
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
  )
}
