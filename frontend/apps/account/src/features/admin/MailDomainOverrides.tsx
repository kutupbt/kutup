import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import api from '@kutup/session/client'
import { Button } from '@kutup/ui/components/button'
import { Card } from '@kutup/ui/components/card'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@kutup/ui/components/select'
import { Skeleton } from '@kutup/ui/components/skeleton'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { adminKey } from './api'

interface Overrides {
  maxDomains: number | null
  maxAddresses: number | null
  catchAll: boolean | null
}

/** The overrides as the server shows them, with each one's range. */
interface OverridesView extends Overrides {
  maxDomainsRange: { min: number; max: number }
  maxAddressesRange: { min: number; max: number }
}

/** A number field's value, `null` when left empty (the site's). */
function parsed(value: string): number | null {
  return value.trim() === '' ? null : Number(value)
}

/**
 * One account's custom-domain limits over the site's
 * (docs/plans/mail-custom-domains.md §7): domains, addresses, catch-all;
 * each left empty keeps the site's value.
 */
export function MailDomainOverridesCard({ userId }: { userId: string }) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const key = [...adminKey, 'mail', 'domains', 'overrides', userId] as const
  const current = useQuery({
    queryKey: key,
    queryFn: async () => (await api.get<OverridesView>(`/admin/users/${userId}/mail-domains`)).data,
  })
  const [domains, setDomains] = useState('')
  const [addresses, setAddresses] = useState('')
  const [catchAll, setCatchAll] = useState<'site' | 'on' | 'off'>('site')
  useEffect(() => {
    if (!current.data) return
    setDomains(current.data.maxDomains?.toString() ?? '')
    setAddresses(current.data.maxAddresses?.toString() ?? '')
    setCatchAll(current.data.catchAll === null ? 'site' : current.data.catchAll ? 'on' : 'off')
  }, [current.data])
  const save = useMutation({
    mutationFn: async (body: Overrides) => (await api.put<Overrides>(`/admin/users/${userId}/mail-domains`, body)).data,
    onSuccess: (saved) => {
      queryClient.setQueryData<OverridesView>(key, (old) => (old ? { ...old, ...saved } : old))
      toast.success(t('admin.mailDomains.overrides.saved'))
    },
    onError: (e) => toast.error(apiErrorMessage(e, t('common.tryAgain'))),
  })
  if (current.isPending) return <Skeleton className="h-24 w-full" />
  if (current.isError) return <p className="p-4 text-sm text-destructive">{apiErrorMessage(current.error, t('common.tryAgain'))}</p>
  const maxDomains = parsed(domains)
  const maxAddresses = parsed(addresses)
  // The ranges are the server's (the site settings these override).
  const { maxDomainsRange: dr, maxAddressesRange: ar } = current.data
  const within = (value: number | null, range: { min: number; max: number }) =>
    value === null || (Number.isInteger(value) && value >= range.min && value <= range.max)
  const valid = within(maxDomains, dr) && within(maxAddresses, ar)
  return (
    <Card className="space-y-3 p-4" data-testid="mail-domain-overrides">
      <p className="text-sm text-muted-foreground">{t('admin.mailDomains.overrides.description')}</p>
      <div className="grid gap-3 sm:grid-cols-3">
        <Field label={t('admin.mailDomains.overrides.maxDomains')} description={t('admin.mailDomains.range', { min: dr.min, max: dr.max })}>
          {(props) => <Input {...props} type="number" min={dr.min} max={dr.max} placeholder={t('admin.mailDomains.overrides.site')} value={domains} onChange={(e) => setDomains(e.target.value)} />}
        </Field>
        <Field label={t('admin.mailDomains.overrides.maxAddresses')} description={t('admin.mailDomains.range', { min: ar.min, max: ar.max })}>
          {(props) => (
            <Input {...props} type="number" min={ar.min} max={ar.max} placeholder={t('admin.mailDomains.overrides.site')} value={addresses} onChange={(e) => setAddresses(e.target.value)} />
          )}
        </Field>
        <Field label={t('admin.mailDomains.overrides.catchAll')}>
          {(props) => (
            <Select value={catchAll} onValueChange={(value) => setCatchAll(value as typeof catchAll)}>
              <SelectTrigger {...props}>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="site">{t('admin.mailDomains.overrides.site')}</SelectItem>
                <SelectItem value="on">{t('admin.mailDomains.on')}</SelectItem>
                <SelectItem value="off">{t('admin.mailDomains.off')}</SelectItem>
              </SelectContent>
            </Select>
          )}
        </Field>
      </div>
      <Button
        size="sm"
        disabled={!valid}
        loading={save.isPending}
        onClick={() => save.mutate({ maxDomains, maxAddresses, catchAll: catchAll === 'site' ? null : catchAll === 'on' })}
      >
        {t('common.save')}
      </Button>
    </Card>
  )
}
