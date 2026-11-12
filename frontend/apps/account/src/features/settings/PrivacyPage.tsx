import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ExternalLink } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import api from '@kutup/session/client'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Card, CardContent } from '@kutup/ui/components/card'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { PageBody, PageHeader, Section } from '@kutup/ui/components/page'
import { LoadingPanel } from '@kutup/ui/components/states'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { formatInstant } from '@kutup/ui/lib/format'
import { documentName, oneEach, type LegalDocument } from '../auth/legal'
import { meKey, useMe } from './api'

/** The core's consent purposes (docs/plans/server-personal-data.md, A4). */
const PURPOSES = ['federation_abroad', 'marketing'] as const
type Purpose = (typeof PURPOSES)[number]

interface Consent {
  purpose: Purpose
  given: boolean
  documentId: string | null
  at: string
}

interface ConsentsView {
  consents: Consent[]
  documents: LegalDocument[]
}

const consentsKey = ['consents'] as const

/**
 * Settings → Privacy: each consent, given or withdrawn at any time, with the
 * text it was asked under. A purpose with no document published is still
 * yours to set.
 */
export function PrivacyPage() {
  const { t, i18n } = useTranslation()
  const queryClient = useQueryClient()
  const view = useQuery({
    queryKey: consentsKey,
    queryFn: async () => (await api.get<ConsentsView>('/user/consents')).data,
  })
  const change = useMutation({
    mutationFn: async ({ purpose, given, documentId }: { purpose: Purpose; given: boolean; documentId: string | null }) => {
      await api.put('/user/consents', { purpose, given, documentId })
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: consentsKey })
      // Withdrawing the consent to talk to other servers turns that off.
      void queryClient.invalidateQueries({ queryKey: meKey })
    },
    onError: (error) => toast.error(apiErrorMessage(error, t('settings.privacy.failed'))),
  })
  const me = useMe()
  const federation = useMutation({
    mutationFn: async ({ on, documentId }: { on: boolean; documentId: string | null }) => {
      await api.put('/user/federation', { on, documentId })
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: meKey })
      void queryClient.invalidateQueries({ queryKey: consentsKey })
    },
    onError: (error) => toast.error(apiErrorMessage(error, t('settings.privacy.failed'))),
  })
  // Turning it on asks for the consent when its text is published.
  const [asking, setAsking] = useState(false)

  return (
    <PageBody width="prose">
      <PageHeader title={t('settings.privacy.title')} description={t('settings.privacy.description')} />
      {view.isPending ? <LoadingPanel label={t('common.loading')} /> : null}
      {view.isError ? <Alert variant="error">{apiErrorMessage(view.error, t('common.tryAgain'))}</Alert> : null}
      {view.data && me.data ? (
        <Section title={t('settings.privacy.federation.title')} description={t('settings.privacy.federation.description')}>
          <Card>
            <CardContent className="flex items-start gap-4 p-5">
              <div className="min-w-0 flex-1 space-y-1">
                <p className="font-medium">
                  {t(me.data.federation === 'on' ? 'settings.privacy.federation.on' : 'settings.privacy.federation.off')}
                </p>
                <p className="text-sm text-muted-foreground">{t('settings.privacy.federation.hint')}</p>
              </div>
              <Button
                variant="outline"
                size="sm"
                loading={federation.isPending}
                onClick={() => {
                  if (me.data.federation === 'on') {
                    federation.mutate({ on: false, documentId: null })
                    return
                  }
                  const text = oneEach(view.data.documents.filter((d) => d.kind === 'federation_abroad'), i18n.language)[0]
                  const given = view.data.consents.find((c) => c.purpose === 'federation_abroad')?.given ?? false
                  if (text && !given) setAsking(true)
                  else federation.mutate({ on: true, documentId: null })
                }}
              >
                {t(me.data.federation === 'on' ? 'settings.privacy.federation.turnOff' : 'settings.privacy.federation.turnOn')}
              </Button>
            </CardContent>
          </Card>
          {asking ? (
            <FederationConsent
              text={oneEach(view.data.documents.filter((d) => d.kind === 'federation_abroad'), i18n.language)[0]}
              pending={federation.isPending}
              onCancel={() => setAsking(false)}
              onAgree={(documentId) => federation.mutate({ on: true, documentId }, { onSuccess: () => setAsking(false) })}
            />
          ) : null}
        </Section>
      ) : null}
      {view.data ? (
        <Section title={t('settings.privacy.consents')}>
          <Card className="divide-y divide-border p-0">
            {PURPOSES.map((purpose) => {
              const state = view.data.consents.find((c) => c.purpose === purpose)
              const text = oneEach(view.data.documents.filter((d) => d.kind === purpose), i18n.language)[0] as LegalDocument | undefined
              const given = state?.given ?? false
              return (
                <CardContent key={purpose} className="flex items-start gap-4 p-5">
                  <div className="min-w-0 flex-1 space-y-1">
                    <p className="font-medium">{t(`settings.privacy.purposes.${purpose}.title`)}</p>
                    <p className="text-sm text-muted-foreground">{t(`settings.privacy.purposes.${purpose}.description`)}</p>
                    {text ? (
                      <a
                        href={text.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 text-sm font-medium text-primary underline-offset-4 hover:underline"
                      >
                        {t('legal.readNamed', { name: documentName(t, text.kind), version: text.version })} <ExternalLink className="size-3" />
                      </a>
                    ) : null}
                    {state ? (
                      <p className="text-xs text-muted-foreground">
                        {t(given ? 'settings.privacy.givenAt' : 'settings.privacy.withdrawnAt', { date: formatInstant(state.at, i18n.language) })}
                      </p>
                    ) : null}
                  </div>
                  <Button
                    variant="outline"
                    size="sm"
                    loading={change.isPending && change.variables.purpose === purpose}
                    disabled={change.isPending}
                    onClick={() => change.mutate({ purpose, given: !given, documentId: given ? null : (text?.id ?? null) })}
                  >
                    {t(given ? 'settings.privacy.withdraw' : 'settings.privacy.give')}
                  </Button>
                </CardContent>
              )
            })}
          </Card>
        </Section>
      ) : null}
    </PageBody>
  )
}

/** The consent to talk to other servers, asked when its text is published. */
function FederationConsent({
  text,
  pending,
  onCancel,
  onAgree,
}: {
  text: LegalDocument
  pending: boolean
  onCancel: () => void
  onAgree: (documentId: string) => void
}) {
  const { t } = useTranslation()
  const [agreed, setAgreed] = useState(false)
  return (
    <Dialog open onOpenChange={(open) => (!open && !pending ? onCancel() : undefined)}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>{t('settings.privacy.federation.consentTitle')}</DialogTitle>
          <DialogDescription>{t('settings.privacy.purposes.federation_abroad.description')}</DialogDescription>
        </DialogHeader>
        <a
          href={text.url}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-1 text-sm font-medium text-primary underline-offset-4 hover:underline"
        >
          {t('legal.readNamed', { name: documentName(t, text.kind), version: text.version })} <ExternalLink className="size-3" />
        </a>
        <label className="flex items-start gap-2 text-sm">
          <Checkbox className="mt-0.5" checked={agreed} onCheckedChange={(value) => setAgreed(value === true)} />
          <span>{t('settings.privacy.federation.agree')}</span>
        </label>
        <DialogFooter>
          <Button variant="outline" onClick={onCancel} disabled={pending}>
            {t('common.cancel')}
          </Button>
          <Button loading={pending} disabled={!agreed} onClick={() => onAgree(text.id)}>
            {t('settings.privacy.federation.turnOn')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
