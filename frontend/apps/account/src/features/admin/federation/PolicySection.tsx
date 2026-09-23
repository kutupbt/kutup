import { Copy } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import type { AdminFederationPolicy, FederationMinimumTrust, FederationMode } from '@kutup/session/api-types'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Card, CardContent } from '@kutup/ui/components/card'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { Label } from '@kutup/ui/components/label'
import { Mono } from '@kutup/ui/components/mono'
import { Fact, Section } from '@kutup/ui/components/page'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { copyText } from '@kutup/ui/lib/clipboard'
import { useUpdateFederationPolicy, type FederationFeature } from '../api'
import { Choice, MODES, TRUSTS } from './Choice'

export function IdentitySection({ policy }: { policy: AdminFederationPolicy }) {
  const { t } = useTranslation()
  return (
    <Section title={t('admin.federation.identity')} description={t('admin.federation.identityHint')}>
      {!policy.configured ? (
        <Alert variant="warn" title={t('admin.federation.notConfiguredTitle')}>
          {t('admin.federation.notConfigured')}
        </Alert>
      ) : (
        <Card>
          <CardContent className="grid gap-5 p-5 sm:grid-cols-2">
            <Fact label={t('admin.federation.serverName')}><Mono>{policy.serverName}</Mono></Fact>
            <Fact label={t('admin.federation.sequence')}><Mono>{policy.identitySequence}</Mono></Fact>
            <div className="sm:col-span-2">
              <Fact label={t('admin.federation.fingerprint')}>
                <span className="flex flex-wrap items-center gap-2">
                  <Mono className="break-all">{policy.fingerprintDisplay}</Mono>
                  {policy.fingerprint ? (
                    <Button variant="ghost" size="sm" onClick={() => void copyText(policy.fingerprint!).then(() => toast.success(t('common.copied')))}>
                      <Copy />
                      {t('admin.federation.copyFingerprint')}
                    </Button>
                  ) : null}
                </span>
              </Fact>
            </div>
          </CardContent>
        </Card>
      )}
    </Section>
  )
}

function FeaturePolicyRow({
  feature,
  policy,
}: {
  feature: FederationFeature
  policy: AdminFederationPolicy
}) {
  const { t } = useTranslation()
  const update = useUpdateFederationPolicy()
  const current = policy.features.find((f) => f.feature === feature)
  const [mode, setMode] = useState<FederationMode>(current?.mode ?? 'disabled')
  const [trust, setTrust] = useState<FederationMinimumTrust>(current?.minimumTrust ?? 'verified')
  useEffect(() => {
    if (current) {
      setMode(current.mode)
      setTrust(current.minimumTrust)
    }
  }, [current])
  const changed = mode !== current?.mode || trust !== current?.minimumTrust

  return (
    <div className="flex flex-wrap items-end gap-3 p-4">
      <p className="w-24 font-medium">{t(`apps.${feature}`)}</p>
      <div className="space-y-1">
        <Label className="text-xs text-muted-foreground">{t('admin.federation.mode')}</Label>
        <Choice value={mode} options={MODES} labelPrefix="admin.federation.modes" onChange={setMode}
          ariaLabel={t('admin.federation.modeFor', { feature: t(`apps.${feature}`) })} className="w-44" />
      </div>
      <div className="space-y-1">
        <Label className="text-xs text-muted-foreground">{t('admin.federation.minimumTrust')}</Label>
        <Choice value={trust} options={TRUSTS} labelPrefix="admin.federation.trusts" onChange={setTrust}
          ariaLabel={t('admin.federation.trustFor', { feature: t(`apps.${feature}`) })} className="w-44" />
      </div>
      <Button
        disabled={!changed}
        loading={update.isPending}
        onClick={() =>
          update.mutate(
            { globalEnabled: policy.globalEnabled, feature, mode, minimumTrust: trust },
            { onSuccess: () => toast.success(t('admin.federation.saved')) },
          )
        }
      >
        {t('common.save')}
      </Button>
      {update.isError ? (
        <Alert variant="error" className="basis-full">{apiErrorMessage(update.error, t('admin.federation.saveFailed'))}</Alert>
      ) : null}
    </div>
  )
}

export function PolicySection({ policy }: { policy: AdminFederationPolicy }) {
  const { t } = useTranslation()
  const update = useUpdateFederationPolicy()
  // The global switch travels with a feature policy (the endpoint takes both);
  // chat's current policy is re-sent unchanged.
  const chat = policy.features.find((f) => f.feature === 'chat')

  return (
    <Section title={t('admin.federation.policy')} description={t('admin.federation.policyHint')}>
      <Card className="divide-y divide-border p-0">
        <div className="flex items-start gap-3 p-4">
          <Checkbox
            id="federation-global"
            checked={policy.globalEnabled}
            disabled={!policy.configured || update.isPending}
            onCheckedChange={(v) =>
              update.mutate({
                globalEnabled: v === true,
                feature: 'chat',
                mode: chat?.mode ?? 'disabled',
                minimumTrust: chat?.minimumTrust ?? 'verified',
              })
            }
          />
          <div className="space-y-1">
            <Label htmlFor="federation-global">{t('admin.federation.global')}</Label>
            <p className="text-sm text-muted-foreground">{t('admin.federation.globalHint')}</p>
            {update.isError ? <Alert variant="error">{apiErrorMessage(update.error, t('admin.federation.saveFailed'))}</Alert> : null}
          </div>
        </div>
        <FeaturePolicyRow feature="chat" policy={policy} />
        <FeaturePolicyRow feature="drive" policy={policy} />
      </Card>
    </Section>
  )
}
