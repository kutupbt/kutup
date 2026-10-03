import { useTranslation } from 'react-i18next'
import { Alert } from '@kutup/ui/components/alert'
import { Card } from '@kutup/ui/components/card'
import { PageBody, PageHeader, Section } from '@kutup/ui/components/page'
import { LoadingPanel } from '@kutup/ui/components/states'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { useFederationPolicy } from './api'
import { PeersSection } from './federation/PeersSection'
import { IdentitySection, PolicySection } from './federation/PolicySection'
import { RulesSection } from './federation/RulesSection'

function Counter({ label, value }: { label: string; value: number }) {
  return (
    <div className="p-4">
      <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">{label}</p>
      <p className="mt-1 font-display text-xl font-semibold">{value}</p>
    </div>
  )
}

export function FederationPage() {
  const { t } = useTranslation()
  const policy = useFederationPolicy()

  return (
    <PageBody>
      <PageHeader title={t('admin.federation.title')} description={t('admin.federation.description')} />
      {policy.isPending ? <LoadingPanel label={t('common.loading')} /> : null}
      {policy.isError ? <Alert variant="error">{apiErrorMessage(policy.error, t('common.tryAgain'))}</Alert> : null}
      {policy.data ? (
        <>
          <IdentitySection policy={policy.data} />
          {policy.data.configured ? (
            <>
              <PolicySection policy={policy.data} />
              <Section title={t('admin.federation.operations')}>
                <Card className="grid grid-cols-2 divide-x divide-y divide-border p-0 sm:grid-cols-4 sm:divide-y-0">
                  <Counter label={t('admin.federation.ops.peers')} value={policy.data.operational.peerTotal} />
                  <Counter label={t('admin.federation.ops.quarantined')} value={policy.data.operational.quarantinedPeers} />
                  <Counter label={t('admin.federation.ops.chatPending')} value={policy.data.operational.chatPendingTransactions} />
                  <Counter label={t('admin.federation.ops.driveShares')} value={policy.data.operational.driveIncomingShares + policy.data.operational.driveOutgoingShares} />
                </Card>
              </Section>
              <RulesSection rules={policy.data.rules} />
              <PeersSection peers={policy.data.peers} />
            </>
          ) : null}
        </>
      ) : null}
    </PageBody>
  )
}
