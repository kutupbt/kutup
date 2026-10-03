import { Trash2 } from 'lucide-react'
import { useEffect, useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import type { FederationDomainRule, FederationRuleAction, FederationTrustRequirement } from '@kutup/session/api-types'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Card } from '@kutup/ui/components/card'
import { Input } from '@kutup/ui/components/input'
import { Mono } from '@kutup/ui/components/mono'
import { Section } from '@kutup/ui/components/page'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@kutup/ui/components/table'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { useDeleteFederationRule, useUpsertFederationRule, type FederationFeature, type RuleInput } from '../api'
import { Choice, FEATURES, RULE_ACTIONS, RULE_TRUSTS } from './Choice'

function RuleRow({ rule }: { rule: FederationDomainRule }) {
  const { t } = useTranslation()
  const upsert = useUpsertFederationRule()
  const remove = useDeleteFederationRule()
  const [inbound, setInbound] = useState<FederationRuleAction>(rule.inbound)
  const [outbound, setOutbound] = useState<FederationRuleAction>(rule.outbound)
  const [trust, setTrust] = useState<FederationTrustRequirement>(rule.trustRequirement)
  useEffect(() => {
    setInbound(rule.inbound)
    setOutbound(rule.outbound)
    setTrust(rule.trustRequirement)
  }, [rule.inbound, rule.outbound, rule.trustRequirement])
  const changed = inbound !== rule.inbound || outbound !== rule.outbound || trust !== rule.trustRequirement
  const error = upsert.error ?? remove.error

  return (
    <TableRow>
      <TableCell>{t(`apps.${rule.feature}`)}</TableCell>
      <TableCell><Mono>{rule.domain}</Mono></TableCell>
      <TableCell><Choice value={inbound} options={RULE_ACTIONS} labelPrefix="admin.federation.ruleActions" onChange={setInbound} ariaLabel={t('admin.federation.inbound')} className="w-32" /></TableCell>
      <TableCell><Choice value={outbound} options={RULE_ACTIONS} labelPrefix="admin.federation.ruleActions" onChange={setOutbound} ariaLabel={t('admin.federation.outbound')} className="w-32" /></TableCell>
      <TableCell><Choice value={trust} options={RULE_TRUSTS} labelPrefix="admin.federation.ruleTrusts" onChange={setTrust} ariaLabel={t('admin.federation.trust')} className="w-36" /></TableCell>
      <TableCell className="whitespace-nowrap text-right">
        {changed ? (
          <Button size="sm" loading={upsert.isPending}
            onClick={() => upsert.mutate({ feature: rule.feature, domain: rule.domain, inbound, outbound, trustRequirement: trust },
              { onSuccess: () => toast.success(t('admin.federation.ruleSaved')) })}>
            {t('common.save')}
          </Button>
        ) : null}
        <Button size="icon" variant="ghost" aria-label={t('admin.federation.removeRule', { domain: rule.domain })} loading={remove.isPending}
          onClick={() => remove.mutate({ feature: rule.feature, domain: rule.domain }, { onSuccess: () => toast.success(t('admin.federation.ruleRemoved')) })}>
          <Trash2 />
        </Button>
        {error ? <p className="mt-1 text-xs text-destructive">{apiErrorMessage(error, t('admin.federation.saveFailed'))}</p> : null}
      </TableCell>
    </TableRow>
  )
}

function AddRule() {
  const { t } = useTranslation()
  const upsert = useUpsertFederationRule()
  const [draft, setDraft] = useState<RuleInput>({ feature: 'chat', domain: '', inbound: 'allow', outbound: 'allow', trustRequirement: 'inherit' })
  const set = <K extends keyof RuleInput>(key: K, value: RuleInput[K]) => setDraft((d) => ({ ...d, [key]: value }))

  function submit(event: FormEvent) {
    event.preventDefault()
    const domain = draft.domain.trim().toLowerCase()
    if (!domain) return
    upsert.mutate({ ...draft, domain }, {
      onSuccess: () => {
        toast.success(t('admin.federation.ruleSaved'))
        setDraft((d) => ({ ...d, domain: '' }))
      },
    })
  }

  return (
    <form onSubmit={submit} className="flex flex-wrap items-end gap-2 border-t border-border p-3">
      <Choice<FederationFeature> value={draft.feature} options={FEATURES} labelPrefix="apps" onChange={(v) => set('feature', v)} ariaLabel={t('admin.federation.feature')} className="w-28" />
      <Input value={draft.domain} onChange={(e) => set('domain', e.target.value)} placeholder={t('admin.federation.domainPlaceholder')}
        aria-label={t('admin.federation.domain')} className="w-56 font-mono" autoCapitalize="off" spellCheck={false} />
      <Choice value={draft.inbound} options={RULE_ACTIONS} labelPrefix="admin.federation.ruleActions" onChange={(v) => set('inbound', v)} ariaLabel={t('admin.federation.inbound')} className="w-32" />
      <Choice value={draft.outbound} options={RULE_ACTIONS} labelPrefix="admin.federation.ruleActions" onChange={(v) => set('outbound', v)} ariaLabel={t('admin.federation.outbound')} className="w-32" />
      <Choice value={draft.trustRequirement} options={RULE_TRUSTS} labelPrefix="admin.federation.ruleTrusts" onChange={(v) => set('trustRequirement', v)} ariaLabel={t('admin.federation.trust')} className="w-36" />
      <Button type="submit" loading={upsert.isPending} disabled={!draft.domain.trim()}>{t('admin.federation.addRule')}</Button>
      {upsert.isError ? <Alert variant="error" className="basis-full">{apiErrorMessage(upsert.error, t('admin.federation.saveFailed'))}</Alert> : null}
    </form>
  )
}

export function RulesSection({ rules }: { rules: FederationDomainRule[] }) {
  const { t } = useTranslation()
  return (
    <Section title={t('admin.federation.rules')} description={t('admin.federation.rulesHint')}>
      <Card className="p-0">
        {rules.length > 0 ? (
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('admin.federation.feature')}</TableHead>
                  <TableHead>{t('admin.federation.domain')}</TableHead>
                  <TableHead>{t('admin.federation.inbound')}</TableHead>
                  <TableHead>{t('admin.federation.outbound')}</TableHead>
                  <TableHead>{t('admin.federation.trust')}</TableHead>
                  <TableHead><span className="sr-only">{t('admin.federation.actions')}</span></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rules.map((r) => <RuleRow key={`${r.feature}:${r.domain}`} rule={r} />)}
              </TableBody>
            </Table>
          </div>
        ) : (
          <p className="p-4 text-sm text-muted-foreground">{t('admin.federation.noRules')}</p>
        )}
        <AddRule />
      </Card>
    </Section>
  )
}
