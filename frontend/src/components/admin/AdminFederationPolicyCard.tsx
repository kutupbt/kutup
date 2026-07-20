import { useEffect, useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Icon, ICONS } from '@/components/mobile/Icon'
import {
  useAdminFederationPolicy,
  useDeleteAdminFederationRule,
  useUpdateAdminFederationPolicy,
  useUpsertAdminFederationRule,
} from '@/api/hooks/useAdmin'
import type {
  FederationDomainRule,
  FederationMode,
  FederationRuleAction,
} from '@/types/api'
import { cn } from '@/lib/utils'

const MODES: FederationMode[] = ['disabled', 'allowlist', 'blocklist', 'open']
const ACTIONS: FederationRuleAction[] = ['inherit', 'allow', 'block']

const MODE_COPY: Record<FederationMode, string> = {
  disabled: 'Deny all inbound and outbound chat federation.',
  allowlist: 'Deny by default; only explicitly allowed directions can federate.',
  blocklist: 'Allow by default; explicitly blocked directions are denied.',
  open: 'Allow every authenticated server and ignore saved domain rules.',
}

function titleCase(value: string) {
  return value.charAt(0).toUpperCase() + value.slice(1)
}

function inheritedLabel(mode: FederationMode) {
  if (mode === 'allowlist') return 'Inherit (block)'
  if (mode === 'blocklist') return 'Inherit (allow)'
  return 'Inherit (inactive)'
}

interface Props {
  className?: string
  compact?: boolean
}

/** Shared desktop/mobile administrator surface for chat federation admission. */
export function AdminFederationPolicyCard({ className, compact = false }: Props) {
  const { t } = useTranslation()
  const { data: policy, isLoading } = useAdminFederationPolicy()
  const updatePolicy = useUpdateAdminFederationPolicy()
  const upsertRule = useUpsertAdminFederationRule()
  const [domain, setDomain] = useState('')
  const [inbound, setInbound] = useState<FederationRuleAction>('inherit')
  const [outbound, setOutbound] = useState<FederationRuleAction>('inherit')

  function submitRule(event: FormEvent) {
    event.preventDefault()
    const canonical = domain.trim()
    if (!canonical) return
    upsertRule.mutate(
      { domain: canonical, inbound, outbound },
      { onSuccess: () => setDomain('') },
    )
  }

  const mode = policy?.mode ?? 'open'

  return (
    <section
      className={cn(
        'bg-surface border border-border-light rounded-[var(--radius-lg)] overflow-hidden',
        className,
      )}
    >
      <div className={cn('border-b border-border-light', compact ? 'px-3.5 py-3' : 'px-[18px] py-3.5')}>
        <div className="flex items-start gap-2.5">
          <span className="mt-0.5 text-primary">
            <Icon d={ICONS.globe} size={16} />
          </span>
          <div className="min-w-0">
            <div className="text-[14px] font-semibold text-text-primary">
              {t('admin.federation.title', 'Chat federation')}
            </div>
            <div className="text-[12.5px] text-text-tertiary mt-0.5">
              {t(
                'admin.federation.description',
                'Control which Kutup homeservers may exchange encrypted chat traffic with this instance.',
              )}
            </div>
          </div>
        </div>
      </div>

      {isLoading || !policy ? (
        <div className="px-[18px] py-5 text-[13px] text-text-tertiary">
          {t('admin.federation.loading', 'Loading federation policy…')}
        </div>
      ) : (
        <>
          <div className={cn('border-b border-border-light', compact ? 'px-3.5 py-3' : 'px-[18px] py-4')}>
            {!policy.configured && (
              <div className="mb-3 flex gap-2 rounded-[var(--radius)] border border-warning/40 bg-warning/10 px-3 py-2 text-[12px] text-text-secondary">
                <Icon d={ICONS.alertTriangle} size={15} color="var(--warning)" />
                <span>
                  {t(
                    'admin.federation.notConfigured',
                    'No persistent federation signing key is configured. The saved policy will take effect when federation is enabled.',
                  )}
                </span>
              </div>
            )}
            <div className={cn('flex gap-3', compact ? 'flex-col' : 'items-start justify-between')}>
              <div className="min-w-0">
                <label htmlFor="federation-mode" className="text-[13.5px] font-medium text-text-primary">
                  {t('admin.federation.mode', 'Admission mode')}
                </label>
                <p className="mt-0.5 text-[12px] text-text-tertiary">{MODE_COPY[mode]}</p>
                {policy.serverName && (
                  <p className="mt-1 text-[11.5px] text-text-tertiary">
                    {t('admin.federation.identity', 'Local identity')}: <code>{policy.serverName}</code>
                  </p>
                )}
              </div>
              <select
                id="federation-mode"
                aria-label={t('admin.federation.mode', 'Admission mode')}
                value={mode}
                disabled={updatePolicy.isPending}
                onChange={(event) => updatePolicy.mutate(event.target.value as FederationMode)}
                className="h-9 min-w-[145px] rounded-md border border-input bg-background px-2.5 text-[13px] text-text-primary"
              >
                {MODES.map((value) => (
                  <option key={value} value={value}>
                    {titleCase(value)}{value === 'allowlist' ? ' · recommended' : ''}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <form onSubmit={submitRule} className={cn('border-b border-border-light', compact ? 'px-3.5 py-3' : 'px-[18px] py-4')}>
            <div className="text-[13.5px] font-medium text-text-primary">
              {t('admin.federation.addServer', 'Add or replace a server rule')}
            </div>
            <p className="mt-0.5 mb-3 text-[12px] text-text-tertiary">
              {mode === 'open' || mode === 'disabled'
                ? t(
                    'admin.federation.rulesInactive',
                    'Rules are saved but inactive in the current mode.',
                  )
                : t(
                    'admin.federation.rulesDirectional',
                    'Inbound and outbound decisions are evaluated independently.',
                  )}
            </p>
            <div className={cn('grid gap-2', compact ? 'grid-cols-1' : 'grid-cols-[minmax(180px,1fr)_140px_140px_auto]')}>
              <Input
                value={domain}
                onChange={(event) => setDomain(event.target.value)}
                placeholder="chat.example.com"
                aria-label={t('admin.federation.serverDomain', 'Server domain')}
                autoCapitalize="none"
                autoCorrect="off"
                spellCheck={false}
              />
              <RuleSelect
                label={t('admin.federation.inbound', 'Inbound')}
                value={inbound}
                mode={mode}
                onChange={setInbound}
              />
              <RuleSelect
                label={t('admin.federation.outbound', 'Outbound')}
                value={outbound}
                mode={mode}
                onChange={setOutbound}
              />
              <Button type="submit" size="sm" disabled={!domain.trim() || upsertRule.isPending}>
                {t('common.save', 'Save')}
              </Button>
            </div>
          </form>

          <div>
            {policy.rules.length === 0 ? (
              <div className="px-[18px] py-4 text-[12.5px] text-text-tertiary">
                {t('admin.federation.noRules', 'No server rules configured.')}
              </div>
            ) : (
              policy.rules.map((rule, index) => (
                <FederationRuleRow
                  key={rule.domain}
                  rule={rule}
                  mode={mode}
                  compact={compact}
                  last={index === policy.rules.length - 1}
                />
              ))
            )}
          </div>
        </>
      )}
    </section>
  )
}

function RuleSelect({
  label,
  value,
  mode,
  onChange,
  disabled,
}: {
  label: string
  value: FederationRuleAction
  mode: FederationMode
  onChange: (value: FederationRuleAction) => void
  disabled?: boolean
}) {
  return (
    <label className="min-w-0">
      <span className="sr-only">{label}</span>
      <select
        aria-label={label}
        value={value}
        disabled={disabled}
        onChange={(event) => onChange(event.target.value as FederationRuleAction)}
        className="h-9 w-full rounded-md border border-input bg-background px-2 text-[12.5px] text-text-primary"
      >
        {ACTIONS.map((action) => (
          <option key={action} value={action}>
            {action === 'inherit' ? inheritedLabel(mode) : `${label}: ${titleCase(action)}`}
          </option>
        ))}
      </select>
    </label>
  )
}

function FederationRuleRow({
  rule,
  mode,
  compact,
  last,
}: {
  rule: FederationDomainRule
  mode: FederationMode
  compact: boolean
  last: boolean
}) {
  const { t } = useTranslation()
  const upsert = useUpsertAdminFederationRule()
  const remove = useDeleteAdminFederationRule()
  const [inbound, setInbound] = useState(rule.inbound)
  const [outbound, setOutbound] = useState(rule.outbound)

  useEffect(() => {
    setInbound(rule.inbound)
    setOutbound(rule.outbound)
  }, [rule.inbound, rule.outbound])

  const changed = inbound !== rule.inbound || outbound !== rule.outbound

  return (
    <div
      className={cn(
        'gap-2 px-[18px] py-3',
        compact ? 'grid grid-cols-1' : 'grid grid-cols-[minmax(180px,1fr)_140px_140px_auto] items-center',
        !last && 'border-b border-border-light',
      )}
    >
      <code className="truncate text-[12.5px] font-medium text-text-primary" title={rule.domain}>
        {rule.domain}
      </code>
      <RuleSelect label={t('admin.federation.inbound', 'Inbound')} value={inbound} mode={mode} onChange={setInbound} disabled={upsert.isPending} />
      <RuleSelect label={t('admin.federation.outbound', 'Outbound')} value={outbound} mode={mode} onChange={setOutbound} disabled={upsert.isPending} />
      <div className="flex justify-end gap-1.5">
        {changed && (
          <Button
            size="sm"
            onClick={() => upsert.mutate({ domain: rule.domain, inbound, outbound })}
            disabled={upsert.isPending}
          >
            {t('common.save', 'Save')}
          </Button>
        )}
        <Button
          size="sm"
          variant="outline"
          aria-label={t('admin.federation.removeRule', 'Remove rule for {{domain}}', { domain: rule.domain })}
          onClick={() => remove.mutate(rule.domain)}
          disabled={remove.isPending}
        >
          {t('common.remove', 'Remove')}
        </Button>
      </div>
    </div>
  )
}
