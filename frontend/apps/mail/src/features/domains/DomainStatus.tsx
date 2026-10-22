import { CheckCircle2, XCircle } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { DKIM_STATE, DMARC_STATE, DOMAIN_STATE, MX_STATE, SPF_STATE, VERIFY_STATE, type MailDomain } from '@kutup/mail-core/domains'
import { Badge } from '@kutup/ui/components/badge'

type Tone = 'neutral' | 'danger' | 'warn' | 'ok'

/** The domain's name with Proton's state icon: verified, warned, or not (yet). */
export function DomainName({ domain }: { domain: MailDomain }) {
  const { t } = useTranslation()
  const icon =
    domain.state === DOMAIN_STATE.verified ? (
      <CheckCircle2 className="size-4 shrink-0 text-status-ok" aria-label={t('domains.state.verified')} />
    ) : domain.state === DOMAIN_STATE.warn ? (
      <XCircle className="size-4 shrink-0 text-status-warn" aria-label={t('domains.state.warn')} />
    ) : (
      <XCircle className="size-4 shrink-0 text-destructive" aria-label={t('domains.state.default')} />
    )
  return (
    <span className="flex min-w-0 items-center gap-2">
      {icon}
      <span className="truncate font-medium" title={domain.name}>
        {domain.name}
      </span>
    </span>
  )
}

const VERIFY: Record<number, Tone> = { [VERIFY_STATE.default]: 'neutral', [VERIFY_STATE.exist]: 'danger', [VERIFY_STATE.good]: 'ok' }
const MX: Record<number, Tone> = {
  [MX_STATE.default]: 'neutral',
  [MX_STATE.noUs]: 'danger',
  [MX_STATE.incUs]: 'danger',
  [MX_STATE.good]: 'ok',
  [MX_STATE.backup]: 'warn',
}
const SPF: Record<number, Tone> = { [SPF_STATE.default]: 'neutral', [SPF_STATE.one]: 'danger', [SPF_STATE.mult]: 'danger', [SPF_STATE.good]: 'ok' }
const DKIM: Record<number, Tone> = {
  [DKIM_STATE.default]: 'neutral',
  [DKIM_STATE.error]: 'danger',
  [DKIM_STATE.good]: 'ok',
  [DKIM_STATE.warning]: 'warn',
  [DKIM_STATE.delegated]: 'neutral',
}
const DMARC: Record<number, Tone> = {
  [DMARC_STATE.default]: 'neutral',
  [DMARC_STATE.one]: 'danger',
  [DMARC_STATE.mult]: 'danger',
  [DMARC_STATE.good]: 'ok',
  [DMARC_STATE.relaxed]: 'neutral',
}

/**
 * Proton's seven status badges, in its order: the labels stay, the colour
 * says the state (unknown states, such as DKIM's "found, wrong", read as
 * wrong).
 */
export function DomainStatus({ domain }: { domain: MailDomain }) {
  const { t } = useTranslation()
  const badges: [string, Tone][] = [
    [t('domains.badges.verified'), VERIFY[domain.verifyState] ?? 'danger'],
    [
      t('domains.badges.addresses', { count: domain.addressCount }),
      domain.state === DOMAIN_STATE.verified && domain.addressCount > 0 ? 'ok' : 'danger',
    ],
    ['MX', MX[domain.mxState] ?? 'danger'],
    ['SPF', SPF[domain.spfState] ?? 'danger'],
    ['DKIM', DKIM[domain.dkimState] ?? 'danger'],
    ['DMARC', DMARC[domain.dmarcState] ?? 'danger'],
    [t('domains.badges.catchAll'), domain.catchAllAddressId ? 'ok' : 'neutral'],
  ]
  return (
    <span className="flex flex-wrap gap-1" data-testid="domain-status">
      {badges.map(([label, tone]) => (
        <Badge key={label} variant={tone} data-tone={tone}>
          {label}
        </Badge>
      ))}
      {domain.awaitingApproval ? <Badge variant="warn">{t('domains.badges.awaitingApproval')}</Badge> : null}
    </span>
  )
}
