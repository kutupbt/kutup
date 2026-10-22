import { AlertCircle, CheckCircle2, XCircle } from 'lucide-react'
import { useState, type ReactNode } from 'react'
import { Trans, useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { toast } from 'sonner'
import {
  DKIM_STATE,
  DMARC_STATE,
  DOMAIN_STATE,
  MX_STATE,
  SPF_STATE,
  VERIFY_STATE,
  useAddDomain,
  useDomains,
  useRefreshDomain,
  type MailDomain,
} from '@kutup/mail-core/domains'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { Tooltip } from '@kutup/ui/components/tooltip'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { cn } from '@kutup/ui/lib/cn'
import { CopyValue, DnsRecordTable } from './DnsRecordTable'

const STEPS = ['domain', 'verify', 'addresses', 'mx', 'spf', 'dkim', 'dmarc'] as const
type Step = (typeof STEPS)[number]

type Mark = 'good' | 'bad' | 'warn' | null

/** Each tab's mark (Proton's `getBreadcrumbs`): none until there is something to say. */
function marks(domain: MailDomain | null): Record<Step, Mark> {
  if (!domain) return { domain: null, verify: null, addresses: null, mx: null, spf: null, dkim: null, dmarc: null }
  const of = (state: number, good: number): Mark => (state === 0 ? null : state === good ? 'good' : 'bad')
  return {
    domain: domain.state === DOMAIN_STATE.default ? null : domain.state === DOMAIN_STATE.verified ? 'good' : 'bad',
    verify: of(domain.verifyState, VERIFY_STATE.good),
    addresses: domain.addressCount > 0 ? 'good' : null,
    mx: of(domain.mxState, MX_STATE.good),
    spf: of(domain.spfState, SPF_STATE.good),
    dkim:
      domain.dkimState === DKIM_STATE.good
        ? 'good'
        : domain.dkimState === DKIM_STATE.warning
          ? 'warn'
          : domain.dkimState === DKIM_STATE.default || domain.dkimState === DKIM_STATE.delegated
            ? null
            : 'bad',
    dmarc: of(domain.dmarcState, DMARC_STATE.good),
  }
}

/**
 * Proton's domain wizard (`DomainModal`): seven tabs in its order, Next on
 * each (Verify checks DNS now), Done on the last. Opened on an existing
 * domain it is "Edit domain", any verified step one click away.
 */
export function DomainWizard({ initial, onClose }: { initial?: MailDomain; onClose: () => void }) {
  const { t } = useTranslation()
  const domains = useDomains()
  const add = useAddDomain()
  const refresh = useRefreshDomain()
  const [step, setStep] = useState<Step>('domain')
  const [created, setCreated] = useState<MailDomain | null>(initial ?? null)
  const [name, setName] = useState('')
  const [error, setError] = useState<string | null>(null)
  // The list's copy once it has one: "Refresh status" updates the marks.
  const domain = (created && domains.data?.domains.find((d) => d.id === created.id)) ?? created
  const verified = domain?.verifyState === VERIFY_STATE.good
  const enabled = (s: Step) => s === 'domain' || (s === 'verify' ? domain !== null : verified)
  const tabMarks = marks(domain)
  const next = () => setStep(STEPS[STEPS.indexOf(step) + 1] ?? step)
  const busy = add.isPending || refresh.isPending

  function submit() {
    setError(null)
    if (step === 'domain') {
      if (domain) return next()
      const value = name.trim()
      if (!value) return setError(t('domains.wizard.nameRequired'))
      add.mutate(value, {
        onSuccess: (made) => {
          setCreated(made)
          next()
        },
        onError: (e) => setError(apiErrorMessage(e, t('common.tryAgain'))),
      })
      return
    }
    if (step === 'verify' && domain) {
      if (verified) return next()
      refresh.mutate(domain.id, {
        onSuccess: (checked) => {
          setCreated(checked)
          if (checked.verifyState === VERIFY_STATE.default) toast.error(t('domains.verify.notYet'))
          else if (checked.verifyState === VERIFY_STATE.exist) toast.error(t('domains.verify.wrongCode'))
          else {
            toast.success(t('domains.verify.verified'))
            next()
          }
        },
        onError: (e) => toast.error(apiErrorMessage(e, t('common.tryAgain'))),
      })
      return
    }
    if (step === 'dmarc') return onClose()
    next()
  }

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent className="max-w-3xl" data-testid="domain-wizard">
        <DialogHeader>
          <DialogTitle>{t(initial ? 'domains.wizard.editTitle' : 'domains.wizard.addTitle')}</DialogTitle>
        </DialogHeader>
        <div className="flex flex-wrap gap-1" role="tablist" aria-label={t('domains.wizard.steps')}>
          {STEPS.map((s) => (
            <Tooltip key={s} label={t(`domains.wizard.tabs.${s}`)}>
              <Button
                type="button"
                role="tab"
                size="sm"
                variant={step === s ? 'secondary' : 'ghost'}
                aria-selected={step === s}
                disabled={!enabled(s) || busy}
                onClick={() => setStep(s)}
                className={cn('gap-1.5', step === s && 'font-semibold')}
              >
                {enabled(s) ? <TabMark mark={tabMarks[s]} dkim={s === 'dkim'} /> : null}
                {t(`domains.wizard.tabs.${s}`)}
              </Button>
            </Tooltip>
          ))}
        </div>
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault()
            submit()
          }}
        >
          {!domain || step === 'domain' ? (
            <DomainStep domain={domain} name={name} setName={setName} error={error} />
          ) : step === 'verify' ? (
            <VerifyStep domain={domain} />
          ) : step === 'addresses' ? (
            <AddressesStep onClose={onClose} />
          ) : step === 'mx' ? (
            <MxStep domain={domain} />
          ) : step === 'spf' ? (
            <SpfStep domain={domain} />
          ) : step === 'dkim' ? (
            <DkimStep domain={domain} />
          ) : (
            <DmarcStep domain={domain} />
          )}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose} disabled={busy}>
              {t('common.close')}
            </Button>
            <Button type="submit" loading={busy} data-testid="domain-wizard-next">
              {step === 'dmarc' ? t('domains.wizard.done') : t('domains.wizard.next')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function TabMark({ mark, dkim }: { mark: Mark; dkim: boolean }) {
  const { t } = useTranslation()
  if (mark === 'good') {
    return <CheckCircle2 className="size-3.5 text-status-ok" aria-label={dkim ? t('domains.dkim.good') : t('domains.wizard.good')} />
  }
  if (mark === 'warn') return <AlertCircle className="size-3.5 text-status-warn" aria-label={t('domains.dkim.warning')} />
  if (mark === 'bad') return <XCircle className="size-3.5 text-destructive" aria-label={dkim ? t('domains.dkim.error') : t('domains.wizard.bad')} />
  return null
}

function Intro({ children }: { children: ReactNode }) {
  return <Alert>{children}</Alert>
}

/** "Please add the following …. Note: DNS records can take several hours to update." */
function Ask({ children }: { children: ReactNode }) {
  return <p className="text-sm font-medium">{children}</p>
}

function DomainStep({ domain, name, setName, error }: { domain: MailDomain | null; name: string; setName: (value: string) => void; error: string | null }) {
  const { t } = useTranslation()
  return (
    <div className="space-y-4">
      <Intro>{t('domains.domain.intro')}</Intro>
      <Field label={t('domains.domain.label')} error={error ?? undefined}>
        {(props) =>
          domain ? (
            <Input {...props} value={domain.name} readOnly className="max-w-sm" />
          ) : (
            <Input
              {...props}
              value={name}
              placeholder={t('domains.domain.placeholder')}
              autoFocus
              className="max-w-sm"
              data-testid="domain-name"
              onChange={(e) => setName(e.target.value)}
            />
          )
        }
      </Field>
      {!domain && /^www\./i.test(name.trim()) ? <Alert variant="warn">{t('domains.domain.www')}</Alert> : null}
    </div>
  )
}

function VerifyStep({ domain }: { domain: MailDomain }) {
  const { t } = useTranslation()
  return (
    <div className="space-y-4">
      <Intro>{t('domains.verify.intro', { domain: domain.name })}</Intro>
      <Alert variant="warn">{t('domains.verify.keep')}</Alert>
      <Ask>{t('domains.records.askTxt')}</Ask>
      <DnsRecordTable records={[domain.records.verify]} copied={t('domains.verify.copied')} />
    </div>
  )
}

function AddressesStep({ onClose }: { onClose: () => void }) {
  const { t } = useTranslation()
  return (
    <div className="space-y-4">
      <Intro>{t('domains.addresses.intro')}</Intro>
      <Button asChild>
        <Link to="/settings/identity" onClick={onClose}>
          {t('domains.addresses.add')}
        </Link>
      </Button>
    </div>
  )
}

function MxStep({ domain }: { domain: MailDomain }) {
  const { t } = useTranslation()
  return (
    <div className="space-y-4">
      <Intro>{t('domains.mx.intro', { count: domain.records.mx.length })}</Intro>
      <Ask>{t('domains.mx.ask', { count: domain.records.mx.length })}</Ask>
      <DnsRecordTable records={domain.records.mx} copied={t('domains.records.copied')} />
      <Alert>
        <p>{t('domains.mx.others')}</p>
        <p>
          <Trans i18nKey="domains.mx.switching" components={{ strong: <strong /> }} />
        </p>
      </Alert>
    </div>
  )
}

/** The include a merged SPF record needs: the part of ours past `v=spf1`. */
function spfInclude(value: string): string {
  return value.split(' ').find((part) => part.startsWith('include:')) ?? value
}

function SpfStep({ domain }: { domain: MailDomain }) {
  const { t } = useTranslation()
  const include = spfInclude(domain.records.spf.value)
  return (
    <div className="space-y-4">
      <Intro>
        <p>{t('domains.missingSetup')}</p>
        <p>{t('domains.spf.intro')}</p>
      </Intro>
      <Ask>{t('domains.records.askTxt')}</Ask>
      <DnsRecordTable records={[domain.records.spf]} copied={t('domains.spf.copied')} />
      <Alert>
        <p>
          <Trans i18nKey="domains.spf.merge" values={{ include, start: 'v=spf1' }} components={{ strong: <strong /> }} />
        </p>
        <p>
          {t('domains.spf.example')} <code className="font-mono text-xs">{`v=spf1 ${include} include:spf.example.com ~all`}</code>
        </p>
      </Alert>
    </div>
  )
}

function DkimStep({ domain }: { domain: MailDomain }) {
  const { t } = useTranslation()
  return (
    <div className="space-y-4">
      <Intro>
        <p>{t('domains.missingSetup')}</p>
        <p>{t('domains.dkim.intro', { count: domain.records.dkim.length })}</p>
      </Intro>
      {domain.dkimState === DKIM_STATE.error ? <Alert variant="error">{t('domains.dkim.error')}</Alert> : null}
      {domain.dkimState === DKIM_STATE.warning ? <Alert variant="warn">{t('domains.dkim.warning')}</Alert> : null}
      <Ask>{t('domains.dkim.ask', { count: domain.records.dkim.length })}</Ask>
      <DnsRecordTable records={domain.records.dkim} copied={t('domains.records.copied')} copyHost />
      <Alert variant="warn">{t('domains.dkim.dot')}</Alert>
    </div>
  )
}

function DmarcStep({ domain }: { domain: MailDomain }) {
  const { t } = useTranslation()
  const [value, setValue] = useState(domain.records.dmarc.value)
  return (
    <div className="space-y-4">
      <Intro>
        <p>{t('domains.missingSetup')}</p>
        <p>{t('domains.dmarc.intro')}</p>
      </Intro>
      <Ask>{t('domains.records.askTxt')}</Ask>
      <DnsRecordTable
        records={[domain.records.dmarc]}
        copied={t('domains.dmarc.copied')}
        value={
          <CopyValue value={value} copied={t('domains.dmarc.copied')}>
            <Input
              value={value}
              placeholder={domain.records.dmarc.value}
              aria-label={t('domains.records.value')}
              className="h-8 font-mono text-xs"
              onChange={(e) => setValue(e.target.value)}
            />
          </CopyValue>
        }
      />
      <Alert>
        {(['quarantine', 'reject', 'none'] as const).map((policy) => (
          <p key={policy}>
            <Trans i18nKey={`domains.dmarc.${policy}`} values={{ policy: `p=${policy}` }} components={{ strong: <strong /> }} />
          </p>
        ))}
      </Alert>
    </div>
  )
}
