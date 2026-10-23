import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { useMailAccount } from '@kutup/mail-core/api'
import {
  forwardingKindOf,
  useCreateForwarding,
  useForwardingConditions,
  type ForwardingCondition,
  type ForwardingKind,
  type MailForwarding,
} from '@kutup/mail-core/forwardings'
import { encryptionOff, type CheckedAddress } from '@kutup/mail-core/keyList'
import { Alert } from '@kutup/ui/components/alert'
import { Badge } from '@kutup/ui/components/badge'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { ConditionsEditor } from './ConditionsEditor'
import type { Conditions } from './conditions'
import { describeForwarding, forwardingErrorMessage } from './forwardingText'

/** A plain mailbox, as the server takes a forwardee (it checks the rest). */
const MAILBOX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

/**
 * Setting a forwarding up, as Proton's `ForwardModal`: forward from the
 * account's address, to an address, with the filter conditions (sender,
 * subject, attachments; none forwards everything). Next shows which kind it
 * is (end to end to a Kutup address here, outside for anything else) and
 * what that means before anything is made. With `forwarding`, only its
 * conditions change.
 */
export function ForwardingDialog({
  from,
  forwarding,
  onClose,
}: {
  /** The forwarder address: the account's current one. */
  from: CheckedAddress
  forwarding?: MailForwarding
  /** Closed; with the forwarding just made, whose code is now to be entered. */
  onClose: (made?: MailForwarding) => void
}) {
  const { t } = useTranslation()
  const account = useMailAccount()
  const create = useCreateForwarding()
  const change = useForwardingConditions()
  const [to, setTo] = useState(forwarding?.forwardeeEmail ?? '')
  const [conditions, setConditions] = useState<Conditions>({
    match: forwarding?.match ?? 'all',
    conditions: forwarding?.conditions ?? [],
  })
  const [step, setStep] = useState<'details' | 'confirm'>('details')
  const [kind, setKind] = useState<ForwardingKind | null>(null)
  const [checking, setChecking] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const pending = create.isPending || change.isPending
  const editing = forwarding !== undefined

  const problem = (): string | null => {
    if (!editing && !MAILBOX.test(to.trim())) return t('forwarding.toInvalid')
    if (conditions.conditions.some((c) => c.field !== 'attachments' && c.value.trim() === '')) return t('forwarding.conditionEmpty')
    return null
  }

  async function next() {
    const wrong = problem()
    if (wrong) return setError(wrong)
    setError(null)
    if (!account.data) return
    setChecking(true)
    try {
      setKind((await forwardingKindOf(account.data, to.trim())).kind)
      setStep('confirm')
    } catch (e) {
      setError(forwardingErrorMessage(e, t))
    } finally {
      setChecking(false)
    }
  }

  function save() {
    const wrong = problem()
    if (wrong) return setError(wrong)
    const body = { match: conditions.match, conditions: conditions.conditions as ForwardingCondition[] }
    if (forwarding) {
      change.mutate(
        { id: forwarding.id, ...body },
        {
          onSuccess: () => {
            toast.success(t('forwarding.saved'))
            onClose()
          },
          onError: (e) => setError(forwardingErrorMessage(e, t)),
        },
      )
      return
    }
    if (!kind) return
    create.mutate(
      { from, to: to.trim(), kind, ...body },
      {
        onSuccess: (made) => {
          toast.success(t('forwarding.code.sent', { to: made.forwardeeEmail }))
          onClose(made)
        },
        onError: (e) => {
          setError(forwardingErrorMessage(e, t))
          setStep('details')
        },
      },
    )
  }

  return (
    <Dialog open onOpenChange={(open) => !open && !pending && onClose()}>
      <DialogContent className="sm:max-w-2xl" data-testid="forwarding-dialog">
        <DialogHeader>
          <DialogTitle>{t(editing ? 'forwarding.editTitle' : 'forwarding.addTitle')}</DialogTitle>
          <DialogDescription>{t('forwarding.dialogHint')}</DialogDescription>
        </DialogHeader>
        {step === 'details' ? (
          <div className="space-y-4">
            <Field label={t('forwarding.from')}>
              {(props) => <Input {...props} value={forwarding?.forwarderAddress ?? from.address} readOnly />}
            </Field>
            <Field label={t('forwarding.to')}>
              {(props) => (
                <Input
                  {...props}
                  type="email"
                  autoFocus={!editing}
                  readOnly={editing}
                  value={to}
                  placeholder={t('forwarding.toPlaceholder')}
                  onChange={(e) => setTo(e.target.value)}
                  data-testid="forwarding-to"
                />
              )}
            </Field>
            <fieldset className="space-y-2">
              <legend className="text-sm font-medium">{t('forwarding.conditions')}</legend>
              <p className="text-xs text-muted-foreground">
                {conditions.conditions.length === 0 ? t('forwarding.everythingHint') : t('forwarding.conditionsHint')}
              </p>
              <ConditionsEditor value={conditions} onChange={setConditions} fields={['sender', 'subject', 'attachments']} allowNone />
            </fieldset>
            <p className="text-xs text-muted-foreground">{t('forwarding.noChains')}</p>
            {error ? <Alert variant="error">{error}</Alert> : null}
          </div>
        ) : (
          <div className="space-y-4" data-testid="forwarding-confirm">
            <p className="flex flex-wrap items-center gap-2 text-sm">
              {t('forwarding.summary', { from: from.address, to: to.trim() })}
              <Badge variant={kind === 'end_to_end' ? 'ok' : 'warn'}>{t(`forwarding.kind.${kind}`)}</Badge>
            </p>
            <p className="rounded-md border border-border bg-muted/40 p-3 text-sm">{describeForwarding(conditions, t)}</p>
            {kind === 'end_to_end' ? (
              // With post-quantum mail (POST_QUANTUM_MAIL), this is where the
              // address staying on classic encryption is said.
              <p className="text-sm">{t('forwarding.endToEndExplained', { to: to.trim() })}</p>
            ) : (
              <>
                {encryptionOff(from) ? null : (
                  <Alert variant="warn" data-testid="forwarding-outside-warning">
                    {t('forwarding.outsideWarning', { address: from.address })}
                  </Alert>
                )}
                <p className="text-sm">{t('forwarding.outsideExplained', { to: to.trim() })}</p>
              </>
            )}
            {/* The server, with the recipient, can read all of this address's mail (Proton's design, said plainly). */}
            <Alert variant="info" data-testid="forwarding-trust-hint">
              {t('forwarding.trustHint')}
            </Alert>
            {error ? <Alert variant="error">{error}</Alert> : null}
          </div>
        )}
        <DialogFooter>
          {step === 'confirm' ? (
            <Button variant="outline" onClick={() => setStep('details')} disabled={pending}>
              {t('common.back')}
            </Button>
          ) : (
            <Button variant="outline" onClick={() => onClose()} disabled={pending}>
              {t('common.cancel')}
            </Button>
          )}
          {editing ? (
            <Button onClick={save} loading={pending}>
              {t('common.save')}
            </Button>
          ) : step === 'details' ? (
            <Button onClick={() => void next()} loading={checking} disabled={!account.data} data-testid="forwarding-next">
              {t('forwarding.next')}
            </Button>
          ) : (
            <Button onClick={save} loading={pending} data-testid="forwarding-submit">
              {t('forwarding.submit')}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
