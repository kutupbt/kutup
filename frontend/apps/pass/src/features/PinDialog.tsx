import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { PasswordInput } from '@kutup/ui/components/password-input'
import { isPin, PIN_LENGTH, removePin, setPin, useRefreshPinStatus, type PinChangeResult } from '../sync/pin'

export type PinAction = 'set' | 'change' | 'remove'

function PinField({ label, value, onChange }: { label: string; value: string; onChange: (value: string) => void }) {
  return (
    <Field label={label}>
      {(field) => (
        <PasswordInput
          {...field}
          value={value}
          inputMode="numeric"
          autoComplete="off"
          maxLength={PIN_LENGTH}
          className="font-mono tracking-[0.3em]"
          onChange={(e) => onChange(e.target.value.replace(/\D/g, '').slice(0, PIN_LENGTH))}
        />
      )}
    </Field>
  )
}

/** Sets, changes or removes the account's PIN, with the account password. */
export function PinDialog({
  action,
  onOpenChange,
  onDone,
}: {
  /** null: closed. */
  action: PinAction | null
  onOpenChange: (open: boolean) => void
  onDone: (action: PinAction) => void
}) {
  const { t } = useTranslation()
  const refresh = useRefreshPinStatus()
  const [password, setPassword] = useState('')
  const [pin, setPinValue] = useState('')
  const [again, setAgain] = useState('')
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!action) return
    setPassword('')
    setPinValue('')
    setAgain('')
    setError(null)
  }, [action])

  const removing = action === 'remove'
  const mismatch = !removing && isPin(pin) && isPin(again) && pin !== again
  const ready = Boolean(password) && (removing || (isPin(pin) && pin === again))

  const submit = async () => {
    if (!action || !ready) return
    setPending(true)
    setError(null)
    try {
      const result: PinChangeResult = removing ? await removePin(password) : await setPin(password, pin)
      if (result === 'wrongPassword') {
        setError(t('unlock.wrongAccountPassword'))
        return
      }
      if (result === 'paused' || result === 'slowDown') {
        setError(t(result === 'slowDown' ? 'unlock.slowDown' : 'unlock.paused'))
        return
      }
      await refresh()
      toast.success(t(`pin.done.${action}`))
      onOpenChange(false)
      onDone(action)
    } catch {
      setError(t('unlock.checkUnreachable'))
    } finally {
      setPassword('')
      setPending(false)
    }
  }

  return (
    <Dialog open={action !== null} onOpenChange={(next) => !pending && onOpenChange(next)}>
      <DialogContent className="sm:max-w-md">
        <form
          onSubmit={(e) => {
            e.preventDefault()
            void submit()
          }}
        >
          <DialogHeader>
            <DialogTitle>{action ? t(`pin.title.${action}`) : null}</DialogTitle>
            <DialogDescription>{removing ? t('pin.removeDescription') : t('pin.description')}</DialogDescription>
          </DialogHeader>
          <div className="mt-4 space-y-4">
            <Field label={t('unlock.accountPassword')} description={t('pin.passwordDescription')}>
              {(field) => <PasswordInput {...field} value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" autoFocus />}
            </Field>
            {removing ? null : (
              <>
                <PinField label={t('pin.new')} value={pin} onChange={setPinValue} />
                <PinField label={t('pin.again')} value={again} onChange={setAgain} />
              </>
            )}
            {mismatch ? <Alert variant="error">{t('pin.mismatch')}</Alert> : null}
            {error ? <Alert variant="error">{error}</Alert> : null}
          </div>
          <DialogFooter className="mt-6">
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)} disabled={pending}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" variant={removing ? 'destructive' : 'default'} loading={pending} disabled={!ready}>
              {action ? t(`pin.submit.${action}`) : null}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
