import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@kutup/ui/components/select'
import { otpFormOf, otpUriOf, type OtpAlgorithm, type OtpDigits, type OtpForm } from '../lib/otp'

const DIGITS: OtpDigits[] = [6, 7, 8, 'steam']
const ALGORITHMS: OtpAlgorithm[] = ['SHA1', 'SHA256', 'SHA512']

/**
 * One-time code setup (docs/plans/pass-gaps-3.md, A2), KeePassXC's: the
 * secret, digits (or Steam Guard), period and algorithm, written as the
 * `otp` field's otpauth:// URI.
 */
export function TotpSetupDialog({
  open,
  onOpenChange,
  value,
  title,
  userName,
  onSave,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** The field as it is (a URI, a bare secret, or empty). */
  value: string
  title: string
  userName: string
  onSave: (uri: string) => void
}) {
  const { t } = useTranslation()
  const [form, setForm] = useState<OtpForm>(() => otpFormOf(value))
  const [error, setError] = useState<string | null>(null)
  useEffect(() => {
    if (open) {
      setForm(otpFormOf(value))
      setError(null)
    }
  }, [open, value])
  const steam = form.digits === 'steam'
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t('totp.title')}</DialogTitle>
          <DialogDescription>{t('totp.description')}</DialogDescription>
        </DialogHeader>
        <form
          className="mt-4 space-y-4"
          onSubmit={(event) => {
            event.preventDefault()
            const uri = otpUriOf(form, title, userName)
            if (!uri) {
              setError(t('totp.badSecret'))
              return
            }
            onSave(uri)
            onOpenChange(false)
          }}
        >
          <Field label={t('totp.secret')} description={t('totp.secretHint')} required>
            {(field) => <Input {...field} value={form.secret} onChange={(e) => setForm({ ...form, secret: e.target.value })} autoComplete="off" spellCheck={false} className="font-mono" required autoFocus />}
          </Field>
          <div className="grid gap-3 sm:grid-cols-3">
            <Field label={t('totp.digits')}>
              {(field) => (
                <Select value={String(form.digits)} onValueChange={(v) => setForm({ ...form, digits: v === 'steam' ? 'steam' : (Number(v) as 6 | 7 | 8) })}>
                  <SelectTrigger id={field.id}>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {DIGITS.map((d) => (
                      <SelectItem key={String(d)} value={String(d)}>
                        {d === 'steam' ? t('totp.steam') : String(d)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}
            </Field>
            <Field label={t('totp.period')}>
              {(field) => <Input {...field} type="number" min={15} max={300} step={1} inputMode="numeric" disabled={steam} value={steam ? 30 : form.period} onChange={(e) => setForm({ ...form, period: Number(e.target.value) || 30 })} />}
            </Field>
            <Field label={t('totp.algorithm')}>
              {(field) => (
                <Select value={steam ? 'SHA1' : form.algorithm} disabled={steam} onValueChange={(v) => setForm({ ...form, algorithm: v as OtpAlgorithm })}>
                  <SelectTrigger id={field.id}>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {ALGORITHMS.map((a) => (
                      <SelectItem key={a} value={a}>
                        {a.replace('SHA', 'SHA-')}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}
            </Field>
          </div>
          {error ? <Alert variant="error">{error}</Alert> : null}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              {t('common.cancel')}
            </Button>
            <Button type="submit">{t('common.save')}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
