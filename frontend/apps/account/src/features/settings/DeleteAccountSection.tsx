import { useMutation } from '@tanstack/react-query'
import { isAxiosError } from 'axios'
import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import api, { endSession } from '@kutup/session/client'
import { accountGrant, OneUseSecret, ReauthLockedError, WrongPasswordError } from '@kutup/session/reauth'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Card, CardContent } from '@kutup/ui/components/card'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { Section } from '@kutup/ui/components/page'
import { PasswordInput } from '@kutup/ui/components/password-input'
import { formatInstant } from '@kutup/ui/lib/format'

/**
 * Asks for the account to be deleted (docs/plans/server-personal-data.md,
 * A5): after the password, it is closing; every sign-in ends, and it is
 * deleted with everything in it once the waiting period is over. Signing in
 * before then offers to keep it.
 */
async function closeAccount(password: OneUseSecret): Promise<string> {
  const grant = await accountGrant(password.take(), 'close')
  const { data } = await api.post<{ closesAt: string }>('/user/close', { grant })
  return data.closesAt
}

function bodyCode(error: unknown): string | undefined {
  return isAxiosError(error) ? (error.response?.data as { code?: string } | undefined)?.code : undefined
}

export function DeleteAccountSection() {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)

  return (
    <Section title={t('settings.account.delete.title')} description={t('settings.account.delete.description')}>
      <Card>
        <CardContent className="flex flex-wrap items-center gap-3 p-5">
          <p className="min-w-0 flex-1 text-sm text-muted-foreground">{t('settings.account.delete.keepHint')}</p>
          <Button variant="destructive" onClick={() => setOpen(true)}>
            {t('settings.account.delete.action')}
          </Button>
        </CardContent>
      </Card>
      {open ? <DeleteAccountDialog onClose={() => setOpen(false)} /> : null}
    </Section>
  )
}

function DeleteAccountDialog({ onClose }: { onClose: () => void }) {
  const { t, i18n } = useTranslation()
  const [password, setPassword] = useState('')
  const [understood, setUnderstood] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const close = useMutation({ mutationFn: closeAccount })

  const submit = (event: FormEvent) => {
    event.preventDefault()
    if (password === '' || !understood || close.isPending) return
    setError(null)
    const secret = new OneUseSecret(password)
    setPassword('')
    close.mutate(secret, {
      onSuccess: (closesAt) => {
        toast.success(t('settings.account.delete.done', { date: formatInstant(closesAt, i18n.language) ?? '' }))
        // Every sign-in of the account ended with it, this one too.
        endSession()
      },
      onError: (err) => {
        if (err instanceof WrongPasswordError) setError(t('settings.security.wrongCurrentPassword'))
        else if (err instanceof ReauthLockedError) setError(t(err.reason === 'rateLimited' ? 'auth.errors.slowDown' : 'auth.errors.locked'))
        else if (bodyCode(err) === 'lastAdmin') setError(t('settings.account.delete.lastAdmin'))
        else setError(t('settings.account.delete.failed'))
      },
    })
  }

  return (
    <Dialog open onOpenChange={(next) => (!next && !close.isPending ? onClose() : undefined)}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>{t('settings.account.delete.dialogTitle')}</DialogTitle>
          <DialogDescription>{t('settings.account.delete.dialogDescription')}</DialogDescription>
        </DialogHeader>
        <form className="mt-4 space-y-4" onSubmit={submit} noValidate>
          <Field label={t('auth.fields.password')} required>
            {(field) => (
              <PasswordInput
                {...field}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
                autoFocus
              />
            )}
          </Field>
          <label className="flex items-start gap-2 text-sm">
            <Checkbox checked={understood} onCheckedChange={(value) => setUnderstood(value === true)} className="mt-0.5" />
            <span>{t('settings.account.delete.understand')}</span>
          </label>
          {error ? <Alert variant="error">{error}</Alert> : null}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose} disabled={close.isPending}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" variant="destructive" loading={close.isPending} disabled={password === '' || !understood}>
              {t('settings.account.delete.confirm')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
