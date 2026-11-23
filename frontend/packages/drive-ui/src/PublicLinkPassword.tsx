import { KeyRound } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Field } from '@kutup/ui/components/field'
import { PasswordInput } from '@kutup/ui/components/password-input'

/** Why the last password was not taken. */
export type PasswordRefusal = 'wrong' | 'locked' | null

/**
 * A password-protected link's page before anything shows, as Proton Drive's
 * (`PublicPagePassword`): one password field. The password never leaves the
 * browser; what it derives with the link does (docs/plans/drive-link-password.md).
 */
export function PublicLinkPassword({
  refusal,
  onSubmit,
}: {
  refusal: PasswordRefusal
  onSubmit: (password: string) => void | Promise<void>
}) {
  const { t } = useTranslation()
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)

  function submit(e: FormEvent) {
    e.preventDefault()
    if (!password || busy) return
    setBusy(true)
    void Promise.resolve(onSubmit(password)).finally(() => setBusy(false))
  }

  return (
    <div className="flex flex-1 items-center justify-center px-4 py-10">
      <div className="w-full max-w-md space-y-6 rounded-lg border border-border bg-card p-8 shadow-sm">
        <div className="flex justify-center">
          <span className="rounded-md bg-muted p-4 text-primary">
            <KeyRound className="size-7" aria-hidden />
          </span>
        </div>
        <div className="space-y-1 text-center">
          <h1 className="text-lg font-semibold">{t('linkPassword.title')}</h1>
          <p className="text-sm text-muted-foreground">{t('linkPassword.body')}</p>
        </div>
        <form className="space-y-4" autoComplete="off" onSubmit={submit} data-testid="link-password-form">
          <Field
            label={t('linkPassword.label')}
            description={t('linkPassword.hint')}
            error={refusal === 'wrong' ? t('linkPassword.wrong') : undefined}
          >
            {(props) => (
              <PasswordInput
                {...props}
                autoFocus
                autoComplete="off"
                placeholder={t('linkPassword.placeholder')}
                value={password}
                disabled={busy}
                onChange={(e) => setPassword(e.target.value)}
                data-testid="link-password-entry"
              />
            )}
          </Field>
          {refusal === 'locked' ? <Alert variant="error">{t('linkPassword.locked')}</Alert> : null}
          <Button type="submit" className="w-full" loading={busy} disabled={!password} data-testid="link-password-continue">
            {t('linkPassword.continue')}
          </Button>
        </form>
      </div>
    </div>
  )
}
