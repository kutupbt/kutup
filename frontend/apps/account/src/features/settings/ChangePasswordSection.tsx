import { zodResolver } from '@hookform/resolvers/zod'
import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { z } from 'zod'
import { getSession } from '@kutup/session/store'
import { opaqueReregister } from '@kutup/session/opaque'
import { accountGrant, ReauthLockedError, WrongPasswordError } from '@kutup/session/reauth'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Card, CardContent } from '@kutup/ui/components/card'
import { Field } from '@kutup/ui/components/field'
import { PasswordInput } from '@kutup/ui/components/password-input'
import { Section } from '@kutup/ui/components/page'
import { MIN_PASSWORD_SCORE, passwordScore, usePasswordStrength } from '../auth/passwordStrength'
import { PasswordStrengthMeter } from '../auth/PasswordStrengthMeter'

/**
 * Changes the account password (docs/plans/opaque.md): the current password
 * earns a one-time grant, and the new one is registered in its place. The
 * master key stays the same, so nothing is re-encrypted: only its password
 * envelope is sealed again. The account's other sign-ins end.
 */
async function changePassword(current: string, next: string): Promise<void> {
  const grant = await accountGrant(current, 'passwordChange')
  const session = getSession()
  if (!session) throw new Error('not signed in')
  await opaqueReregister(next, session.envelopeBinding, session.masterKey, grant)
}

export function ChangePasswordSection() {
  const { t } = useTranslation()
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const schema = z
    .object({
      current: z.string().min(1, t('auth.validation.passwordRequired')),
      password: z.string().min(1, t('auth.validation.passwordRequired')),
      confirm: z.string(),
    })
    .refine((v) => v.password === v.confirm, { path: ['confirm'], message: t('auth.validation.passwordsDiffer') })
  const {
    register,
    handleSubmit,
    watch,
    reset,
    setError: setFieldError,
    formState: { errors },
  } = useForm<z.infer<typeof schema>>({
    resolver: zodResolver(schema),
    defaultValues: { current: '', password: '', confirm: '' },
  })
  const score = usePasswordStrength(watch('password'))

  const onSubmit = handleSubmit(async ({ current, password }) => {
    if ((await passwordScore(password)) < MIN_PASSWORD_SCORE) {
      setFieldError('password', { message: t('auth.validation.passwordTooWeak') })
      return
    }
    setError(null)
    setPending(true)
    try {
      await changePassword(current, password)
      reset()
      toast.success(t('settings.security.passwordChanged'))
    } catch (err) {
      if (err instanceof WrongPasswordError) setFieldError('current', { message: t('settings.security.wrongCurrentPassword') })
      else if (err instanceof ReauthLockedError) setError(t('auth.errors.locked'))
      else setError(t('settings.security.passwordChangeFailed'))
    } finally {
      setPending(false)
    }
  })

  return (
    <Section title={t('settings.security.password')} description={t('settings.security.passwordDescription')}>
      <Card>
        <CardContent className="p-5">
          <form className="space-y-4" onSubmit={(e) => void onSubmit(e)} noValidate>
            <Field label={t('settings.security.currentPassword')} error={errors.current?.message} required>
              {(field) => <PasswordInput {...field} {...register('current')} autoComplete="current-password" />}
            </Field>
            <Field label={t('auth.fields.newPassword')} error={errors.password?.message} required>
              {(field) => <PasswordInput {...field} {...register('password')} autoComplete="new-password" />}
            </Field>
            <PasswordStrengthMeter score={score} />
            <Field label={t('auth.fields.confirmPassword')} error={errors.confirm?.message} required>
              {(field) => <PasswordInput {...field} {...register('confirm')} autoComplete="new-password" />}
            </Field>
            <Alert variant="warn">{t('settings.security.passwordSignsOutOthers')}</Alert>
            {error ? <Alert variant="error">{error}</Alert> : null}
            <Button type="submit" loading={pending}>
              {t('settings.security.changePassword')}
            </Button>
          </form>
        </CardContent>
      </Card>
    </Section>
  )
}
