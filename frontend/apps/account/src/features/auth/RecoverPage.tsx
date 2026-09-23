import { zodResolver } from '@hookform/resolvers/zod'
import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { z } from 'zod'
import { validateMnemonic } from '@kutup/crypto'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { PasswordInput } from '@kutup/ui/components/password-input'
import { Textarea } from '@kutup/ui/components/textarea'
import { AuthLayout } from './AuthLayout'
import { authErrorMessage } from './errors'
import { normalizeMnemonic, recoverAccount } from './flows'
import { MIN_PASSWORD_SCORE, passwordScore, usePasswordStrength } from './passwordStrength'
import { PasswordStrengthMeter } from './PasswordStrengthMeter'

/** Reset the password with the 24-word recovery phrase. Ends every existing sign-in. */
export function RecoverPage() {
  const { t } = useTranslation()
  const [done, setDone] = useState(false)
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const schema = z
    .object({
      email: z.string().trim().min(1, t('auth.validation.emailRequired')),
      phrase: z
        .string()
        .refine((v) => validateMnemonic(normalizeMnemonic(v)), t('recover.phraseInvalid')),
      password: z.string().min(1, t('auth.validation.passwordRequired')),
      confirm: z.string(),
    })
    .refine((v) => v.password === v.confirm, {
      path: ['confirm'],
      message: t('auth.validation.passwordsDiffer'),
    })
  const {
    register,
    handleSubmit,
    watch,
    setError: setFieldError,
    formState: { errors },
  } = useForm<z.infer<typeof schema>>({
    resolver: zodResolver(schema),
    defaultValues: { email: '', phrase: '', password: '', confirm: '' },
  })
  const score = usePasswordStrength(watch('password'))

  const onSubmit = handleSubmit(async ({ email, phrase, password }) => {
    if ((await passwordScore(password)) < MIN_PASSWORD_SCORE) {
      setFieldError('password', { message: t('auth.validation.passwordTooWeak') })
      return
    }
    setError(null)
    setPending(true)
    try {
      await recoverAccount(email.trim(), phrase, password)
      setDone(true)
    } catch (err) {
      setError(authErrorMessage(err, t, 'recover.failed'))
    } finally {
      setPending(false)
    }
  })

  if (done) {
    return (
      <AuthLayout title={t('recover.doneTitle')} description={t('recover.doneDescription')}>
        <Button asChild className="w-full">
          <Link to="/login">{t('recover.signIn')}</Link>
        </Button>
      </AuthLayout>
    )
  }

  return (
    <AuthLayout title={t('recover.title')} description={t('recover.description')} width="md">
      <form className="space-y-4" onSubmit={(e) => void onSubmit(e)} noValidate>
        <Field label={t('auth.fields.email')} error={errors.email?.message} required>
          {(field) => <Input {...field} {...register('email')} type="email" autoComplete="username" autoFocus />}
        </Field>
        <Field
          label={t('recover.phrase')}
          error={errors.phrase?.message}
          description={t('recover.phraseHint')}
          required
        >
          {(field) => (
            <Textarea
              {...field}
              {...register('phrase')}
              rows={4}
              autoComplete="off"
              autoCapitalize="off"
              spellCheck={false}
              className="font-mono"
            />
          )}
        </Field>
        <Field label={t('auth.fields.newPassword')} error={errors.password?.message} required>
          {(field) => <PasswordInput {...field} {...register('password')} autoComplete="new-password" />}
        </Field>
        <PasswordStrengthMeter score={score} />
        <Field label={t('auth.fields.confirmPassword')} error={errors.confirm?.message} required>
          {(field) => <PasswordInput {...field} {...register('confirm')} autoComplete="new-password" />}
        </Field>
        <Alert variant="warn">{t('recover.signsOutEverywhere')}</Alert>
        {error ? <Alert variant="error">{error}</Alert> : null}
        <Button type="submit" className="w-full" loading={pending}>
          {t('recover.submit')}
        </Button>
      </form>
      <Link to="/login" className="mt-6 block text-center text-sm text-muted-foreground hover:underline">
        {t('recover.backToSignIn')}
      </Link>
    </AuthLayout>
  )
}
