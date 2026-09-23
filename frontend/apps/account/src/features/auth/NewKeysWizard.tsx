import { zodResolver } from '@hookform/resolvers/zod'
import { useState, type ReactNode } from 'react'
import { useForm } from 'react-hook-form'
import { useTranslation } from 'react-i18next'
import { z } from 'zod'
import type { RegistrationKeys } from '@kutup/crypto'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Field } from '@kutup/ui/components/field'
import { PasswordInput } from '@kutup/ui/components/password-input'
import { Spinner } from '@kutup/ui/components/states'
import { AuthLayout } from './AuthLayout'
import { authErrorMessage } from './errors'
import { generateAccountKeys } from './flows'
import { MIN_PASSWORD_SCORE, passwordScore, usePasswordStrength } from './passwordStrength'
import { PasswordStrengthMeter } from './PasswordStrengthMeter'
import { ConfirmRecoveryPhrase, ShowRecoveryPhrase } from './RecoveryPhrase'

type Step = 'password' | 'generating' | 'phrase' | 'confirm'

/**
 * Choose a password → generate the account keys (Argon2id in a worker) →
 * show the recovery phrase → confirm three of its words → `onKeysConfirmed`.
 * Registration and an administrator-created account's first sign-in both run
 * through this; they differ in the fields before the password and in what
 * happens to the confirmed keys.
 */
export function NewKeysWizard({
  title,
  description,
  email,
  leadingFields,
  validateLeading,
  onKeysConfirmed,
}: {
  title: string
  description: string
  /** The account email the keys are bound to (read when the password is submitted). */
  email: () => string
  /** Fields above the password (registration: email and username). */
  leadingFields?: ReactNode
  /** Validate the leading fields; false keeps the user on the first step. */
  validateLeading?: () => Promise<boolean>
  onKeysConfirmed: (keys: RegistrationKeys) => Promise<void>
}) {
  const { t } = useTranslation()
  const [step, setStep] = useState<Step>('password')
  const [keys, setKeys] = useState<RegistrationKeys | null>(null)
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const schema = z
    .object({
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
    defaultValues: { password: '', confirm: '' },
  })
  const score = usePasswordStrength(watch('password'))

  const onPassword = handleSubmit(async ({ password }) => {
    if (validateLeading && !(await validateLeading())) return
    if ((await passwordScore(password)) < MIN_PASSWORD_SCORE) {
      setFieldError('password', { message: t('auth.validation.passwordTooWeak') })
      return
    }
    setError(null)
    setStep('generating')
    try {
      setKeys(await generateAccountKeys(password, email()))
      setStep('phrase')
    } catch {
      setError(t('auth.errors.keyGenerationFailed'))
      setStep('password')
    }
  })

  if (step === 'generating') {
    return (
      <AuthLayout title={title} description={t('newKeys.generatingDescription')}>
        <div className="flex flex-col items-center gap-3 py-6 text-sm text-muted-foreground">
          <Spinner label={t('newKeys.generating')} className="size-6" />
          {t('newKeys.generating')}
        </div>
      </AuthLayout>
    )
  }

  if (keys && step === 'phrase') {
    return (
      <AuthLayout title={t('recoveryPhrase.title')} description={t('recoveryPhrase.description')} width="md">
        <ShowRecoveryPhrase mnemonic={keys.mnemonic} email={email()} onContinue={() => setStep('confirm')} />
      </AuthLayout>
    )
  }

  if (keys && step === 'confirm') {
    return (
      <AuthLayout title={t('recoveryPhrase.confirmTitle')} description={t('recoveryPhrase.confirmDescription')}>
        <ConfirmRecoveryPhrase
          mnemonic={keys.mnemonic}
          pending={pending}
          error={error}
          onBack={() => setStep('phrase')}
          onConfirmed={() => {
            setPending(true)
            setError(null)
            onKeysConfirmed(keys)
              .catch((err: unknown) => setError(authErrorMessage(err, t, 'auth.errors.generic')))
              .finally(() => setPending(false))
          }}
        />
      </AuthLayout>
    )
  }

  return (
    <AuthLayout title={title} description={description}>
      <form className="space-y-4" onSubmit={(e) => void onPassword(e)} noValidate>
        {leadingFields}
        <Field label={t('auth.fields.newPassword')} error={errors.password?.message} required>
          {(field) => <PasswordInput {...field} {...register('password')} autoComplete="new-password" />}
        </Field>
        <PasswordStrengthMeter score={score} />
        <Field label={t('auth.fields.confirmPassword')} error={errors.confirm?.message} required>
          {(field) => <PasswordInput {...field} {...register('confirm')} autoComplete="new-password" />}
        </Field>
        <Alert>{t('newKeys.passwordNotice')}</Alert>
        {error ? <Alert variant="error">{error}</Alert> : null}
        <Button type="submit" className="w-full">
          {t('newKeys.continue')}
        </Button>
      </form>
    </AuthLayout>
  )
}
